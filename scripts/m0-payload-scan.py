#!/usr/bin/env python3
"""Cross-milestone payload scan: task rows M0-04, M0-08 and M0-09.

**What it proves.**  Diagnostics stay payload-free across the milestones, as a
kept property rather than a one-off measurement.  For every gate in `GATES`
this script runs the real acceptance command as a child of the harness binary
with a private capture directory (`C11_INNER_CAPTURE_DIR`), so that

* every fixture records the exact synthetic values it really used -- the
  credentials, application payloads, filesystem paths and private endpoints --
  in `sentinels.bin` (tombstones applied in order, as the M7-C11 adapter does);
* every `ManagedProcess` writes its joined stdout and stderr, and the relays and
  proxies write their typed payload-free snapshots;
* the in-process relays and clients log through the harness's own JSON tracing
  subscriber, at `LOG_FILTER`, into the child's stderr, which this script
  captures whole.

It then searches **every** captured stream -- the gate's own stdout and
stderr, each managed-process stream and each snapshot -- for every recorded
value in every encoding a diagnostic could plausibly give it (`encodings`):
raw; JSON-escaped (tracing's JSON formatter escapes field values); Rust
`Debug` of a string, and of a byte slice in both its decimal-list and `b"..."`
forms, each also JSON-escaped; lowercase hex; standard base64; and, for a long
value, the same encodings of its leading 32-byte window, so a truncated leak
still matches.  It also searches for fixed credential shapes that need no
manifest (a PEM header, a JWT-shaped token, an `Authorization: Bearer`
header).  Any hit fails the gate.  Only a category, a stream role and an offset
are ever printed: never a value, and never a captured stream.

**What it cannot see**, so a green is read at its real size: an encoding not in
that list (compression, encryption, another base64 alphabet, a re-ordered
field), a leak shorter than the recorded value's 32-byte window, a value the
fixture did not record, and -- because tombstones are applied to the manifest
before scanning and streams carry no timestamps -- any disclosure of a
`private_endpoint` that was later retired: a retired value is dropped from the
whole scan, and each report line prints `retired=` so that gap is counted.

**An empty domain is visible, never green.**  Each gate's report line prints
its sentinel count per kind, its stream count and its bytes.  Each gate
declares the kinds it must record (`requires`), the minimum number of managed
streams and relay snapshots its capture hooks write, and whether it must record
a text (UTF-8) payload; and every gate must show at least one `DEBUG` or
`TRACE` event from `tunnel_relay` in its scanned stderr.  So a fixture that
stops recording, a capture hook that stops writing, or a log level that stops
reaching the scan fails here instead of scanning nothing.

**Two kinds of control, so a green is evidence.**

* A *self-test* per gate plants each recorded kind, raw and JSON-escaped, plus
  every fixed credential shape, into a copy of that gate's own captured stderr
  and requires every plant to be reported -- the scanner is shown able to go
  red on this run's own data.
* A *declared-witness control* per gate runs that gate again with
  `M0_PAYLOAD_SCAN_PLANT=application_payload`: the harness then leaks its
  first recorded payload once (`c11_capture::plant_witness_leak`) as a
  `DEBUG` event under `tunnel_relay::m0_payload_scan_witness`, formatted with
  `?value` -- the decimal byte list a careless `debug!(?body)` would print.
  So each control shows that a `tunnel_relay` target at `debug` reaches the
  scanned stream and that the scanner matches a `Debug`-formatted byte slice
  inside JSON tracing output, binary or text.  The control is RED only if the
  scan goes red **with the witness it declared** -- every hit an
  `application_payload` in `harness_stderr` on the plant's own line -- and the
  child itself passed.  Green, a hit anywhere else, or a failed child is a
  wrong witness and fails the run.

Usage (after `cargo build --locked --workspace --bins`, with TEST_REDIS_URL):

    python3 scripts/m0-payload-scan.py [--harness PATH] [--gate NAME ...]
                                       [--no-witness | --witness-only]
                                       [--keep DIR]
    python3 scripts/m0-payload-scan.py --unit     # scanner unit probes only
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

KINDS = {
    1: "credential",
    2: "application_payload",
    3: "filesystem_path",
    4: "private_endpoint",
}
KIND_ORDER = tuple(KINDS.values())
RETIRED_FLAG = 0x80
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
#: A child stream larger than this fails the gate rather than being truncated,
#: because a truncated stream is an unscanned one.
MAX_STREAM_BYTES = 256 * 1024 * 1024

#: Credential shapes that need no manifest.  A fixture that forgets to record a
#: key or token is still caught if it prints one in a recognisable form.
GENERIC_SHAPES = {
    "pem_block": re.compile(rb"-----BEGIN [A-Z0-9 ]{3,64}-----"),
    "jwt_shape": re.compile(
        rb"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
    ),
    "bearer_header": re.compile(rb"(?i)authorization[\"']?\s*[:=]\s*[\"']?bearer\s+[A-Za-z0-9._~+/-]{8,}"),
}
#: Synthetic plants for the self-test.  Each literal is split across a `+` so
#: this source does not itself match the repository's secret scan
#: (`scripts/m6-release-checks.py`, which splits its own `_BEGIN` the same
#: way); the assembled bytes are unchanged.
GENERIC_PLANTS = {
    "pem_block": b"-----BEGIN " + b"PRIVATE KEY-----",
    "jwt_shape": b"eyJzeW50aGV0aWM." + b"eyJzeW50aGV0aWNfc3Vi.c3ludGhldGljX3NpZw",
    "bearer_header": b"Authorization: " + b"Bearer synthetic-m0-08-token",
}

#: The level the children's tracing subscriber runs at.  The relay's own
#: default is `info`; the product crates run at `trace` here, the most verbose
#: level, so a diagnostic that would only appear when an operator turns logging
#: all the way up is still in the scanned domain.  Third-party crates stay at
#: `info`: their debug output is wire-level framing an operator is not expected
#: to enable.
#:
#: `rmcp` is the one exception, at `warn`.  It is not product code: it is the
#: off-the-shelf MCP SDK that `verify-m3-mcp-cloud-client` drives *as the
#: consumer* (only the harness and the MCP fixture depend on it), and at
#: `info` it logs every notification that consumer receives, whole --
#: measured on 2026-09-28 as 192 exact `application_payload` hits, all
#: `rmcp::service` "received notification".  That is the consumer's own record
#: of its own traffic, not a relay or client diagnostic; its warnings and
#: errors stay in the scanned domain.
LOG_FILTER = ",".join(
    ["info", "rmcp=warn"]
    + [
        f"{crate}=trace"
        for crate in (
            "tunnel_relay",
            "tunnel_client",
            "tunnel_transport",
            "tunnel_core",
            "tunnel_protocol",
            "tunnel_catalog",
            "tunnel_cluster",
            "tunnel_http_forward",
            "tunnel_http_bridge",
            "tunnel_mcp",
            "tunnel_mcp_export",
            "tunnel_acp",
            "tunnel_acp_export",
            "tunnel_fs_core",
            "tunnel_fs_host",
            "tunnel_fs_ninep",
            "tunnel_fs_provider",
            "tunnel_test_harness",
        )
    ]
)
PLANT_ENV = "M0_PAYLOAD_SCAN_PLANT"
PLANT_TARGET = b"m0_payload_scan_witness"
GATE_TIMEOUT_SECONDS = 1_500


@dataclass(frozen=True)
class Gate:
    milestone: str
    command: str
    #: Sentinel kinds the fixture must record, so an empty domain fails.
    requires: tuple[str, ...]
    #: The fewest managed-process streams (stdout and stderr each count) and
    #: relay/proxy snapshot files the capture hooks must write.  Set to what
    #: each gate writes today, so a hook that stops writing fails the gate.
    min_managed: int = 0
    min_snapshots: int = 8
    #: Whether the gate must record at least one UTF-8 payload, so its
    #: payload domain can match a text log line, not only an encoded one.
    text_domain: bool = True
    #: Whether the gate's in-process relay emits at least one `DEBUG` or
    #: `TRACE` event, which the scan then requires to see.
    relay_debug: bool = True


EVERY_KIND = KIND_ORDER
GATES = (
    Gate("M1", "verify", EVERY_KIND, min_managed=2, min_snapshots=1),
    # The M2 echo path emits `tunnel_relay` events only at `info` and above:
    # measured on 2026-09-28 with the product crates at `trace`, 12 and 19
    # relay events and none finer than INFO.  Its witness control still shows
    # a `tunnel_relay` target at `debug` reaches the scanned stderr.
    Gate("M2", "verify-m2", EVERY_KIND, min_snapshots=1, relay_debug=False),
    Gate("M2", "verify-m2-faults", EVERY_KIND, min_snapshots=1, relay_debug=False),
    Gate("M3", "verify-m3-http-forward-real-path", EVERY_KIND),
    Gate("M3", "verify-m3-http-forward-rotation", EVERY_KIND),
    Gate("M3", "verify-m3-mcp-cloud-client", EVERY_KIND),
    Gate("M3", "verify-m3-mcp-isolation", EVERY_KIND, min_snapshots=7),
    Gate("M4", "verify-m4-fs-real-path", EVERY_KIND),
    Gate("M4", "verify-m4-fs-write-path", EVERY_KIND),
    Gate("M4", "verify-m4-fs-client-e2e", EVERY_KIND),
    Gate("M4", "verify-m4-fs-rotation", EVERY_KIND),
    Gate("M4", "verify-m4-fs-consumer-loss", EVERY_KIND),
    Gate("M4", "verify-m4-fs-epoch-change", EVERY_KIND),
    Gate("M4", "verify-m4-fs-process-restart", EVERY_KIND, min_managed=4),
    Gate("M4", "verify-m4-fs-data-recovery", EVERY_KIND),
    Gate("M4", "verify-m4-fs-data-recovery-lost-ack", EVERY_KIND),
    # These three move only `fs_rotation_write::payload_bytes`, whose byte `i`
    # is `(i % 251) | 0x80`: every byte has the high bit set, which the gates'
    # region classifier depends on, so no byte of it is text.  Their payloads
    # are still matched in their Debug, hex and base64 encodings.
    Gate("M4", "verify-m4-fs-rotation-write", EVERY_KIND, text_domain=False),
    Gate("M4", "verify-m4-fs-write-restart", EVERY_KIND, min_managed=4, text_domain=False),
    Gate("M4", "verify-m4-fs-rename-restart", EVERY_KIND, min_managed=4, text_domain=False),
    Gate("M8", "verify-m8-acp-real-path", EVERY_KIND),
    Gate("M8", "verify-m8-acp-cluster", EVERY_KIND),
)
#: Gates of these milestones deliberately outside the scan, with the reason
#: printed on every run so the boundary is visible rather than silent.
EXCLUDED = (
    ("M2", "verify-m2-default", "the verify-m2 code path at the 300 s rotation policy (about 17 minutes); its recording sites are the ones verify-m2 exercises"),
    ("M3", "process_residue", "a cargo test of the stdio export's process-tree residue; it moves no application payload"),
    ("M4", "verify-m6-ts-connection-limit", "an M6 listener-limit gate in the M4 script; it moves no application payload"),
    ("M8", "m8_relay_rekey_process", "a cargo test of peer-key rotation on SIGHUP, not a harness gate; it moves no application payload"),
)
#: Every gate carries its own declared-witness control: the same gate is run
#: again with one recorded payload planted, and must go red with exactly that
#: witness.  The declared witness is (kind, stream role).
WITNESS_DECLARED = ("application_payload", "harness_stderr")


class ScanError(Exception):
    """A capture that cannot be scanned soundly.  Never carries a value."""


# --------------------------------------------------------------------------
# Manifest and capture reading


def read_manifest(data: bytes) -> tuple[dict[str, list[bytes]], int]:
    """Return the active sentinels per kind and the number retired."""
    active: dict[str, dict[bytes, None]] = {kind: {} for kind in KIND_ORDER}
    retired = 0
    offset = 0
    while offset < len(data):
        if offset + 5 > len(data):
            raise ScanError("sentinel manifest has a truncated record header")
        code = data[offset]
        (length,) = struct.unpack_from("<I", data, offset + 1)
        start = offset + 5
        end = start + length
        if length == 0 or end > len(data):
            raise ScanError("sentinel manifest has a truncated record")
        kind = KINDS.get(code & ~RETIRED_FLAG & 0xFF)
        if kind is None or code & ~(RETIRED_FLAG | 0x7) & 0xFF:
            raise ScanError("sentinel manifest has an unknown kind code")
        value = data[start:end]
        if code & RETIRED_FLAG:
            active[kind].pop(value, None)
            retired += 1
        else:
            active[kind][value] = None
        offset = end
    return {kind: list(values) for kind, values in active.items()}, retired


def read_capture(capture: Path) -> tuple[dict[str, list[bytes]], int, dict[str, bytes]]:
    """Read the manifest and every inner stream the capture hooks wrote."""
    manifest_path = capture / "sentinels.bin"
    manifest = b""
    if manifest_path.exists():
        if manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
            raise ScanError("sentinel manifest exceeds its bound")
        manifest = manifest_path.read_bytes()
    sentinels, retired = read_manifest(manifest)
    streams: dict[str, bytes] = {}
    for entry in sorted(capture.iterdir()):
        name = entry.name
        if name == "sentinels.bin":
            continue
        if entry.is_symlink() or not entry.is_file():
            raise ScanError("capture directory holds a non-regular entry")
        if name.startswith("managed-") and name.endswith((".stdout", ".stderr")):
            role = f"managed:{name}"
        elif name.startswith("snapshot-") and name.endswith(".bin"):
            role = f"snapshot:{name}"
        else:
            raise ScanError("capture directory holds an undeclared file")
        if entry.stat().st_size > MAX_STREAM_BYTES:
            raise ScanError("captured stream exceeds its bound")
        streams[role] = entry.read_bytes()
    return sentinels, retired, streams


# --------------------------------------------------------------------------
# Scanning


#: A value longer than this is also searched for by its leading window.
WINDOW_BYTES = 32


def json_escape(data: bytes) -> list[bytes]:
    """JSON string-escaped forms of `data`, when it is text: tracing's JSON
    formatter escapes every field value this way.  Both escapers are kept
    (non-ASCII as itself, and as `\\uXXXX`)."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return []
    return [
        json.dumps(text, ensure_ascii=False)[1:-1].encode("utf-8"),
        json.dumps(text)[1:-1].encode("ascii"),
    ]


def str_debug(text: str) -> bytes:
    """The inside of Rust's `format!("{:?}", text)` for a `str`."""
    out = []
    for char in text:
        code = ord(char)
        if char == "\t":
            out.append("\\t")
        elif char == "\r":
            out.append("\\r")
        elif char == "\n":
            out.append("\\n")
        elif char in "\\\"":
            out.append("\\" + char)
        elif char == "\0":
            out.append("\\0")
        elif code < 0x20 or code == 0x7F:
            out.append(f"\\u{{{code:x}}}")
        else:
            out.append(char)
    return "".join(out).encode("utf-8")


def bytes_debug_list(data: bytes, closed: bool) -> bytes:
    """Rust's `Debug` of `&[u8]` / `Vec<u8>`: `[104, 105]`.  An open form (no
    brackets) matches the value inside a longer slice's list, too."""
    inner = ", ".join(str(byte) for byte in data)
    return (f"[{inner}]" if closed else inner).encode("ascii")


def bytes_debug_escape(data: bytes) -> bytes:
    """The inside of `bytes::Bytes`'s `Debug`: `b"..."` with `\\n`, `\\r`,
    `\\t`, `\\0`, `\\\\`, `\\"` and `\\xNN` escapes."""
    out = []
    for byte in data:
        if byte == 0x0A:
            out.append("\\n")
        elif byte == 0x0D:
            out.append("\\r")
        elif byte == 0x09:
            out.append("\\t")
        elif byte == 0x00:
            out.append("\\0")
        elif byte in (0x5C, 0x22):
            out.append("\\" + chr(byte))
        elif 0x20 <= byte < 0x7F:
            out.append(chr(byte))
        else:
            out.append(f"\\x{byte:02x}")
    return "".join(out).encode("ascii")


def base64_form(data: bytes) -> bytes:
    """Standard base64 of `data`, cut to the characters that do not depend on
    whatever follows it, so the value still matches inside a longer encoding
    that starts where it does."""
    encoded = base64.b64encode(data).rstrip(b"=")
    whole = (len(data) // 3) * 4
    return encoded[:whole] if len(data) % 3 else encoded


def encodings(value: bytes) -> list[bytes]:
    """Every form of `value` the scan searches for (see the module docstring).

    A form shorter than 12 bytes is dropped: the shortest recorded values are
    endpoints such as `127.0.0.1:NNNNN`, and a shorter encoded form would match
    unrelated text."""
    forms: list[bytes] = []

    def add(form: bytes) -> None:
        if len(form) >= 12 and form not in forms:
            forms.append(form)

    def encode(data: bytes, closed: bool) -> None:
        add(data)
        for escaped in json_escape(data):
            add(escaped)
        try:
            debug = str_debug(data.decode("utf-8"))
            add(debug)
            for escaped in json_escape(debug):
                add(escaped)
        except UnicodeDecodeError:
            pass
        add(bytes_debug_list(data, closed))
        escape_form = bytes_debug_escape(data)
        add(escape_form)
        for escaped in json_escape(escape_form):
            add(escaped)
        add(data.hex().encode("ascii"))
        add(base64_form(data))

    encode(value, closed=False)
    if len(value) > WINDOW_BYTES:
        encode(value[:WINDOW_BYTES], closed=False)
    return forms


def needles(sentinels: dict[str, list[bytes]]) -> list[tuple[str, bytes]]:
    return [
        (kind, form)
        for kind in KIND_ORDER
        for value in sentinels.get(kind, ())
        for form in encodings(value)
    ]


@dataclass
class Hit:
    kind: str
    role: str
    offset: int
    witness_line: bool = False


def plant_lines(data: bytes) -> list[tuple[int, int]]:
    """The byte ranges of every line carrying the witness plant's target."""
    spans = []
    index = data.find(PLANT_TARGET)
    while index >= 0:
        start = data.rfind(b"\n", 0, index) + 1
        end = data.find(b"\n", index)
        spans.append((start, end if end >= 0 else len(data)))
        index = data.find(PLANT_TARGET, index + 1)
    return spans


def planted_at(spans: list[tuple[int, int]], offset: int) -> bool:
    return any(start <= offset < end for start, end in spans)


def scan_streams(
    sentinels: dict[str, list[bytes]], streams: dict[str, bytes]
) -> list[Hit]:
    hits: list[Hit] = []
    forms = needles(sentinels)
    for role, data in streams.items():
        spans = plant_lines(data)
        for kind, form in forms:
            index = data.find(form)
            while index >= 0:
                hits.append(Hit(kind, role, index, planted_at(spans, index)))
                index = data.find(form, index + 1)
        for label, pattern in GENERIC_SHAPES.items():
            for match in pattern.finditer(data):
                hits.append(
                    Hit(label, role, match.start(), planted_at(spans, match.start()))
                )
    # One leak can match several forms (and its window) at one offset.
    unique = {(hit.kind, hit.role, hit.offset): hit for hit in hits}
    return sorted(unique.values(), key=lambda hit: (hit.role, hit.offset, hit.kind))


def self_test(sentinels: dict[str, list[bytes]], base: bytes) -> tuple[int, int]:
    """Plant every recorded kind, raw and escaped, and every generic shape,
    into copies of `base`; return (detected, planted)."""
    planted = 0
    detected = 0
    cases: list[tuple[str, bytes]] = []
    for kind in KIND_ORDER:
        values = sentinels.get(kind, [])
        if not values:
            continue
        value = values[0]
        cases.append((kind, value))
        cases.append((kind, b"[" + bytes_debug_list(value, closed=True) + b"]"))
        cases.append((kind, value.hex().encode("ascii")))
        try:
            text = value.decode("utf-8")
            cases.append((kind, json.dumps({"field": text}).encode("ascii")))
        except UnicodeDecodeError:
            pass
    for label, sample in GENERIC_PLANTS.items():
        cases.append((label, sample))
    # The last 64 KiB of the gate's own stream carries the plant: the same
    # scanner runs on the same bytes, without rescanning megabytes per plant.
    tail = base[-65536:]
    for kind, plant in cases:
        planted += 1
        stream = tail + b"\nplanted:" + plant + b":end\n"
        found = scan_streams(sentinels, {"selftest": stream})
        if any(h.kind == kind and h.offset >= len(tail) for h in found):
            detected += 1
    return detected, planted


# --------------------------------------------------------------------------
# Running gates


@dataclass
class GateRun:
    gate: Gate
    planted: bool
    exit_code: int
    seconds: float
    sentinels: dict[str, list[bytes]]
    retired: int
    streams: dict[str, bytes] = field(default_factory=dict)
    hits: list[Hit] = field(default_factory=list)
    error: str = ""


def child_environment(capture: Path, plant: bool) -> dict[str, str]:
    env = dict(os.environ)
    env.pop(PLANT_ENV, None)
    env.pop("C11_INNER_CAPTURE_DIR", None)
    env["C11_INNER_CAPTURE_DIR"] = str(capture)
    env["RUST_LOG"] = LOG_FILTER
    if plant:
        env[PLANT_ENV] = WITNESS_DECLARED[0]
    return env


def run_gate(harness: Path, gate: Gate, workdir: Path, plant: bool) -> GateRun:
    label = gate.command + (".witness" if plant else "")
    capture = workdir / f"capture-{label}"
    capture.mkdir(mode=0o700)
    os.chmod(capture, 0o700)
    stdout_path = workdir / f"{label}.stdout"
    stderr_path = workdir / f"{label}.stderr"
    started = time.monotonic()
    with open(stdout_path, "wb") as out, open(stderr_path, "wb") as err:
        child = subprocess.Popen(
            [str(harness), gate.command],
            cwd=ROOT,
            env=child_environment(capture, plant),
            stdin=subprocess.DEVNULL,
            stdout=out,
            stderr=err,
            start_new_session=True,
        )
        try:
            exit_code = child.wait(timeout=GATE_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
            exit_code = -1
    seconds = time.monotonic() - started
    run = GateRun(gate, plant, exit_code, seconds, {k: [] for k in KIND_ORDER}, 0)
    try:
        sentinels, retired, inner = read_capture(capture)
        streams = {}
        for role, path in (("harness_stdout", stdout_path), ("harness_stderr", stderr_path)):
            if path.stat().st_size > MAX_STREAM_BYTES:
                raise ScanError("gate output exceeds its bound")
            streams[role] = path.read_bytes()
        streams.update(inner)
        run.sentinels, run.retired, run.streams = sentinels, retired, streams
        run.hits = scan_streams(sentinels, streams)
    except (OSError, ScanError) as error:
        run.error = f"capture unreadable: {type(error).__name__}: {error}"
    return run


def redacted_tail(run: GateRun, lines: int = 20) -> str:
    """The end of a failed child's stderr with every recorded value and every
    generic credential shape replaced by its category."""
    data = run.streams.get("harness_stderr", b"")
    for kind in KIND_ORDER:
        for value in sorted(run.sentinels.get(kind, ()), key=len, reverse=True):
            for form in encodings(value):
                data = data.replace(form, f"[{kind}]".encode())
    for label, pattern in GENERIC_SHAPES.items():
        data = pattern.sub(f"[{label}]".encode(), data)
    tail = data.splitlines()[-lines:]
    return "\n".join("    " + line.decode("utf-8", "replace")[:400] for line in tail)


def tracing_crates(data: bytes) -> dict[str, int]:
    """Count the harness's JSON tracing events by emitting crate, so the
    report shows the in-process relays' and clients' diagnostics really
    reached the scanned stream.  Reads only the `target` field."""
    counts: dict[str, int] = {}
    for line in data.splitlines():
        if not line.startswith(b"{"):
            continue
        try:
            target = json.loads(line).get("target", "")
        except (ValueError, AttributeError):
            continue
        crate = str(target).split("::", 1)[0]
        counts[crate] = counts.get(crate, 0) + 1
    return dict(sorted(counts.items()))


def relay_detail_events(data: bytes) -> int:
    """`DEBUG` and `TRACE` events from `tunnel_relay` in the scanned stderr,
    excluding the witness plant's own event."""
    count = 0
    for line in data.splitlines():
        if not line.startswith(b"{") or PLANT_TARGET in line:
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict):
            continue
        target = str(event.get("target", ""))
        if target.split("::", 1)[0] == "tunnel_relay" and event.get("level") in ("DEBUG", "TRACE"):
            count += 1
    return count


def describe(run: GateRun) -> str:
    counts = ",".join(f"{kind}:{len(run.sentinels.get(kind, []))}" for kind in KIND_ORDER)
    managed = [r for r in run.streams if r.startswith("managed:")]
    snapshots = [r for r in run.streams if r.startswith("snapshot:")]
    size = lambda roles: sum(len(run.streams[r]) for r in roles)  # noqa: E731
    total = sum(len(data) for data in run.streams.values())
    events = ",".join(
        f"{crate}:{count}"
        for crate, count in tracing_crates(run.streams.get("harness_stderr", b"")).items()
    )
    return (
        f"milestone={run.gate.milestone} gate={run.gate.command} exit={run.exit_code} "
        f"secs={run.seconds:.0f} sentinels={counts} retired={run.retired} "
        f"streams={len(run.streams)} bytes={total} "
        f"harness_stdout={len(run.streams.get('harness_stdout', b''))} "
        f"harness_stderr={len(run.streams.get('harness_stderr', b''))} "
        f"managed={len(managed)}/{size(managed)} snapshots={len(snapshots)}/{size(snapshots)} "
        f"tracing_events={events or 'none'} "
        f"relay_debug_events={relay_detail_events(run.streams.get('harness_stderr', b''))} "
        f"text_payloads={len(text_payloads(run))} hits={len(run.hits)}"
    )


def hit_summary(hits: list[Hit]) -> str:
    return ", ".join(
        f"{hit.kind}@{hit.role}+{hit.offset}{'(plant)' if hit.witness_line else ''}"
        for hit in hits[:20]
    ) + (f", ... {len(hits) - 20} more" if len(hits) > 20 else "")


def text_payloads(run: GateRun) -> list[bytes]:
    """Recorded payloads that are valid UTF-8 text of at least 16 bytes."""
    found = []
    for value in run.sentinels.get("application_payload", ()):
        if len(value) < 16:
            continue
        try:
            value.decode("utf-8")
        except UnicodeDecodeError:
            continue
        found.append(value)
    return found


def check_clean(run: GateRun) -> list[str]:
    failures: list[str] = []
    if run.error:
        failures.append(run.error)
    if run.exit_code != 0:
        failures.append(f"gate exited {run.exit_code}; redacted stderr tail:\n{redacted_tail(run)}")
    for kind in run.gate.requires:
        if not run.sentinels.get(kind):
            failures.append(f"empty domain: the fixture recorded no {kind} sentinel")
    # Every gate runs its relays in process, so their diagnostics must be seen
    # in the scanned stderr; none seen means the domain lost them.
    stderr = run.streams.get("harness_stderr", b"")
    if not tracing_crates(stderr).get("tunnel_relay"):
        failures.append("empty domain: no in-process tunnel_relay diagnostic reached the scanned stderr")
    if run.gate.relay_debug and not relay_detail_events(stderr):
        failures.append("empty domain: no DEBUG or TRACE tunnel_relay event reached the scanned stderr")
    managed = sum(1 for role in run.streams if role.startswith("managed:"))
    snapshots = sum(1 for role in run.streams if role.startswith("snapshot:"))
    if managed < run.gate.min_managed:
        failures.append(
            f"empty domain: {managed} managed-process streams captured, the gate writes at least {run.gate.min_managed}"
        )
    if snapshots < run.gate.min_snapshots:
        failures.append(
            f"empty domain: {snapshots} snapshots captured, the gate writes at least {run.gate.min_snapshots}"
        )
    if run.gate.text_domain and not text_payloads(run):
        failures.append("empty domain: no UTF-8 application_payload was recorded")
    if run.hits:
        failures.append(f"scan hits (category@stream+offset): {hit_summary(run.hits)}")
    return failures


def classify_witness(run: GateRun) -> str:
    """RED only when the scan went red with exactly the declared witness."""
    if run.error:
        return f"DID NOT RUN ({run.error})"
    if run.exit_code != 0:
        return f"WRONG WITNESS (the planted child exited {run.exit_code})"
    kind, role = WITNESS_DECLARED
    if not run.sentinels.get(kind):
        return f"DID NOT RUN (the fixture recorded no {kind} to plant)"
    if not run.hits:
        return "STILL GREEN (the plant was not detected)"
    stray = [h for h in run.hits if not (h.kind == kind and h.role == role and h.witness_line)]
    if stray:
        return f"WRONG WITNESS (hits outside the declared witness: {hit_summary(stray)})"
    return "RED"


# --------------------------------------------------------------------------
# Unit probes: pure scanner rules, both directions, no harness


def unit_probes() -> list[str]:
    failures: list[str] = []

    def record(code: int, value: bytes) -> bytes:
        return bytes([code]) + struct.pack("<I", len(value)) + value

    manifest = (
        record(1, b"synthetic-credential-A")
        + record(2, b'payload "quoted"\nline')
        + record(4, b"127.0.0.1:1")
        + record(4 | RETIRED_FLAG, b"127.0.0.1:1")
    )
    sentinels, retired = read_manifest(manifest)
    if retired != 1 or sentinels["private_endpoint"]:
        failures.append("a tombstone did not retire its endpoint")
    if sentinels["credential"] != [b"synthetic-credential-A"]:
        failures.append("the credential record was not read")
    for broken in (manifest[:-1], bytes([9]) + manifest[1:], record(1, b"")):
        try:
            read_manifest(broken)
            failures.append("a malformed manifest was accepted")
        except ScanError:
            pass
    clean = b'{"level":"INFO","fields":{"message":"ok"},"target":"tunnel_relay"}\n'
    if scan_streams(sentinels, {"s": clean}):
        failures.append("a clean stream was reported")
    escaped = json.dumps({"fields": {"payload": 'payload "quoted"\nline'}}).encode()
    if [h.kind for h in scan_streams(sentinels, {"s": escaped})] != ["application_payload"]:
        failures.append("a JSON-escaped payload was not reported exactly once")
    retired_leak = b"relay listening on 127.0.0.1:1"
    if scan_streams(sentinels, {"s": retired_leak}):
        failures.append("a retired endpoint was reported")
    for label, sample in GENERIC_PLANTS.items():
        if [h.kind for h in scan_streams({}, {"s": sample})] != [label]:
            failures.append(f"the {label} shape was not reported")
    witness_line = (
        b'{"level":"DEBUG","target":"tunnel_relay::m0_payload_scan_witness",'
        b'"fields":{"planted":"synthetic-credential-A"}}'
    )
    hits = scan_streams(sentinels, {"harness_stderr": witness_line})
    if len(hits) != 1 or not hits[0].witness_line:
        failures.append("a planted line was not attributed to the plant")
    unplanted = scan_streams(sentinels, {"harness_stderr": b"x raw=synthetic-credential-A"})
    if len(unplanted) != 1 or unplanted[0].witness_line:
        failures.append("an unplanted leak was attributed to the plant")

    # One probe per encoding: a leak in that form alone must be reported, and
    # the same form of a different value must not be.
    payload = b'm0-probe "payload"\n\x01tail-of-a-long-synthetic-value-0123456789'
    other = b'm0-probe "PAYLOAD"\n\x01tail-of-a-long-synthetic-value-9876543210'
    probe = {"application_payload": [payload]}
    text = payload.decode("utf-8")
    forms = {
        "raw": payload,
        "json": json.dumps({"f": text}).encode("ascii"),
        "debug list": ("[7, " + ", ".join(str(b) for b in payload) + ", 9]").encode("ascii"),
        "debug b-escape": b'b"' + bytes_debug_escape(payload) + b'"',
        "debug b-escape in json": json.dumps({"f": 'b"' + bytes_debug_escape(payload).decode("ascii") + '"'}).encode("ascii"),
        "str debug": b'"' + str_debug(text) + b'"',
        "str debug in json": json.dumps({"f": '"' + str_debug(text).decode("utf-8") + '"'}).encode("ascii"),
        "hex": b"0x" + payload.hex().encode("ascii"),
        "base64": base64.b64encode(payload + b"trailing"),
        "truncated window": payload[:WINDOW_BYTES] + b"...",
        "truncated debug list": ("[" + ", ".join(str(b) for b in payload[:WINDOW_BYTES]) + ", ..]").encode("ascii"),
    }
    for name, leak in forms.items():
        found = [h.kind for h in scan_streams(probe, {"s": b"x " + leak + b" y"})]
        if "application_payload" not in found:
            failures.append(f"a {name} leak was not reported")
        control = leak.replace(payload, other)
        if name in ("raw", "truncated window") and scan_streams(probe, {"s": b"x " + other + b" y"}):
            failures.append(f"a {name} form of a different value was reported")
        del control
    for name, render in (
        ("debug list", lambda v: bytes_debug_list(v, closed=True)),
        ("hex", lambda v: v.hex().encode("ascii")),
        ("base64", lambda v: base64.b64encode(v)),
    ):
        if scan_streams(probe, {"s": render(other)}):
            failures.append(f"the {name} form of a different value was reported")

    # The empty-domain rules: a broken capture hook, a missing debug level,
    # and a gate with no text payload each fail check_clean.
    good_stderr = (
        b'{"level":"DEBUG","target":"tunnel_relay::actor","fields":{"message":"m"}}\n'
    )
    gate = Gate("M0", "probe", ("application_payload",), min_managed=2, min_snapshots=1)
    base_streams = {
        "harness_stderr": good_stderr,
        "managed:a.stdout": b"",
        "managed:a.stderr": b"",
        "snapshot:s.bin": b"x",
    }

    def run_with(streams: dict[str, bytes], payloads: list[bytes]) -> GateRun:
        return GateRun(gate, False, 0, 0.0, {"application_payload": payloads}, 0, dict(streams))

    text_value = [b"a-long-enough-text-payload"]
    if check_clean(run_with(base_streams, text_value)):
        failures.append("a complete synthetic capture was refused")
    cases = {
        "a missing managed stream": {k: v for k, v in base_streams.items() if k != "managed:a.stderr"},
        "a missing snapshot": {k: v for k, v in base_streams.items() if k != "snapshot:s.bin"},
        "no DEBUG relay event": {**base_streams, "harness_stderr": good_stderr.replace(b"DEBUG", b"INFO")},
    }
    for name, streams in cases.items():
        if not check_clean(run_with(streams, text_value)):
            failures.append(f"{name} was not refused")
    if not check_clean(run_with(base_streams, [b"\xff\xfe" * 20])):
        failures.append("a gate with no text payload was not refused")
    detected, planted = self_test(sentinels, clean)
    if detected != planted or planted < 5:
        failures.append(f"the self-test detected {detected} of {planted}")
    return failures


# --------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--harness", type=Path)
    parser.add_argument("--gate", action="append", default=[])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--no-witness", action="store_true")
    mode.add_argument("--witness-only", action="store_true")
    parser.add_argument("--keep", type=Path, help="keep captures in this private directory")
    parser.add_argument("--unit", action="store_true", help="run the scanner unit probes only")
    args = parser.parse_args()

    failures = unit_probes()
    print(f"m0-payload-scan: unit probes {'ok' if not failures else 'FAILED'}", flush=True)
    for failure in failures:
        print(f"m0-payload-scan: unit probe failed: {failure}", file=sys.stderr)
    if failures or args.unit:
        return 1 if failures else 0

    target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
    harness = args.harness or target / "debug" / "tunnel-test-harness"
    if not harness.is_file():
        print(f"m0-payload-scan: harness binary not found at {harness}; build the workspace bins first", file=sys.stderr)
        return 2
    if not os.environ.get("TEST_REDIS_URL"):
        print("m0-payload-scan: TEST_REDIS_URL is required", file=sys.stderr)
        return 2
    os.environ.setdefault("TUNNEL_CATALOG_REDIS_URL", os.environ["TEST_REDIS_URL"])

    known = {gate.command: gate for gate in GATES}
    unknown = [name for name in args.gate if name not in known]
    if unknown:
        print(f"m0-payload-scan: unknown gate(s): {', '.join(unknown)}", file=sys.stderr)
        return 2
    gates = [known[name] for name in args.gate] if args.gate else list(GATES)
    witnesses = [] if args.no_witness else list(gates)
    if args.witness_only:
        gates = []
    if not gates and not witnesses:
        print("m0-payload-scan: nothing selected to run", file=sys.stderr)
        return 2

    if args.keep:
        args.keep.mkdir(mode=0o700, parents=True, exist_ok=False)
        workdir = args.keep
        cleanup = None
    else:
        cleanup = tempfile.TemporaryDirectory(prefix="m0-payload-scan-")
        workdir = Path(cleanup.name)
    os.chmod(workdir, 0o700)
    print(f"m0-payload-scan: log_filter={LOG_FILTER}", flush=True)
    for milestone, command, reason in EXCLUDED:
        print(f"m0-payload-scan: not scanned milestone={milestone} gate={command}: {reason}", flush=True)
    failed = False
    totals = {"streams": 0, "bytes": 0, "sentinels": {kind: 0 for kind in KIND_ORDER}}
    try:
        for gate in gates:
            run = run_gate(harness, gate, workdir, plant=False)
            detected, planted = self_test(run.sentinels, run.streams.get("harness_stderr", b""))
            problems = check_clean(run)
            if detected != planted:
                problems.append(f"self-test detected {detected} of {planted} plants")
            status = "ok" if not problems else "FAILED"
            print(f"m0-payload-scan: {status} {describe(run)} selftest={detected}/{planted}", flush=True)
            for problem in problems:
                print(f"m0-payload-scan:   {gate.command}: {problem}", flush=True)
            failed |= bool(problems)
            totals["streams"] += len(run.streams)
            totals["bytes"] += sum(len(d) for d in run.streams.values())
            for kind in KIND_ORDER:
                totals["sentinels"][kind] += len(run.sentinels.get(kind, []))
        red = 0
        for gate in witnesses:
            run = run_gate(harness, gate, workdir, plant=True)
            outcome = classify_witness(run)
            red += outcome == "RED"
            print(
                f"m0-payload-scan: witness milestone={gate.milestone} gate={gate.command} "
                f"declared={WITNESS_DECLARED[0]}@{WITNESS_DECLARED[1]} outcome={outcome} "
                f"hits={len(run.hits)} secs={run.seconds:.0f}",
                flush=True,
            )
            failed |= outcome != "RED"
    finally:
        if cleanup is not None:
            cleanup.cleanup()
    if not gates and not witnesses:
        failed = True
    sentinel_totals = ",".join(f"{k}:{v}" for k, v in totals["sentinels"].items())
    print(
        f"m0-payload-scan: {'FAILED' if failed else 'PASS'} gates={len(gates)} "
        f"streams={totals['streams']} bytes={totals['bytes']} sentinels={sentinel_totals} "
        f"witnesses={red}/{len(witnesses)} RED with the declared witness",
        flush=True,
    )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
