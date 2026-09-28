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
value (raw and JSON-escaped, because tracing's JSON formatter escapes field
values) and for fixed credential shapes that need no manifest (a PEM header, a
JWT-shaped token, an `Authorization: Bearer` header).  Any hit fails the gate.
Only a category, a stream role and an offset are ever printed: never a value,
and never a captured stream.

**An empty domain is visible, never green.**  Each gate's report line prints
its sentinel count per kind, its stream count and its bytes; and each gate
declares the kinds it must record (`requires`), so a fixture that stops
recording its payloads fails here instead of scanning nothing.

**Two kinds of control, so a green is evidence.**

* A *self-test* per gate plants each recorded kind, raw and JSON-escaped, plus
  every fixed credential shape, into a copy of that gate's own captured stderr
  and requires every plant to be reported -- the scanner is shown able to go
  red on this run's own data.
* A *declared-witness control* per milestone (`WITNESSES`) runs a real gate
  again with `M0_PAYLOAD_SCAN_PLANT=application_payload`: the harness then
  leaks its first recorded payload once, through its tracing subscriber
  (`c11_capture::plant_witness_leak`), the path an in-process relay diagnostic
  takes.  The control is RED only if the scan goes red **with the witness it
  declared** -- an `application_payload` hit in `harness_stderr`, on a line
  carrying the plant's tracing target -- and the child itself passed.  Green,
  a hit anywhere else, or a failed child is a wrong witness and fails the run.

Usage (after `cargo build --locked --workspace --bins`, with TEST_REDIS_URL):

    python3 scripts/m0-payload-scan.py [--harness PATH] [--gate NAME ...]
                                       [--no-witness] [--keep DIR]
    python3 scripts/m0-payload-scan.py --unit     # scanner unit probes only
"""

from __future__ import annotations

import argparse
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
GENERIC_PLANTS = {
    "pem_block": b"-----BEGIN PRIVATE KEY-----",
    "jwt_shape": b"eyJzeW50aGV0aWM.eyJzeW50aGV0aWNfc3Vi.c3ludGhldGljX3NpZw",
    "bearer_header": b"Authorization: Bearer synthetic-m0-08-token",
}

#: The level the children's tracing subscriber runs at.  The relay's own
#: default is `info`; the product crates run one level more verbose here, so a
#: diagnostic that would only appear when an operator turns logging up is still
#: in the scanned domain.  Third-party crates stay at `info`: their debug
#: output is wire-level framing an operator is not expected to enable.
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
        f"{crate}=debug"
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


EVERY_KIND = KIND_ORDER
GATES = (
    Gate("M1", "verify", EVERY_KIND),
    Gate("M2", "verify-m2", EVERY_KIND),
    Gate("M2", "verify-m2-faults", EVERY_KIND),
    Gate("M3", "verify-m3-http-forward-real-path", EVERY_KIND),
    Gate("M3", "verify-m3-mcp-cloud-client", EVERY_KIND),
    Gate("M3", "verify-m3-mcp-isolation", EVERY_KIND),
    Gate("M4", "verify-m4-fs-real-path", EVERY_KIND),
    Gate("M4", "verify-m4-fs-client-e2e", EVERY_KIND),
    Gate("M8", "verify-m8-acp-real-path", EVERY_KIND),
    Gate("M8", "verify-m8-acp-cluster", EVERY_KIND),
)
#: One declared-witness control per milestone, each on that milestone's
#: cheapest gate.  The declared witness is (kind, stream role).
WITNESSES = (
    ("M1", "verify"),
    ("M2", "verify-m2"),
    ("M3", "verify-m3-http-forward-real-path"),
    ("M4", "verify-m4-fs-client-e2e"),
    ("M8", "verify-m8-acp-real-path"),
)
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


def variants(value: bytes) -> list[bytes]:
    """The exact value, plus its JSON-escaped form when that differs."""
    forms = [value]
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        return forms
    escaped = json.dumps(text, ensure_ascii=False)[1:-1].encode("utf-8")
    if escaped != value:
        forms.append(escaped)
    ascii_escaped = json.dumps(text)[1:-1].encode("ascii")
    if ascii_escaped not in forms:
        forms.append(ascii_escaped)
    return forms


@dataclass
class Hit:
    kind: str
    role: str
    offset: int
    witness_line: bool = False


def line_at(data: bytes, offset: int) -> bytes:
    start = data.rfind(b"\n", 0, offset) + 1
    end = data.find(b"\n", offset)
    return data[start : end if end >= 0 else len(data)]


def scan_streams(
    sentinels: dict[str, list[bytes]], streams: dict[str, bytes]
) -> list[Hit]:
    hits: list[Hit] = []
    for role, data in streams.items():
        for kind in KIND_ORDER:
            for value in sentinels.get(kind, ()):
                for form in variants(value):
                    index = data.find(form)
                    while index >= 0:
                        hits.append(
                            Hit(kind, role, index, PLANT_TARGET in line_at(data, index))
                        )
                        index = data.find(form, index + 1)
        for label, pattern in GENERIC_SHAPES.items():
            for match in pattern.finditer(data):
                hits.append(
                    Hit(label, role, match.start(), PLANT_TARGET in line_at(data, match.start()))
                )
    # One leak can match both its raw and its escaped form at one offset.
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
            for form in variants(value):
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
        f"tracing_events={events or 'none'} hits={len(run.hits)}"
    )


def hit_summary(hits: list[Hit]) -> str:
    return ", ".join(
        f"{hit.kind}@{hit.role}+{hit.offset}{'(plant)' if hit.witness_line else ''}"
        for hit in hits[:20]
    ) + (f", ... {len(hits) - 20} more" if len(hits) > 20 else "")


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
    if run.streams and not tracing_crates(run.streams.get("harness_stderr", b"")).get("tunnel_relay"):
        failures.append("empty domain: no in-process tunnel_relay diagnostic reached the scanned stderr")
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
    witness_line = b'{"target":"m0_payload_scan_witness","fields":{"planted":"synthetic-credential-A"}}'
    hits = scan_streams(sentinels, {"harness_stderr": witness_line})
    if len(hits) != 1 or not hits[0].witness_line:
        failures.append("a planted line was not attributed to the plant")
    detected, planted = self_test(sentinels, clean)
    if detected != planted or planted < 5:
        failures.append(f"the self-test detected {detected} of {planted}")
    return failures


# --------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--harness", type=Path)
    parser.add_argument("--gate", action="append", default=[])
    parser.add_argument("--no-witness", action="store_true")
    parser.add_argument("--witness-only", action="store_true")
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
    witnesses = [] if args.no_witness else [
        known[command] for _, command in WITNESSES if not args.gate or command in args.gate
    ]
    if args.witness_only:
        gates = []

    if args.keep:
        args.keep.mkdir(mode=0o700, parents=True, exist_ok=False)
        workdir = args.keep
        cleanup = None
    else:
        cleanup = tempfile.TemporaryDirectory(prefix="m0-payload-scan-")
        workdir = Path(cleanup.name)
    os.chmod(workdir, 0o700)
    print(f"m0-payload-scan: log_filter={LOG_FILTER}", flush=True)
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
