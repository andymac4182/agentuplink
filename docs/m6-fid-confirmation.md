# Real-endpoint fid confirmation acceptance (M6-C244)

Status: source prepared; compilation and actual execution are pending. This
gate closes only the missing product-boundary evidence in M6-C244 if its
positive run and declared negative controls pass. M4-21's broader deadline
and descriptor acceptance remains open.

The command is `tunnel-test-harness verify-m6-ts-fid-ordering`, registered in
`scripts/m4-harness-verify.sh`. It uses the existing three-relay, disposable-Redis
filesystem fixture, an actual device connector with synthetic host files, and
the shared TypeScript client's exported discovery, verified-TLS upgrade,
`ConsumerSession`, and `RemoteFilesystem` implementation. Its owner-local route
does not claim filesystem forwarding through a non-owner.

The driver holds a real `Rwalk` or `Rclunk` received from the endpoint and
every subsequent reply in arrival order. It never fabricates a reply, changes
provider state, or allows `Rflush` to overtake an earlier original reply. The
hold is limited to 16 messages/64 KiB, all event collections to 128 entries,
and protocol output to 16 KiB per line. Node observations are bounded at 10 seconds and Rust driver/stream waits at
15 seconds; existing startup, owner, completed-exchange and cleanup helper
bounds remain unchanged. The scenario is bounded at 90 seconds. The
public operation's explicit two-second deadline is an ordinary supported
caller option. Descriptor quotas, single-request deadlines, and the device's
300/10/30 rotation policy remain unchanged.

| Case | Actual device witness | Required client ownership witness |
| --- | --- | --- |
| First walk reply unobserved at the operation deadline | Received `Rwalk`, followed by a real `Tgetattr` probe of that exact fid returning the independently seeded host-file size while all replies remain held | The deadline returns `DEADLINE_EXCEEDED`; the fid remains charged, no early `Tclunk` is sent, and a concurrent directory operation uses another fid. After ordered settlement and real `Rclunk`, the original numeric fid is reused successfully. |
| Applied clunk reply unobserved when cleanup stops waiting | Received `Rclunk`, followed by a real probe of the same fid returning `Rlerror(EINVAL)`, independently proving that the device has released it | The known stat result remains successful, but its fid stays charged until the client receives the held `Rclunk`. A concurrent directory operation uses a different fid; confirmed cleanup permits exact numeric reuse. |
| Definite refusal and pre-dispatch abort | Real missing-path refusal, followed by a successful host-backed stat | Definite refusal releases the number without an unnecessary clunk; the next walk reuses it. An already-aborted operation sends no request. |

Both held cases exercise a real `Tflush`/`Rflush`: walk expiry issues its normal
flush, and the clunk case explicitly cancels the still-unconfirmed cleanup
request. Original replies remain first in the ordered hold and are delivered
before their flush replies. **The clunk case proves an applied clunk with an
unobserved response. It does not prove a clunk flushed before dispatch.** No
existing provider scheduling hook established that second schedule, so the
gate does not invent one or claim it from the first.

At each hold, Rust independently checks the real connector stream and its
unchanged control session/epoch and Redis owner before releasing Node. A
directory iterator keeps the parallel fid live across the fault, making the
later exact reuse of the original number unambiguous. Wire tag/fid identifiers
and monotonic event ordinals establish receive, delivery, cancellation and
cleanup ordering. After all three consumer sessions close, the device must
record exactly three completed exchanges, no mutation dispatch and no written
bytes. Host files and directory membership must remain unchanged; the device
session must remain active without rotation or recovery.

The Node child remains owned outside the timed scenario. Driver, connector,
relay and catalog cleanup are bounded and attempted even after an earlier
failure. The connector handle survives a timed-out first stop through relay
and catalog teardown, followed by one bounded final join; the first timeout
remains a failure. A forced or unsuccessful cleanup cannot make a run pass. Reports
contain closed labels, identifiers, counters and host-comparison results;
tokens live only in the private fixture plan and no file contents are logged.

## Required verification before closure

Preserve source hashes, exact Node/dependency identity, immutable Rust
executables and all first failures. The existing full M4/Node result on the
previous candidate remains evidence for that earlier scope; this new gate has
not run and is not included in that result.

1. Compile the new Rust gate and type-check the new driver under the pinned
   toolchain after the coordinator grants an exclusive lease. Run its focused
   evidence controls, including seeded missing provider, ordering, resource,
   same-session, host and cleanup witnesses.
2. Run the real gate once with current client behavior and retain the exact
   wire/host/device evidence.
3. In an isolated test-source copy only, restore the original premature
   first-walk release behavior. Run the identical real fixture and require
   rejection at early fid reuse/resource ownership, with an actual already
   bound device fid. Restore exact source bytes regardless of outcome.
4. Separately restore only the original premature clunk release after the
   caller stops waiting. Require the same fixture to reject unconfirmed
   numeric reuse; preserve the actual applied-clunk probe. Restore exact bytes.
5. Re-run the fixed focused gate after both restorations. Record required
   integration checks separately; do not substitute a retry or a mock-peer
   success for this actual endpoint proof.

No production implementation, automatic mutation replay, whole-session close,
fid quota, or runtime deadline is changed by the acceptance fixture.
