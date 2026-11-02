# Local h3 0.0.8 patch

Source is the locked crates.io h3 0.0.8 archive, checksum `10872b55cfb02a821b69dc7cf8dc6a71d6af25eb9a79662bec4a9d016056b3be`, copied from the existing local Cargo registry. The upstream license and metadata are retained. Dependency versions are unchanged.

`Connection::wait_for_remote_goaway` exposes receipt of a validated remote GOAWAY while continuing normal control-frame and server-stream validation. It opens no synthetic request and leaves the connection open for admitted response streams. The Agent Tunnel driver uses this event to gate new requests, wait for retained stream leases, acknowledge GOAWAY, and join within its existing deadline.

The causal real HTTP/3 no-post-GOAWAY-open regression failed on unmodified h3/client driving with Timeout in0.91 seconds. Full patched validation is recorded in docs/m7-verification.md when complete.

Patch SHA-256: `272f33e58cdc95604f71b613088100d63066153f0ea1e91debe5b79c5f4ce7c4`.

`ConnectionError::is_remote_no_error_application_close` reports a remote QUIC
application close carrying code 0. `is_h3_no_error` accepts only the HTTP/3
`H3_NO_ERROR` code (0x100), while this crate and the relay close gracefully with
application code 0, and the `Remote` variant is otherwise reachable only behind
the third-party-backend feature. The peer driver needs that distinction to tell
a peer's clean shutdown during its own post-GOAWAY drain from a real protocol
failure, which always carries a defined 0x1xx code.

This vendored crate is not a workspace member, so it carries no runnable test of
its own; the accessor's behaviour is exercised through `tunnel-transport`.

## M6-C246: unresolved request cancellation and accounting

The upstream crate/version/archive checksum above remains unchanged. The
incremental patch `c246-unresolved-request.patch` applies on repository source
`b566d201070cd8b75c8dd30b0ece48d81bf2059f` (the existing locally patched h3 baseline).
Its SHA-256 is `81e3d61ad3557bb7bb34d6838e3c2006c5a07e3dbe24e8ac6d909b365c6a6266`. Replaying it onto both pinned baseline source files
reproduced the fixed file hashes exactly; the patch reverses cleanly. Apply or
reverse this zero-context patch with `git apply --unidiff-zero` against the
pinned baseline; zero-context storage avoids whitespace-only context lines.

Two opt-in APIs leave `resolve_request()` source-compatible:
`RequestResolver::reject(code)` resets both request directions without parsing
headers, and `resolve_request_with_rejection_on_cancel(code)` owns cancellation
guards before returning its future. Dropping that future before its first poll,
during a partial header read, or while resolving an oversized-header reply
resets that request rather than implicitly finishing an empty response. The
guards disarm on normal success or an ordinary error, preserving existing
malformed-header/protocol error classification. No connection-wide error is
reclassified or suppressed; no unsafe code is introduced.

`RequestEnd` ownership now begins when the resolver is constructed, at the
same accepted-stream accounting boundary, and transfers into the resolved
request stream. Dropping/rejecting an unresolved resolver therefore releases
its ongoing-stream entry once. Successful streams retain their existing Arc
ownership across send/receive halves and normal drop.

The application uses request-scoped `H3_REQUEST_REJECTED` before dispatch for
planned cancellation, header-read timeout, stream-capacity refusal and late
drain resolution. Pin refusal retains its authentication error and uses
`H3_REQUEST_CANCELLED`. Transport limits, admission predicates, and the public
GOAWAY/error classifiers are unchanged.

Validation lives in `tunnel-transport`'s `m6c246_*` loopback mTLS/H3 tests:
unpolled/pre-cancel and in-progress partial-header cancellation, a scoped-reset
wire control, request accounting through GOAWAY completion, real semaphore
capacity refusal with an admitted sibling, normal released-capacity traffic,
and an exact server-side malformed-frame protocol error. The latter records
server classification; the fixture's early task return does not prove that
the same wire close code reached the client. Full transport checks and broader
acceptance are recorded under M6-C246 in `docs/tasks.md`.
