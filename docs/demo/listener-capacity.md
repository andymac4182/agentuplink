# Demo: a connection over the listener limit gets a 503, not a reset

Task row M6-C153 (fix for M6-C143). Every request goes
consumer -> relay -> device over the real local relay.

## What it shows

Each public listener serves at most `listener_max_connections` connections
(default 64). Before the fix, a connection over that limit was dropped before
TLS and the client saw a connection reset, the same as for a crashed relay. In
a 128-worker flood, 64 workers were reset on every attempt (about 120,000
`CONN_ConnectionResetError` per 60 s run). After the fix, the relay answers
such a connection and then closes it cleanly:

```
HTTP/1.1 503 Service Unavailable
retry-after: 1
connection: close
{"code":"CONNECTION_LIMIT","execution":"not_dispatched",
 "message":"relay listener connection limit reached",
 "retryable":true,"retry_after_ms":1000}
```

For the design and the reasons for choosing it, see
[runtime.md](../runtime.md#connections-over-the-limit-m6-c153).

## Run it

You need a Redis at `127.0.0.1:63790` (the harness uses a unique namespace
and deletes its keys), Python 3 and release binaries.

```sh
cargo build --release --locked --workspace --bins
python3 scripts/m6-soak.py flood --bin-dir target/release --logs /tmp/cap-demo \
  --workers 128 --seconds 60 --bin-head "$(git rev-parse HEAD)"
```

The harness sets up a relay, one device and one user with the shipped
commands. It then runs 128 closed-loop keep-alive echo workers for 60 s,
followed by 10 probe echoes. The workers retry at once and ignore
`Retry-After`, so this is a worst case.

Deterministic check with no relay (real TCP and TLS, limit + 1 connections):

```sh
cargo test --locked -p tunnel-transport --test m6_listener_capacity
```

## Expected output

In `/tmp/cap-demo/flood-*/summary.json`:

* `flood.errors_by_code` has only `CONNECTION_LIMIT/not_dispatched` and
  `RESOURCE_EXHAUSTED/not_dispatched`, with no `CONN_*` entry. Before the fix
  it had about 120,000 `CONN_ConnectionResetError`.
* `device_session_ends` is `[]` and `after` shows 10 of 10 answered 200.

Before M6-C193, in `requests.csv` 64 workers held the 64 served keep-alive
connections for the whole run and the other 64 got `CONNECTION_LIMIT` on
every attempt. Since M6-C193 the consumer listener turns its permits over
while it is full (below), so served workers change over the run: each served
connection is closed after a response once it has lived 5 -- 10 s (drawn
per connection) under pressure,
and a waiting connection takes its permit. Some `CONNECTION_LIMIT` refusals
remain, because 128 workers still want 64 permits.

The harness runs the relay with `RUST_LOG=warn`. At the default level, the
relay also logs `refusing connection over the listener connection limit`
(`phase=listener_capacity`), rate limited per listener.

## If it fails

* `CONN_ConnectionResetError` entries: check that `--bin-dir` points at
  binaries built from this branch (`tunnel-relay --version`). If so, the
  kernel listen backlog may have overflowed (`sysctl kern.ipc.somaxconn` or
  `net.core.somaxconn`). Record the run directory on row M6-C153 and do not
  re-run for a green result.
* `DEVICE_OFFLINE` from the start: the device never came up. Read
  `device-a-1.stderr.log` and `relay-1.log` in the run directory.
* To tune the limits, set `listener_max_connections` (`1..=4096`) or
  `listener_refusal_margin` (`0..=256`) at the top level of the relay
  config. A margin of `0` does no TLS work over the limit. Excess connections
  then wait in the backlog with no answer.

## Turnover: a late client is served during a flood (M6-C193, M6-C194)

Deterministic checks with no relay (real TCP and TLS 1.3):

```sh
cargo test --locked -p tunnel-transport --test m6_listener_turnover -- --nocapture
cargo test --locked -p tunnel-transport --test m6_consumer_resumption
```

`under_pressure_a_late_client_is_served_while_a_flood_holds_every_permit`
fills a 4-permit listener with busy keep-alive workers plus two that retry at
once, then connects a new client. It prints how long the late client waited,
for example `M6-C193 late client served after 498.556416ms and 0 refusals;
flood served 31843, connections recycled 4, capacity refusals 2`. Before the
fix the late client was refused on every attempt. Other tests in the file
check that nothing is recycled without pressure, that a streaming response and
a `101` upgrade are never cut, that HTTP/2 closes with GOAWAY after its
in-flight streams finish, the 500 ms hand-off, and that turnover of
connections open before pressure is spread out.

Through a real relay, user B connects 10 s into user A's 128-worker flood:

```sh
python3 scripts/m6-soak.py fairness --bin-dir target/release --logs /tmp/fair-demo \
  --flood-processes 2 --quiet-late-seconds 10 --bin-head "$(git rev-parse HEAD)"
```

In `/tmp/fair-demo/fairness-*/summary.json`, each `flood-quiet-on-*` phase has
`quiet_user_b_first_ok_s` with `all_served: true` and each B worker's seconds
to its first success, and `cpu_percent` has `listener_recycled`,
`listener_handoffs` and `listener_refusals` as rates per second. Before the
fix a B that connected during the flood got no success at all (0 of 198 in the
local run of M6-C193). Hosted results: task rows M6-C193 and M6-C194 and
[soak-2026-09-27.md](../soak-2026-09-27.md) section 8.

If B is never served: check that the relay is from this branch and that
`listener_refusal_margin` is not `0` (with no margin there is no pressure and
no turnover). Record the run directory on M6-C193; do not re-run for a green
result.

Server handshake cost by key type:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=localhost \
  -addext subjectAltName=DNS:localhost -addext basicConstraints=critical,CA:FALSE \
  -keyout /tmp/rsa.key -out /tmp/rsa.pem -days 2
cargo run --release --locked -p tunnel-transport --example handshake_cost -- /tmp/rsa.pem /tmp/rsa.key
```

prints the server CPU per full and resumed handshake for ECDSA P-256 and the
given key (M1 Pro: RSA-2048 full about 605 µs, ECDSA P-256 about 79 µs,
resumed about 74 µs with either).

## Descriptor exhaustion (M6-C155, M6-C156)

```sh
cargo test --locked -p tunnel-transport --test m6_accept_errors
cargo test --locked -p tunnel-transport --lib accept_error_tests
```

The first test lowers its own process's open-file limit to 256, fills it,
and connects so that the listener's `accept` fails with `EMFILE`. It then
checks that the listener is still serving. Before M6-C155 the listener
returned `Accept(Too many open files)`, and the relay exited.

To see the startup check, run `ulimit -n 100` in a shell, then start
`tunnel-relay serve` from it. Before it prints `tunnel-relay listening`, it
prints `tunnel-relay warning: open-file soft limit 100 is below the 160
descriptors ...`.
