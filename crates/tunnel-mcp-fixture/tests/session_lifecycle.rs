#![cfg(unix)]
//! Stdio export lifecycle guards (review round 1): legacy session idle
//! expiry, a stalled consumer confined to its own stream, duplicate in-flight
//! progress tokens, and process-group cleanup of wrapper descendants.

mod common;

use std::path::{Path, PathBuf};
use std::time::Duration;

use bytes::Bytes;
use common::{
    body_bytes, count_lines, exchange, fixture_binary, stdio_export_with, wait_for_file, within,
};
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Full};
use tunnel_http_bridge::ChannelBody;

const LEGACY: &str = "mcp-2025-11-25";
const CURRENT: &str = "mcp-2026-07-28";
const INIT: &str = r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"raw","version":"1"}}}"#;

fn legacy_headers(session: Option<&str>) -> Vec<(&'static str, String)> {
    let mut headers = vec![
        ("content-type", "application/json".to_owned()),
        ("accept", "application/json, text/event-stream".to_owned()),
        ("mcp-protocol-version", "2025-11-25".to_owned()),
    ];
    if let Some(session) = session {
        headers.push(("mcp-session-id", session.to_owned()));
    }
    headers
}

fn build<B>(method: &str, headers: &[(&'static str, String)], body: B) -> Request<B> {
    let mut builder = Request::builder()
        .method(method)
        .uri("/mcp")
        .header("host", "gateway.test");
    for (name, value) in headers {
        builder = builder.header(*name, value.as_str());
    }
    builder.body(body).expect("request")
}

fn post(headers: &[(&'static str, String)], body: &str) -> Request<Full<Bytes>> {
    build("POST", headers, Full::new(Bytes::from(body.to_owned())))
}

async fn open_session(export: &tunnel_mcp_export::McpExport) -> String {
    let response = within(exchange(export, post(&legacy_headers(None), INIT))).await;
    assert_eq!(response.status(), StatusCode::OK);
    let session = response.headers()["mcp-session-id"]
        .to_str()
        .expect("session")
        .to_owned();
    let _ = body_bytes(response).await;
    session
}

fn tools_list(id: u64) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/list"}}"#)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_idle_legacy_session_expires_even_with_an_open_get_stream() {
    let workspace = tempfile::tempdir().expect("workspace");
    let export = stdio_export_with(
        LEGACY,
        workspace.path(),
        1,
        &fixture_binary(),
        "session_idle_seconds = 1\n",
    );
    let session = open_session(&export).await;
    let mut get_headers = legacy_headers(Some(&session));
    get_headers.retain(|(name, _)| *name != "accept" && *name != "content-type");
    get_headers.push(("accept", "text/event-stream".to_owned()));
    let stream = within(exchange(
        &export,
        build("GET", &get_headers, Full::new(Bytes::new())),
    ))
    .await;
    assert_eq!(stream.status(), StatusCode::OK);
    tokio::time::sleep(Duration::from_millis(2500)).await;
    // The session ended: its stream is interrupted, its child is gone and
    // its only slot is free for a new session.
    assert!(body_bytes(stream).await.is_err(), "open GET interrupted");
    let response = within(exchange(
        &export,
        post(&legacy_headers(Some(&session)), &tools_list(1)),
    ))
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let diagnostics = export.diagnostics();
    assert_eq!(diagnostics.sessions_expired, 1, "{diagnostics:?}");
    for _ in 0..200 {
        if export.diagnostics().children_running == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(export.diagnostics().children_running, 0);
    let _replacement = open_session(&export).await;
}

/// M3-27: the count that announces an expiry is published only after the
/// session has left the map.  The reader here waits on `sessions_expired`
/// and then reads the map at once, with nothing between them that could
/// close a gap for it: had the counter been released before the removal, as
/// it once was, a reader landing in between would see an expired session
/// still open.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_expired_session_has_left_the_map_before_its_expiry_is_counted() {
    let workspace = tempfile::tempdir().expect("workspace");
    let export = stdio_export_with(
        LEGACY,
        workspace.path(),
        1,
        &fixture_binary(),
        "session_idle_seconds = 1\n",
    );
    let _session = open_session(&export).await;
    assert_eq!(export.open_stdio_sessions(), Some(1), "the session is open");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    // A tight poll, so the read lands as close to the release as it can.
    while export.diagnostics().sessions_expired == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the idle session never expired: {:?}",
            export.diagnostics()
        );
        tokio::task::yield_now().await;
    }
    assert_eq!(
        export.open_stdio_sessions(),
        Some(0),
        "an expiry was counted while the session was still in the map"
    );
    assert_eq!(export.diagnostics().sessions_expired, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn activity_keeps_a_legacy_session_alive() {
    let workspace = tempfile::tempdir().expect("workspace");
    let export = stdio_export_with(
        LEGACY,
        workspace.path(),
        1,
        &fixture_binary(),
        "session_idle_seconds = 3\n",
    );
    let session = open_session(&export).await;
    // Five 1 s gaps outlast the 3 s idle limit, with 2 s of margin per
    // exchange for a loaded host.
    for id in 1..=5u64 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let response = within(exchange(
            &export,
            post(&legacy_headers(Some(&session)), &tools_list(id)),
        ))
        .await;
        assert_eq!(response.status(), StatusCode::OK, "request {id}");
        let _ = body_bytes(response).await;
    }
    assert_eq!(export.diagnostics().sessions_expired, 0);
}

fn direct(headers: &[(&'static str, String)], body: &str) -> Request<ChannelBody> {
    build(
        "POST",
        headers,
        ChannelBody::full(Bytes::from(body.to_owned())),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stalled_consumer_interrupts_only_its_own_stream() {
    let workspace = tempfile::tempdir().expect("workspace");
    let export = stdio_export_with(LEGACY, workspace.path(), 1, &fixture_binary(), "");
    let session = open_session(&export).await;
    let headers = legacy_headers(Some(&session));
    // A progress stream whose consumer never reads: served directly by the
    // export so no bridge buffer absorbs the backlog.
    let stalled = within(export.handle(direct(
        &headers,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"progress","arguments":{"steps":100},"_meta":{"progressToken":"stalled"}}}"#,
    )))
    .await
    .expect("stalled stream head");
    assert_eq!(stalled.status(), StatusCode::OK);
    let log = workspace.path().join("invocations.log");
    for _ in 0..400 {
        if count_lines(&log, "progress") == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // Wait for the stall itself, with a bound, rather than for a fixed time.
    // The detector counts at the instant a notification finds this stream's
    // queue full, which needs the child to have emitted about
    // `SESSION_STREAM_QUEUE` + `STREAM_QUEUE` notifications at 5 ms apart or
    // slower.  A fixed 800 ms sleep usually covered that, but on a loaded
    // host the child had not emitted enough by the time the echo below
    // completed, so a bare read of the count after the echo raced the child
    // (M3-20).  Waiting here also makes the echo run with the stall already
    // detected, which is the ordering this test is about.
    let stall_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while export.diagnostics().stalled_streams == 0 {
        assert!(
            tokio::time::Instant::now() < stall_deadline,
            "the stalled stream was never detected: {:?}",
            export.diagnostics()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // Another request on the same session still completes promptly.
    let echo = tokio::time::timeout(
        Duration::from_secs(5),
        export.handle(direct(
            &headers,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{}}}"#,
        )),
    )
    .await
    .expect("the session pump is not blocked by the stalled stream")
    .expect("echo");
    assert_eq!(echo.status(), StatusCode::OK);
    let bytes = tokio::time::timeout(Duration::from_secs(5), echo.into_body().collect())
        .await
        .expect("echo body")
        .expect("echo body ok")
        .to_bytes();
    assert!(String::from_utf8_lossy(&bytes).contains(r#""id":2"#));
    // Exactly the one stalled stream: the echo, which was read, is not one.
    assert_eq!(export.diagnostics().stalled_streams, 1);
    // The stalled stream itself is interrupted, not completed.
    let collected = tokio::time::timeout(Duration::from_secs(5), stalled.into_body().collect())
        .await
        .expect("stalled body ends");
    assert!(collected.is_err(), "the stalled stream is interrupted");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_duplicate_in_flight_progress_token_is_rejected() {
    let workspace = tempfile::tempdir().expect("workspace");
    let export = stdio_export_with(LEGACY, workspace.path(), 1, &fixture_binary(), "");
    let session = open_session(&export).await;
    let headers = legacy_headers(Some(&session));
    let sleep = |id: u64, token: &str| {
        format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"sleep","arguments":{{"label":"t{id}"}},"_meta":{{"progressToken":"{token}"}}}}}}"#
        )
    };
    let first_export = export.clone();
    let first_headers = headers.clone();
    let first_body = sleep(1, "shared");
    let first = tokio::spawn(async move {
        let response = exchange(&first_export, post(&first_headers, &first_body)).await;
        tokio::time::sleep(Duration::from_secs(3)).await;
        drop(response);
    });
    let log = workspace.path().join("invocations.log");
    for _ in 0..400 {
        if count_lines(&log, "sleep") == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let response = within(exchange(&export, post(&headers, &sleep(2, "shared")))).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = body_bytes(response).await.expect("body");
    assert!(String::from_utf8_lossy(&body).contains("progress token"));
    assert_eq!(count_lines(&log, "sleep"), 1, "the duplicate never ran");
    first.abort();
}

/// M3-48: a request the client cancelled with `notifications/cancelled` must
/// not hold its POST open until the session is deleted.  The server need not
/// answer a cancelled request (2025-11-25), and rmcp's fixture does not, so
/// the bridge closes that POST itself: promptly, cleanly (not interrupted)
/// and with no JSON-RPC response it did not receive.  The session stays
/// usable and its DELETE is clean.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancelled_legacy_request_closes_its_post_promptly() {
    let workspace = tempfile::tempdir().expect("workspace");
    let export = stdio_export_with(LEGACY, workspace.path(), 1, &fixture_binary(), "");
    let session = open_session(&export).await;
    let headers = legacy_headers(Some(&session));
    let cancelled_export = export.clone();
    let cancelled_headers = headers.clone();
    let cancelled = tokio::spawn(async move {
        let response = exchange(
            &cancelled_export,
            post(
                &cancelled_headers,
                r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"sleep","arguments":{"label":"m348"}}}"#,
            ),
        )
        .await;
        let status = response.status();
        (status, body_bytes(response).await)
    });
    let log = workspace.path().join("invocations.log");
    for _ in 0..400 {
        if count_lines(&log, "sleep") == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(count_lines(&log, "sleep"), 1, "sleep started");
    let cancel = within(exchange(
        &export,
        post(
            &headers,
            r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7,"reason":"synthetic"}}"#,
        ),
    ))
    .await;
    assert_eq!(cancel.status(), StatusCode::ACCEPTED);
    assert!(
        wait_for_file(&workspace.path().join("cancelled-m348")).await,
        "the child observed notifications/cancelled"
    );
    // Well inside the session's lifetime: nothing deletes it before this.
    let (status, body) = tokio::time::timeout(Duration::from_secs(5), cancelled)
        .await
        .expect("the cancelled POST closed without waiting for DELETE")
        .expect("task");
    assert_eq!(status, StatusCode::OK);
    let body = body.expect("the cancelled POST ends cleanly, not interrupted");
    assert!(
        !String::from_utf8_lossy(&body).contains(r#""id":7"#),
        "no response for the cancelled request"
    );
    assert_eq!(export.diagnostics().cancelled_requests_closed, 1);
    // The session is still usable, and ending it is clean.
    let response = within(exchange(&export, post(&headers, &tools_list(8)))).await;
    assert_eq!(response.status(), StatusCode::OK);
    let _ = body_bytes(response).await;
    let mut delete_headers = headers.clone();
    delete_headers.retain(|(name, _)| *name != "content-type");
    let deleted = within(exchange(
        &export,
        build("DELETE", &delete_headers, Full::new(Bytes::new())),
    ))
    .await;
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
}

/// M3-48 review: closing a cancelled request's POST must not free its ID
/// early.  The cancelled request stays registered until its own POST has
/// ended, so a new request that reuses the ID in that window is refused as a
/// duplicate.  Before the review fix it was registered instead: it could then
/// receive the cancelled request's late response (rmcp's fixture answers a
/// cancelled `sleep`), or be torn down by the old POST's cleanup, which
/// would interrupt it.  The old POST's future is deliberately left unpolled
/// after the cancel, which holds that window open.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_id_reused_right_after_its_cancel_is_never_interrupted() {
    let workspace = tempfile::tempdir().expect("workspace");
    let export = stdio_export_with(LEGACY, workspace.path(), 1, &fixture_binary(), "");
    let session = open_session(&export).await;
    let headers = legacy_headers(Some(&session));
    let sleep = |label: &str| {
        format!(
            r#"{{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{{"name":"sleep","arguments":{{"label":"{label}"}}}}}}"#
        )
    };
    // The first request, polled only until it is registered and waiting.
    let mut first = Box::pin(export.handle(direct(&headers, &sleep("old"))));
    let log = workspace.path().join("invocations.log");
    for _ in 0..400 {
        if tokio::time::timeout(Duration::from_millis(10), &mut first)
            .await
            .is_ok()
        {
            panic!("the sleep request answered before it was cancelled");
        }
        if count_lines(&log, "sleep") == 1 {
            break;
        }
    }
    assert_eq!(count_lines(&log, "sleep"), 1, "sleep started");
    let cancel = within(export.handle(direct(
        &headers,
        r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7}}"#,
    )))
    .await
    .expect("cancel");
    assert_eq!(cancel.status(), StatusCode::ACCEPTED);
    // The same ID again, while the old POST has not yet run its cleanup.
    let reuse_export = export.clone();
    let reuse_headers = headers.clone();
    let reuse_body = sleep("new");
    let reuse = tokio::spawn(async move {
        reuse_export
            .handle(direct(&reuse_headers, &reuse_body))
            .await
            .map(|response| response.status())
    });
    // Give a registered reuse time to reach the child before the old POST's
    // cleanup runs; a refused one has already answered.
    for _ in 0..100 {
        if reuse.is_finished() || count_lines(&log, "sleep") == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // Now let the old POST end, and its cleanup run.
    let old = within(first)
        .await
        .expect("the cancelled POST ends cleanly");
    assert_eq!(old.status(), StatusCode::OK);
    let reuse = tokio::time::timeout(Duration::from_secs(3), reuse).await;
    match reuse {
        // Refused before dispatch: the ID was still in flight.
        Ok(Ok(Ok(status))) => assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "refused as a duplicate, never answered with another request's response"
        ),
        Ok(Ok(Err(_))) => panic!("the reused ID's POST was interrupted"),
        Ok(Err(error)) => panic!("task: {error}"),
        // Registered and still waiting: not interrupted either.
        Err(_) => {}
    }
}

/// M3-48's limit: a cancellation names a request of **this** session only.
/// A `requestId` that is not in flight closes nothing and is still
/// forwarded (202), and the in-flight request with another ID is untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancellation_for_another_id_closes_nothing() {
    let workspace = tempfile::tempdir().expect("workspace");
    let export = stdio_export_with(LEGACY, workspace.path(), 1, &fixture_binary(), "");
    let session = open_session(&export).await;
    let headers = legacy_headers(Some(&session));
    let cancel = within(exchange(
        &export,
        post(
            &headers,
            r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":99}}"#,
        ),
    ))
    .await;
    assert_eq!(cancel.status(), StatusCode::ACCEPTED);
    let response = within(exchange(&export, post(&headers, &tools_list(99)))).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_bytes(response).await.expect("body");
    assert!(String::from_utf8_lossy(&body).contains(r#""id":99"#));
    assert_eq!(export.diagnostics().cancelled_requests_closed, 0);
}

/// M3-10, stdio export kind: no resume, and it says so on the wire.  The
/// bridge emits no SSE `id:` field, so a conforming client never has a
/// `Last-Event-ID` to send.  A GET that carries one anyway is served as a
/// fresh standalone stream of this session: nothing is replayed, from this
/// stream or any other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_stdio_export_emits_no_event_ids_and_replays_nothing() {
    let workspace = tempfile::tempdir().expect("workspace");
    let export = stdio_export_with(LEGACY, workspace.path(), 1, &fixture_binary(), "");
    let session = open_session(&export).await;
    let headers = legacy_headers(Some(&session));
    let progress = within(exchange(
        &export,
        post(
            &headers,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"progress","arguments":{"steps":3},"_meta":{"progressToken":"m310"}}}"#,
        ),
    ))
    .await;
    assert_eq!(progress.status(), StatusCode::OK);
    let body = body_bytes(progress).await.expect("progress body");
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("notifications/progress"), "an SSE response");
    assert!(
        !text.lines().any(|line| line.starts_with("id:")),
        "no event carries an ID"
    );
    // The standalone stream: server messages that belong to no request.
    let mut get_headers = legacy_headers(Some(&session));
    get_headers.retain(|(name, _)| *name != "accept" && *name != "content-type");
    get_headers.push(("accept", "text/event-stream".to_owned()));
    let log = |label: &str, id: u64| {
        format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"log","arguments":{{"label":"{label}","count":3}}}}}}"#
        )
    };
    let first = within(exchange(
        &export,
        build("GET", &get_headers, Full::new(Bytes::new())),
    ))
    .await;
    assert_eq!(first.status(), StatusCode::OK);
    let mut first = first.into_body();
    let call = within(exchange(&export, post(&headers, &log("before", 4)))).await;
    let _ = body_bytes(call).await;
    let delivered = read_until(&mut first, r#""label":"before","seq":2"#).await;
    assert!(delivered.contains(r#""label":"before","seq":0"#));
    assert!(
        !delivered.lines().any(|line| line.starts_with("id:")),
        "no standalone event carries an ID"
    );
    drop(first);
    // Reconnect with a Last-Event-ID, as a resuming client would.  The old
    // stream's close is noticed asynchronously, so a GET that still meets
    // the open stream is refused and retried, bounded.
    get_headers.push(("last-event-id", "0".to_owned()));
    let mut second = None;
    for _ in 0..200 {
        let response = within(exchange(
            &export,
            build("GET", &get_headers, Full::new(Bytes::new())),
        ))
        .await;
        if response.status() == StatusCode::OK {
            second = Some(response.into_body());
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mut second = second.expect("a second standalone stream opens");
    let call = within(exchange(&export, post(&headers, &log("after", 5)))).await;
    let _ = body_bytes(call).await;
    let resumed = read_until(&mut second, r#""label":"after","seq":2"#).await;
    // A resuming bridge would deliver the messages already seen first.
    assert!(
        !resumed.contains(r#""label":"before""#),
        "nothing already delivered is replayed: {resumed}"
    );
    assert!(resumed.contains(r#""label":"after","seq":0"#));
}

/// Read `body` until `needle` has arrived; returns everything read.
async fn read_until(body: &mut tunnel_http_bridge::ChannelBody, needle: &str) -> String {
    let mut text = String::new();
    within(async {
        while !text.contains(needle) {
            let frame = body.frame().await.expect("stream open").expect("frame");
            if let Ok(data) = frame.into_data() {
                text.push_str(std::str::from_utf8(&data).expect("utf-8"));
            }
        }
    })
    .await;
    text
}

fn wrapper_script(dir: &Path) -> PathBuf {
    let script = dir.join("wrapper.sh");
    write_executable(
        &script,
        &format!(
            "#!/bin/sh\n/bin/sleep 300 &\necho $! > grandchild.pid\nexec \"{}\" \"$@\"\n",
            fixture_binary().display()
        ),
    );
    script
}

/// Write an executable script that no descriptor of **this** process has
/// ever held open for writing (task row M3-35).
///
/// Tests in one binary run on parallel threads, and each spawn briefly
/// shares this process's descriptor table with a child that has not yet
/// `exec`ed.  A script written here with `std::fs::write` can therefore still
/// be open for writing in such a child when another thread `exec`s it, and
/// Linux refuses that `exec` with `ETXTBSY` -- seen once on hosted
/// `ubuntu-latest` as `spawn: SpawnError`.  So the text is written to a
/// side file and `/bin/cp` creates the script: the only writer of the
/// script's inode is the `cp` process, which exits before this returns.
fn write_executable(script: &Path, text: &str) {
    let source = script.with_extension("src");
    std::fs::write(&source, text).expect("script source");
    for (program, args) in [
        ("/bin/cp", vec![source.as_os_str(), script.as_os_str()]),
        ("/bin/chmod", vec!["755".as_ref(), script.as_os_str()]),
    ] {
        let status = std::process::Command::new(program)
            .args(args)
            .status()
            .expect("run a script writer");
        assert!(status.success(), "{program} failed");
    }
}

fn alive(pid: &str) -> bool {
    std::process::Command::new("/bin/kill")
        .args(["-0", pid])
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

async fn grandchild_is_reaped(workspace: &Path) {
    let mut pid = String::new();
    for _ in 0..200 {
        pid = std::fs::read_to_string(workspace.join("grandchild.pid"))
            .unwrap_or_default()
            .trim()
            .to_owned();
        if !pid.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(!pid.is_empty(), "the wrapper started a grandchild");
    for _ in 0..500 {
        if !alive(&pid) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // Clean up before failing so a red run leaks nothing.
    let _ = std::process::Command::new("/bin/kill")
        .args(["-9", &pid])
        .status();
    panic!("grandchild {pid} outlived its process group");
}

fn current_call(id: u64, tool: &str) -> (Vec<(&'static str, String)>, String) {
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{tool}","arguments":{{}},"_meta":{{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}}}}"#
    );
    let headers = vec![
        ("content-type", "application/json".to_owned()),
        ("accept", "application/json, text/event-stream".to_owned()),
        ("mcp-protocol-version", "2026-07-28".to_owned()),
        ("mcp-method", "tools/call".to_owned()),
        ("mcp-name", tool.to_owned()),
    ];
    (headers, body)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrapper_descendants_die_with_a_completed_request() {
    let workspace = tempfile::tempdir().expect("workspace");
    let script = wrapper_script(workspace.path());
    let export = stdio_export_with(CURRENT, workspace.path(), 2, &script, "");
    let (headers, body) = current_call(1, "echo");
    let response = within(exchange(&export, post(&headers, &body))).await;
    assert_eq!(response.status(), StatusCode::OK);
    let _ = body_bytes(response).await;
    grandchild_is_reaped(workspace.path()).await;
    // M3-35: the grandchild dies from the supervisor's *pre-reap* group
    // signal, which is not counted; `child_group_kills` counts only the
    // post-reap one, sent after `child.wait()` returns.  Reading the counter
    // the moment the grandchild is gone raced that second signal (the
    // M5-C18 window), so wait for the supervisor itself, bounded.
    assert!(
        group_kill_counted(&export).await,
        "the supervisor never counted its post-reap group kill"
    );
}

/// Wait, bounded, until the export's supervisor has counted a post-reap
/// group kill.  The count is the supervisor's last step before its child is
/// reported gone, so a slow supervisor is waited for and a missing kill is
/// still red.
async fn group_kill_counted(export: &tunnel_mcp_export::McpExport) -> bool {
    for _ in 0..1_000 {
        if export.diagnostics().child_group_kills >= 1 {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrapper_descendants_die_when_the_server_crashes() {
    let workspace = tempfile::tempdir().expect("workspace");
    let script = wrapper_script(workspace.path());
    let export = stdio_export_with(CURRENT, workspace.path(), 2, &script, "");
    let (headers, body) = current_call(1, "crash");
    let response = within(exchange(&export, post(&headers, &body))).await;
    let _ = body_bytes(response).await;
    grandchild_is_reaped(workspace.path()).await;
}

/// M3-04 review: a legacy session's pump is a detached task that owns the
/// child and its `max_children` permit, so a session nobody ended used to
/// keep its child alive after the export, the connector's handler registry
/// and the device session were gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unended_legacy_session_dies_with_its_export() {
    let workspace = tempfile::tempdir().expect("workspace");
    let script = wrapper_script(workspace.path());
    let export = stdio_export_with(LEGACY, workspace.path(), 2, &script, "");
    let _session = open_session(&export).await;
    assert_eq!(export.diagnostics().children_running, 1);
    // No DELETE, no idle expiry: just the export going away, as it does when
    // the connector drops its handlers.
    drop(export);
    grandchild_is_reaped(workspace.path()).await;
}

/// The explicit form a connector can call before dropping its handlers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_ends_every_open_legacy_session() {
    let workspace = tempfile::tempdir().expect("workspace");
    let script = wrapper_script(workspace.path());
    let export = stdio_export_with(LEGACY, workspace.path(), 2, &script, "");
    let _session = open_session(&export).await;
    export.shutdown();
    // Idempotent, and the counters settle without dropping the export.
    export.shutdown();
    grandchild_is_reaped(workspace.path()).await;
    for _ in 0..500 {
        if export.diagnostics().children_running == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(export.diagnostics().children_running, 0);
    assert!(export.diagnostics().child_group_kills >= 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrapper_descendants_die_when_a_legacy_session_is_deleted() {
    let workspace = tempfile::tempdir().expect("workspace");
    let script = wrapper_script(workspace.path());
    let export = stdio_export_with(LEGACY, workspace.path(), 2, &script, "");
    let session = open_session(&export).await;
    let mut delete_headers = legacy_headers(Some(&session));
    delete_headers.retain(|(name, _)| *name != "accept" && *name != "content-type");
    let response = within(exchange(
        &export,
        build("DELETE", &delete_headers, Full::new(Bytes::new())),
    ))
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    grandchild_is_reaped(workspace.path()).await;
}
