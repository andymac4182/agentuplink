#![cfg(unix)]
//! The official rmcp client against the Streamable HTTP export, which
//! forwards to the official rmcp Streamable HTTP server on a fixed loopback
//! port, through the in-process http-forward/1 bridge.

mod common;

use std::time::Duration;

use common::{
    connect, connect_pinned, count_lines, gateway, http_export, rmcp_http_backend, wait_for_file,
    within,
};
use rmcp::model::{CallToolRequestParams, ClientRequest, Request, RequestMetaObject};
use rmcp::service::PeerRequestOptions;

fn arguments(value: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    value.as_object().cloned().expect("object")
}

async fn http_export_round_trip(profile: &str, legacy: bool) {
    let dir = tempfile::tempdir().expect("dir");
    let (url, shutdown) = rmcp_http_backend(legacy, dir.path()).await;
    let export = http_export(profile, &url, None);
    let gateway = gateway(export.clone(), dir.path());
    let (client, handler) = connect(&gateway, legacy).await;

    let tools = within(client.list_all_tools()).await.expect("tools/list");
    assert!(tools.iter().any(|tool| tool.name == "progress"));

    let mut meta = RequestMetaObject::new();
    meta.insert(
        "io.agent-tunnel.test/marker".to_owned(),
        serde_json::json!({"k": [true, null, 7]}),
    );
    let mut params =
        CallToolRequestParams::new("echo").with_arguments(arguments(serde_json::json!({"z": 26})));
    params.meta = Some(meta);
    let echoed = within(client.call_tool(params)).await.expect("echo");
    let text = echoed
        .content
        .iter()
        .find_map(|block| block.as_text().map(|text| text.text.clone()))
        .expect("text");
    let seen: serde_json::Value = serde_json::from_str(&text).expect("json");
    assert_eq!(seen["arguments"], serde_json::json!({"z": 26}));
    assert_eq!(
        seen["meta"]["io.agent-tunnel.test/marker"],
        serde_json::json!({"k": [true, null, 7]})
    );

    let handle = within(
        client.send_cancellable_request(
            ClientRequest::CallToolRequest(Request::new(
                CallToolRequestParams::new("progress")
                    .with_arguments(arguments(serde_json::json!({"steps": 3}))),
            )),
            PeerRequestOptions::no_options(),
        ),
    )
    .await
    .expect("progress");
    within(handle.await_response())
        .await
        .expect("progress result");
    assert_eq!(
        handler.progress.lock().expect("lock").clone(),
        vec![1.0, 2.0, 3.0]
    );

    // Cancellation: 2026 closes the request's response stream (the export
    // drops the backend connection); 2025 POSTs notifications/cancelled.
    let handle = within(
        client.send_cancellable_request(
            ClientRequest::CallToolRequest(Request::new(
                CallToolRequestParams::new("sleep")
                    .with_arguments(arguments(serde_json::json!({"label": "h1"}))),
            )),
            PeerRequestOptions::no_options(),
        ),
    )
    .await
    .expect("sleep");
    let log = dir.path().join("invocations.log");
    for _ in 0..400 {
        if count_lines(&log, "sleep") == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    within(handle.cancel(Some("test".to_owned())))
        .await
        .expect("cancel");
    assert!(
        wait_for_file(&dir.path().join("cancelled-h1")).await,
        "{profile}: the backend observed cancellation"
    );
    assert_eq!(count_lines(&log, "sleep"), 1);
    let diagnostics = export.diagnostics();
    assert_eq!(diagnostics.children_spawned, 0);
    assert!(diagnostics.dispatched >= 4, "{diagnostics:?}");
    let _ = within(client.cancel()).await;
    shutdown.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn current_profile_http_export_round_trip_and_cancellation() {
    http_export_round_trip("mcp-2026-07-28", false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn legacy_profile_http_export_round_trip_and_cancellation() {
    http_export_round_trip("mcp-2025-11-25", true).await;
}

/// M3-38 for the Streamable HTTP export kind: an `initialize` offering an
/// older revision is refused by the export before anything is dispatched to
/// the backend, which would otherwise have accepted it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn legacy_profile_http_export_refuses_an_older_revision_at_initialize() {
    let dir = tempfile::tempdir().expect("dir");
    let (url, shutdown) = rmcp_http_backend(true, dir.path()).await;
    let export = http_export("mcp-2025-11-25", &url, None);
    let gateway = gateway(export.clone(), dir.path());
    let outcome = connect_pinned(&gateway, rmcp::model::ProtocolVersion::V_2025_06_18).await;
    assert!(
        outcome.is_err(),
        "initialize offering 2025-06-18 must fail at initialize"
    );
    let diagnostics = export.diagnostics();
    assert_eq!(diagnostics.dispatched, 0, "{diagnostics:?}");
    let current = connect_pinned(&gateway, rmcp::model::ProtocolVersion::V_2025_11_25)
        .await
        .expect("2025-11-25 initialize");
    let _ = within(current.cancel()).await;
    shutdown.cancel();
}

/// Read SSE events from `body` until `done` holds for one of them; returns
/// each event as `(id, data)`.
async fn read_events(
    body: &mut tunnel_http_bridge::ChannelBody,
    mut done: impl FnMut(&(Option<String>, String)) -> bool,
) -> Vec<(Option<String>, String)> {
    use http_body_util::BodyExt;
    let mut buffer = String::new();
    let mut events = Vec::new();
    loop {
        while let Some(end) = buffer.find("\n\n") {
            let raw: String = buffer.drain(..end + 2).collect();
            let mut id = None;
            let mut data = String::new();
            for line in raw.lines() {
                if let Some(value) = line.strip_prefix("id:") {
                    id = Some(value.trim().to_owned());
                } else if let Some(value) = line.strip_prefix("data:") {
                    data.push_str(value.trim_start());
                }
            }
            let event = (id, data);
            let stop = done(&event);
            events.push(event);
            if stop {
                return events;
            }
        }
        let frame = within(body.frame())
            .await
            .expect("the stream ended early")
            .expect("frame");
        if let Ok(data) = frame.into_data() {
            buffer.push_str(std::str::from_utf8(&data).expect("utf-8"));
        }
    }
}

/// M3-10, Streamable HTTP export kind: the export neither emits nor
/// interprets SSE event IDs.  It forwards the backend's `id:` fields and a
/// consumer's `Last-Event-ID` unchanged, inside the principal-bound session
/// (M3-04), so resume is exactly the backend's.  Here the backend is rmcp's
/// own server: a POST stream abandoned after its first event is resumed by
/// a GET carrying that event's ID, which delivers the rest of that
/// request's events and its final response, from that request's stream
/// only.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn legacy_http_export_forwards_last_event_id_to_the_backend() {
    use common::{body_bytes, exchange};
    let dir = tempfile::tempdir().expect("dir");
    let (url, shutdown) = rmcp_http_backend(true, dir.path()).await;
    let export = http_export("mcp-2025-11-25", &url, None);
    let head = |session: Option<&str>| {
        let mut builder = http::Request::builder()
            .uri("/mcp")
            .header("host", "gateway.test")
            .header("accept", "application/json, text/event-stream")
            .header("content-type", "application/json")
            .header("mcp-protocol-version", "2025-11-25");
        if let Some(session) = session {
            builder = builder.header("mcp-session-id", session);
        }
        builder
    };
    let post = |session: Option<&str>, body: &str| {
        head(session)
            .method("POST")
            .body(http_body_util::Full::new(bytes::Bytes::from(
                body.to_owned(),
            )))
            .expect("request")
    };
    let init = within(exchange(
        &export,
        post(
            None,
            r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"raw","version":"1"}}}"#,
        ),
    ))
    .await;
    assert_eq!(init.status(), http::StatusCode::OK);
    let session = init.headers()["mcp-session-id"]
        .to_str()
        .expect("session")
        .to_owned();
    let _ = body_bytes(init).await;
    let initialized = within(exchange(
        &export,
        post(
            Some(&session),
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        ),
    ))
    .await;
    assert_eq!(initialized.status(), http::StatusCode::ACCEPTED);
    let _ = body_bytes(initialized).await;

    let call = within(exchange(
        &export,
        post(
            Some(&session),
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"progress","arguments":{"steps":20},"_meta":{"progressToken":"m310"}}}"#,
        ),
    ))
    .await;
    assert_eq!(call.status(), http::StatusCode::OK);
    let mut body = call.into_body();
    // The first event that carries data and an ID: the backend's, forwarded.
    let first = within(read_events(&mut body, |(id, data)| {
        id.is_some() && !data.is_empty()
    }))
    .await;
    let (Some(seen_id), _) = first.last().cloned().expect("an event") else {
        panic!("the backend's event IDs reach the consumer");
    };
    // Abandon the POST stream: a 2025-11-25 disconnect, not a cancellation.
    drop(body);

    let resume = head(Some(&session))
        .method("GET")
        .header("last-event-id", seen_id.as_str())
        .body(http_body_util::Full::new(bytes::Bytes::new()))
        .expect("request");
    let resumed = within(exchange(&export, resume)).await;
    assert_eq!(resumed.status(), http::StatusCode::OK);
    let mut body = resumed.into_body();
    // Bounded as a whole: keep-alive comments would satisfy a per-frame
    // bound for ever.
    let rest = within(read_events(&mut body, |(_, data)| {
        data.contains(r#""id":5"#) && data.contains(r#""result""#)
    }))
    .await;
    // rmcp's IDs are `<index>/<request stream>`.  Every resumed event is from
    // the abandoned request's own stream and none precedes the one seen, so
    // the header reached the backend and nothing crossed streams.  rmcp
    // 3.4.0 re-delivers the `Last-Event-ID` event itself (M3-52, upstream):
    // a duplicate the relay forwards unchanged, as it forwards everything.
    let (seen_index, seen_stream) = seen_id.split_once('/').expect("rmcp event id");
    let seen_index: usize = seen_index.parse().expect("index");
    for (id, _) in &rest {
        let id = id.as_deref().expect("every resumed event has an id");
        let (index, stream) = id.split_once('/').expect("rmcp event id");
        assert_eq!(stream, seen_stream, "no event from another stream: {id}");
        assert!(
            index.parse::<usize>().expect("index") >= seen_index,
            "nothing before the resumed event: {id}"
        );
    }
    assert!(
        rest.iter()
            .filter(|(_, data)| data.contains("notifications/progress"))
            .count()
            >= 19,
        "the rest of the request's progress arrives on the resumed stream"
    );
    drop(body);
    shutdown.cancel();
}
