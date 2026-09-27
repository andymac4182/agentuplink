//! Task row M6-C210, route level: a consumer stream whose OPEN is in a frozen
//! rotation roster and that the connector refuses `GOAWAY` "connector is
//! draining" gets the retryable rotation answer on the wire, through the real
//! consumer router on a loopback listener.
//!
//! The relay is a real actor with a fake connector (forwarded control and
//! data registrations, as `pending_open_abandon_tests` uses).  The freeze is
//! entered through the actor's own quiesce transition by a test hook
//! (`enter_rotation_freeze_for_test`) after the consumer's OPEN is queued, so
//! the OPEN is in the roster; the connector stand-in then answers that exact
//! OPEN with the shipped `GOAWAY` refusal.  A connector-driven PREPARE and
//! candidate attach are not exercised here; the actor tests in
//! `actor_rotation_freeze_tests` drive a full attempt.

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use chrono::{Duration as ChronoDuration, Utc};
use futures_util::StreamExt as _;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rcgen::KeyPair;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    time::timeout,
};
use tokio_tungstenite::tungstenite::{
    Message as WsMessage, client::IntoClientRequest, http::HeaderValue,
};
use tunnel_catalog::{
    ApprovedJwk, Catalog, CatalogFixture, CredentialRecord, FixtureDevice, GrantSpec,
    MembershipRecord, MembershipRole, MemoryCatalog, OidcConfig, OidcVerifier, PermissionSet,
    PrincipalIdentity, ServiceSpec, TenantRecord, UserRecord,
};
use tunnel_protocol::{ControlMessage, Hello, Rejected};
use uuid::Uuid;

use super::{ECHO_STREAM_SUBPROTOCOL, consumer_router_with_peer_and_barriers, wire};
use crate::{
    actor::{ControlOutbound, RelayHandle, SessionKey},
    config::RelayOptions,
};

const ISSUER: &str = "https://rotation-refusal-issuer.example";
const AUDIENCE: &str = "rotation-refusal-audience";
const KID: &str = "rotation-refusal";
const SUBJECT: &str = "rotation-refusal-consumer";
const DEVICE_SPKI: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const PROFILE: &str = "mcp-2026-07-28";
const BUDGET: Duration = Duration::from_secs(5);

fn tenant_id() -> Uuid {
    Uuid::from_u128(0x3700_0000_0000_0000_0000_0000_0000_0001)
}
fn user_id() -> Uuid {
    Uuid::from_u128(0x3700_0000_0000_0000_0000_0000_0000_0002)
}
fn device_id() -> Uuid {
    Uuid::from_u128(0x3700_0000_0000_0000_0000_0000_0000_0003)
}
fn echo_service() -> Uuid {
    Uuid::from_u128(0x3700_0000_0000_0000_0000_0000_0000_0004)
}
fn http_service() -> Uuid {
    Uuid::from_u128(0x3700_0000_0000_0000_0000_0000_0000_0005)
}
fn fs_service() -> Uuid {
    Uuid::from_u128(0x3700_0000_0000_0000_0000_0000_0000_0006)
}

#[derive(serde::Serialize)]
struct Claims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    exp: i64,
    scope: &'a str,
}

fn catalog_fixture() -> CatalogFixture {
    let now = Utc::now();
    let service = |service_id, service_type: &str, capabilities| ServiceSpec {
        tenant_id: tenant_id(),
        device_id: device_id(),
        service_id,
        service_type: service_type.to_owned(),
        display_name: format!("rotation-refusal {service_type}"),
        capabilities,
        version: 1,
        active: true,
    };
    let grant = |service_id, operations: &[&str]| GrantSpec {
        tenant_id: tenant_id(),
        principal_id: user_id(),
        device_id: device_id(),
        service_id,
        permissions: PermissionSet {
            operations: operations
                .iter()
                .map(|op| (*op).to_owned())
                .collect::<BTreeSet<_>>(),
        },
        constraints: serde_json::json!({}),
        expires_at: Some(now + ChronoDuration::minutes(5)),
        active: true,
    };
    CatalogFixture {
        tenants: vec![TenantRecord {
            tenant_id: tenant_id(),
            display_name: "rotation-refusal tenant".to_owned(),
            active: true,
        }],
        users: vec![UserRecord {
            user_id: user_id(),
            display_name: "rotation-refusal consumer".to_owned(),
        }],
        identities: vec![PrincipalIdentity {
            issuer: ISSUER.to_owned(),
            subject: SUBJECT.to_owned(),
            user_id: user_id(),
        }],
        memberships: vec![MembershipRecord {
            tenant_id: tenant_id(),
            user_id: user_id(),
            role: MembershipRole::Member,
            active: true,
        }],
        devices: vec![FixtureDevice {
            tenant_id: tenant_id(),
            device_id: device_id(),
            owner_user_id: user_id(),
            display_name: "rotation-refusal device".to_owned(),
            active: true,
            last_seen_at: Some(now),
        }],
        credentials: vec![CredentialRecord {
            tenant_id: tenant_id(),
            device_id: device_id(),
            credential_id: Uuid::from_u128(0x3700_0000_0000_0000_0000_0000_0000_0007),
            spki_fingerprint: DEVICE_SPKI.to_owned(),
            serial: Some("rotation-refusal-device".to_owned()),
            not_before: now - ChronoDuration::seconds(1),
            expires_at: now + ChronoDuration::minutes(5),
            revoked_at: None,
            active: true,
        }],
        services: vec![
            service(
                echo_service(),
                "echo",
                serde_json::json!({"operations": ["echo:invoke"]}),
            ),
            service(
                http_service(),
                crate::HTTP_FORWARD_SERVICE_TYPE,
                serde_json::json!({crate::HTTP_FORWARD_PROFILE_CAPABILITY: PROFILE}),
            ),
            service(
                fs_service(),
                crate::FS_SERVICE_TYPE,
                serde_json::json!({crate::FS_CASE_SENSITIVITY_CAPABILITY: "sensitive"}),
            ),
        ],
        grants: vec![
            grant(echo_service(), &[crate::ECHO_OPERATION]),
            grant(http_service(), &[crate::HTTP_FORWARD_OPERATION]),
            grant(
                fs_service(),
                &[crate::FS_SESSION_OPERATION, crate::FS_READ_OPERATION],
            ),
        ],
    }
}

fn drain_control(rx: &mut mpsc::Receiver<ControlOutbound>) -> Vec<ControlMessage> {
    let mut messages = Vec::new();
    while let Ok(item) = rx.try_recv() {
        if let ControlOutbound::Text(text) = item {
            let (text, mut charge) = text.into_parts();
            charge.release();
            messages.push(wire::parse_control(text.as_bytes()).expect("control message decodes"));
        }
    }
    messages
}

/// A relay with one M2 device session behind a fake connector and the real
/// consumer router on a loopback listener.
struct Stage {
    handle: RelayHandle,
    key: SessionKey,
    control_rx: mpsc::Receiver<ControlOutbound>,
    // Held so the data carrier stays live.
    _data_rx: mpsc::Receiver<crate::actor::DataOutbound>,
    address: std::net::SocketAddr,
    token: String,
}

impl Stage {
    async fn start(label: &str) -> Self {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("OIDC signing key");
        let approved =
            ApprovedJwk::from_ed25519_der(KID, key_pair.public_key_raw()).expect("approved key");
        let config =
            OidcConfig::new(ISSUER, [AUDIENCE.to_owned()], vec![approved]).expect("OIDC config");
        let oidc = Arc::new(OidcVerifier::new(config).expect("OIDC verifier"));
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(KID.to_owned());
        let scope = format!(
            "{} {} {}",
            crate::ECHO_OPERATION,
            crate::HTTP_FORWARD_OPERATION,
            crate::FS_SESSION_OPERATION
        );
        let token = encode(
            &header,
            &Claims {
                iss: ISSUER,
                sub: SUBJECT,
                aud: AUDIENCE,
                exp: Utc::now().timestamp() + 120,
                scope: &scope,
            },
            &EncodingKey::from_ed_der(key_pair.serialized_der()),
        )
        .expect("OIDC token");

        let catalog = Arc::new(MemoryCatalog::new());
        catalog
            .seed_fixture(&catalog_fixture())
            .await
            .expect("seed catalog");
        let mut options = RelayOptions::new(oidc.clone());
        options.node_id = format!("{label}-node");
        options.boot_id = format!("{label}-boot");
        let limits = options.limits.clone();
        let handle = RelayHandle::spawn(options, catalog.clone());

        let device = catalog
            .resolve_device(DEVICE_SPKI, Utc::now())
            .await
            .expect("resolve device")
            .expect("device identity");
        let mut hello = Hello::new(format!("{label}-hello"), device_id().to_string(), 1, 0);
        hello.features = vec![
            wire::M1_PROFILE_FEATURE.to_owned(),
            wire::ORDERED_ROTATION_FEATURE.to_owned(),
            "echo".to_owned(),
        ];
        let registration = handle
            .register_forwarded_control(device, DEVICE_SPKI.to_owned(), hello)
            .await
            .expect("admit M2 control session");
        let key = registration.key.clone();
        let mut control_rx = registration.rx;
        let ticket = match wire::parse_control(registration.welcome.as_bytes()).expect("WELCOME") {
            ControlMessage::Welcome(welcome) => welcome.attachment_ticket,
            other => panic!("unexpected registration response: {other:?}"),
        };
        let data_device = catalog
            .resolve_device(DEVICE_SPKI, Utc::now())
            .await
            .expect("resolve data device")
            .expect("data device identity");
        let data = handle
            .attach_forwarded_data(data_device, DEVICE_SPKI.to_owned(), ticket)
            .await
            .expect("attach data carrier");
        let _ = drain_control(&mut control_rx);

        let profile = tunnel_mcp::McpProfile::V2026_07_28
            .policies(tunnel_mcp::McpLimits::default())
            .expect("MCP profile");
        let exports = crate::http::forward::HttpForwardExports::new()
            .with_profile(
                PROFILE,
                crate::http::forward::HttpForwardExport::new(
                    Arc::new(profile),
                    tunnel_http_bridge::BridgeConfig::default(),
                ),
            )
            .expect("export");
        let router = consumer_router_with_peer_and_barriers(
            handle.clone(),
            catalog,
            oidc,
            limits,
            None,
            None,
            None,
            Some(exports),
            crate::health::ReadinessChecks::default(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        tokio::spawn(async move {
            axum::serve(listener, router.into_make_service())
                .await
                .expect("consumer router");
        });
        Self {
            handle,
            key,
            control_rx,
            _data_rx: data.rx,
            address,
            token,
        }
    }

    /// Wait for the consumer's OPEN, freeze the session with that OPEN in the
    /// roster, and have the connector refuse it `GOAWAY`.
    async fn refuse_open_during_freeze(&mut self) {
        self.refuse_open(tunnel_protocol::open_refusal::CONNECTOR_DRAINING, true)
            .await;
    }

    /// Wait for the consumer's OPEN and have the connector refuse that exact
    /// OPEN with `refusal`; with `freeze`, the session is first frozen with the
    /// OPEN in the roster (task rows M6-C210 and M6-C215).
    async fn refuse_open(
        &mut self,
        refusal: tunnel_protocol::open_refusal::OpenRefusal,
        freeze: bool,
    ) {
        let open = timeout(BUDGET, async {
            loop {
                if let Some(open) = drain_control(&mut self.control_rx).into_iter().find_map(
                    |message| match message {
                        ControlMessage::Open(open) => Some(open),
                        _ => None,
                    },
                ) {
                    return open;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the consumer's OPEN is queued");
        if freeze {
            self.handle
                .enter_rotation_freeze_for_test(self.key.clone())
                .await;
            let quiesced = drain_control(&mut self.control_rx);
            assert!(
                quiesced.iter().any(|message| matches!(
                    message,
                    ControlMessage::RotateQuiesce(quiesce)
                        if quiesce.roster.stream_ids.contains(&open.stream_id)
                )),
                "the OPEN is in the frozen roster"
            );
        }
        let goaway = refusal;
        self.handle
            .inbound_control(
                self.key.clone(),
                ControlMessage::Rejected(Rejected::new(
                    "route-test-refusal",
                    open.message_id.clone(),
                    self.key.session_id.clone(),
                    self.key.epoch,
                    open.stream_id,
                    open.operation_id.clone(),
                    goaway.code(),
                    goaway.reason(),
                )),
            )
            .await
            .expect("the connector's REJECTED is delivered");
    }

    fn path(&self, service: Uuid, tail: &str) -> String {
        format!("/v1/devices/{}/services/{service}/{tail}", device_id())
    }

    /// Open a consumer WebSocket on `tail` with `subprotocol`.
    async fn websocket(
        &self,
        service: Uuid,
        tail: &str,
        subprotocol: &str,
    ) -> tokio_tungstenite::WebSocketStream<TcpStream> {
        let mut request = format!("ws://{}{}", self.address, self.path(service, tail))
            .into_client_request()
            .expect("client request");
        let headers = request.headers_mut();
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {}", self.token)).expect("header"),
        );
        headers.insert(
            "Sec-WebSocket-Protocol",
            HeaderValue::from_str(subprotocol).expect("header"),
        );
        let socket = TcpStream::connect(self.address).await.expect("connect");
        let (stream, response) = timeout(BUDGET, tokio_tungstenite::client_async(request, socket))
            .await
            .expect("upgrade in time")
            .expect("upgrade accepted");
        assert_eq!(response.status(), 101);
        stream
    }
}

/// The close frame a consumer WebSocket ends with.
async fn close_of(
    mut stream: tokio_tungstenite::WebSocketStream<TcpStream>,
) -> Option<(u16, String)> {
    timeout(BUDGET, async {
        while let Some(message) = stream.next().await {
            match message {
                Ok(WsMessage::Close(frame)) => {
                    return frame.map(|frame| (u16::from(frame.code), frame.reason.to_string()));
                }
                Ok(_) => {}
                Err(error) => panic!("socket failed before its close: {error}"),
            }
        }
        panic!("socket ended without a close frame")
    })
    .await
    .expect("closed in time")
}

/// M6-C210: the echo stream route closes the consumer 1013 `ROTATION_FREEZE`.
#[tokio::test]
async fn m6c210_route_echo_stream_refused_during_a_freeze_closes_1013() {
    let mut stage = Stage::start("m6c210-route-echo").await;
    let socket = stage
        .websocket(echo_service(), "stream", ECHO_STREAM_SUBPROTOCOL)
        .await;
    stage.refuse_open_during_freeze().await;
    assert_eq!(
        close_of(socket).await,
        Some((1013, "ROTATION_FREEZE".to_owned()))
    );
}

/// M6-C210: the filesystem route closes the consumer 1013 `ROTATION_FREEZE`,
/// which the contract maps to the retryable `RESOURCE_EXHAUSTED`.
#[tokio::test]
async fn m6c210_route_fs_session_refused_during_a_freeze_closes_1013() {
    let mut stage = Stage::start("m6c210-route-fs").await;
    let socket = stage
        .websocket(fs_service(), "fs", tunnel_fs_core::TRANSPORT_SUBPROTOCOL)
        .await;
    stage.refuse_open_during_freeze().await;
    assert_eq!(
        close_of(socket).await,
        Some((1013, "ROTATION_FREEZE".to_owned()))
    );
}

/// M6-C210: the `http-forward/1` route answers `503 ROTATION_FREEZE`,
/// `not_dispatched`, retryable, with `Retry-After`.
#[tokio::test]
async fn m6c210_route_http_forward_refused_during_a_freeze_is_503_rotation_freeze() {
    let mut stage = Stage::start("m6c210-route-http").await;
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\
         Authorization: Bearer {}\r\nContent-Type: application/json\r\n\
         Accept: application/json, text/event-stream\r\n\
         MCP-Protocol-Version: 2026-07-28\r\nContent-Length: {}\r\n\r\n{body}",
        stage.path(http_service(), "http/mcp"),
        stage.token,
        body.len(),
    );
    let mut socket = TcpStream::connect(stage.address).await.expect("connect");
    socket
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    stage.refuse_open_during_freeze().await;
    let mut response = Vec::new();
    timeout(BUDGET, socket.read_to_end(&mut response))
        .await
        .expect("answered in time")
        .expect("read response");
    let response = String::from_utf8(response).expect("UTF-8 response");
    let (head, body) = response.split_once("\r\n\r\n").expect("head and body");
    assert!(head.starts_with("HTTP/1.1 503"), "{head}");
    assert!(
        head.lines()
            .any(|line| line.eq_ignore_ascii_case("retry-after: 1")),
        "{head}"
    );
    let body: serde_json::Value = serde_json::from_str(body).expect("JSON body");
    assert_eq!(body["code"], "ROTATION_FREEZE");
    assert_eq!(body["execution"], "not_dispatched");
    assert_eq!(body["retryable"], true);
    assert_eq!(body["retry_after_ms"], 250);
}

// Task row M6-C215: a stream OPEN the connector refuses outside a rotation
// freeze gets an explicit, `not_dispatched` answer on the wire.  Before
// M6-C215 `http-forward/1` answered `502 HTTP_STREAM_INTERRUPTED`/`unknown`
// and an echo stream or filesystem session closed with no code.

/// A refusal the actor answers `DEVICE_REJECTED` (the connector's export
/// allowlist) and one it answers `RESOURCE_EXHAUSTED` (its stream limit).
fn device_rejected() -> tunnel_protocol::open_refusal::OpenRefusal {
    tunnel_protocol::open_refusal::EXPORT_NOT_ALLOWLISTED
}
fn capacity() -> tunnel_protocol::open_refusal::OpenRefusal {
    tunnel_protocol::open_refusal::STREAM_LIMIT
}

/// Send one `http-forward/1` request, have the connector refuse its OPEN with
/// `refusal` outside a freeze, and return the response head and JSON body.
async fn http_forward_refused(
    label: &str,
    refusal: tunnel_protocol::open_refusal::OpenRefusal,
) -> (String, serde_json::Value) {
    let mut stage = Stage::start(label).await;
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\
         Authorization: Bearer {}\r\nContent-Type: application/json\r\n\
         Accept: application/json, text/event-stream\r\n\
         MCP-Protocol-Version: 2026-07-28\r\nContent-Length: {}\r\n\r\n{body}",
        stage.path(http_service(), "http/mcp"),
        stage.token,
        body.len(),
    );
    let mut socket = TcpStream::connect(stage.address).await.expect("connect");
    socket
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    stage.refuse_open(refusal, false).await;
    let mut response = Vec::new();
    timeout(BUDGET, socket.read_to_end(&mut response))
        .await
        .expect("answered in time")
        .expect("read response");
    let response = String::from_utf8(response).expect("UTF-8 response");
    let (head, body) = response.split_once("\r\n\r\n").expect("head and body");
    (
        head.to_owned(),
        serde_json::from_str(body).expect("JSON body"),
    )
}

/// M6-C215: `http-forward/1` refused by the device (not a freeze) answers
/// `503 DEVICE_REJECTED`/`not_dispatched`, the unary echo's answer for the
/// same refusal, with no retry hint.
#[tokio::test]
async fn m6c215_route_http_forward_refused_by_the_device_is_503_device_rejected() {
    let (head, body) = http_forward_refused("m6c215-route-http-rejected", device_rejected()).await;
    assert!(head.starts_with("HTTP/1.1 503"), "{head}");
    assert!(
        !head
            .lines()
            .any(|line| line.to_ascii_lowercase().starts_with("retry-after")),
        "{head}"
    );
    assert_eq!(body["code"], "DEVICE_REJECTED");
    assert_eq!(body["execution"], "not_dispatched");
    assert!(body.get("retry_after_ms").is_none(), "{body}");
}

/// M6-C215: `http-forward/1` refused for the connector's capacity answers the
/// retryable `503 RESOURCE_EXHAUSTED`/`not_dispatched` with its retry hint.
#[tokio::test]
async fn m6c215_route_http_forward_refused_for_capacity_is_retryable_resource_exhausted() {
    let (head, body) = http_forward_refused("m6c215-route-http-capacity", capacity()).await;
    assert!(head.starts_with("HTTP/1.1 503"), "{head}");
    assert!(
        head.lines()
            .any(|line| line.eq_ignore_ascii_case("retry-after: 1")),
        "{head}"
    );
    assert_eq!(body["code"], "RESOURCE_EXHAUSTED");
    assert_eq!(body["execution"], "not_dispatched");
    assert_eq!(body["retryable"], true);
    assert_eq!(body["retry_after_ms"], 250);
}

/// M6-C215: an echo stream refused outside a freeze closes with a code:
/// 1011 `DEVICE_REJECTED` for a device refusal, 1013 `RESOURCE_EXHAUSTED`
/// (Try Again Later) for capacity.
#[tokio::test]
async fn m6c215_route_echo_stream_refused_outside_a_freeze_closes_with_its_code() {
    for (label, refusal, expected) in [
        (
            "m6c215-route-echo-rejected",
            device_rejected(),
            (1011, "DEVICE_REJECTED"),
        ),
        (
            "m6c215-route-echo-capacity",
            capacity(),
            (1013, "RESOURCE_EXHAUSTED"),
        ),
    ] {
        let mut stage = Stage::start(label).await;
        let socket = stage
            .websocket(echo_service(), "stream", ECHO_STREAM_SUBPROTOCOL)
            .await;
        stage.refuse_open(refusal, false).await;
        assert_eq!(
            close_of(socket).await,
            Some((expected.0, expected.1.to_owned())),
            "{label}"
        );
    }
}

/// M6-C215: a filesystem session refused outside a freeze closes with a code
/// from the filesystem contract: 1011 `DEVICE_REJECTED` (the client reads
/// `SESSION_LOST`) for a device refusal, 1013 `RESOURCE_EXHAUSTED` for
/// capacity.
#[tokio::test]
async fn m6c215_route_fs_session_refused_outside_a_freeze_closes_with_its_code() {
    for (label, refusal, expected) in [
        (
            "m6c215-route-fs-rejected",
            device_rejected(),
            (1011, "DEVICE_REJECTED"),
        ),
        (
            "m6c215-route-fs-capacity",
            capacity(),
            (1013, "RESOURCE_EXHAUSTED"),
        ),
    ] {
        let mut stage = Stage::start(label).await;
        let socket = stage
            .websocket(fs_service(), "fs", tunnel_fs_core::TRANSPORT_SUBPROTOCOL)
            .await;
        stage.refuse_open(refusal, false).await;
        assert_eq!(
            close_of(socket).await,
            Some((expected.0, expected.1.to_owned())),
            "{label}"
        );
    }
}
