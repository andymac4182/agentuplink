//! Task row M6-C213, route level: a consumer stream that reaches the owner
//! through a peer hop from another cluster relay, whose OPEN the owner's
//! connector refuses, gets the same explicit answer on the ingress's wire as
//! the owner's local consumer gets (M6-C210, M6-C215).
//!
//! Two real relays in one process: the owner is the H3 fixture's relay
//! behind the production peer handler (with an `http-forward/1` export) and
//! a fake connector; the ingress is a second relay whose real consumer router
//! resolves the device's owner through the fixture's `PeerRuntime` and
//! forwards over authenticated HTTP/3.  The connector stand-in refuses the
//! exact OPEN the owner queued, optionally inside a rotation freeze entered
//! through the owner actor's own quiesce transition (the M6-C210 test hook).

use super::*;

use crate::{
    actor::SessionKey,
    http::{ECHO_STREAM_SUBPROTOCOL, consumer_router_with_peer_and_barriers},
};
use futures_util::StreamExt as _;
use std::sync::Mutex;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_tungstenite::tungstenite::{
    Message as WsMessage, client::IntoClientRequest, http::HeaderValue,
};
use tunnel_protocol::{Rejected, open_refusal::OpenRefusal};

const PROFILE: &str = "mcp-2026-07-28";
const BUDGET: Duration = Duration::from_secs(10);

fn http_service_id() -> Uuid {
    Uuid::from_u128(0x4400_0000_0000_0000_0000_0000_0000_00c1)
}

fn exports() -> crate::http::forward::HttpForwardExports {
    let profile = tunnel_mcp::McpProfile::V2026_07_28
        .policies(tunnel_mcp::McpLimits::default())
        .expect("MCP profile");
    crate::http::forward::HttpForwardExports::new()
        .with_profile(
            PROFILE,
            crate::http::forward::HttpForwardExport::new(
                Arc::new(profile),
                tunnel_http_bridge::BridgeConfig::default(),
            ),
        )
        .expect("export")
}

/// The owner relay (the fixture) with one M2 device session, and an ingress
/// relay's consumer router on a loopback listener.
struct TwoRelays {
    fixture: H3PeerFixture,
    ingress: RelayHandle,
    key: SessionKey,
    control_rx: mpsc::Receiver<ControlOutbound>,
    _data_rx: mpsc::Receiver<DataOutbound>,
    address: SocketAddr,
    token: String,
}

impl TwoRelays {
    async fn start(label: &str) -> Self {
        let oidc_slot: Arc<Mutex<Option<Arc<OidcVerifier>>>> = Arc::default();
        let slot = Arc::clone(&oidc_slot);
        let fixture = H3PeerFixture::new_with_limits(
            test_limits(),
            move |runtime, handle, catalog, oidc, _device, returned_errors| {
                *slot.lock().expect("OIDC slot") = Some(Arc::clone(&oidc));
                let production_handler =
                    super::super::super::peer_ingress_handler_with_http_forward(
                        handle,
                        catalog,
                        oidc,
                        DESTINATION_NODE.to_owned(),
                        DESTINATION_BOOT.to_owned(),
                        Some(exports()),
                    );
                runtime.server_handler(RecordingHandler {
                    inner: production_handler,
                    returned_errors,
                })
            },
        )
        .await;
        let oidc = oidc_slot
            .lock()
            .expect("OIDC slot")
            .clone()
            .expect("the handler factory ran");
        let now = Utc::now();
        // Only the new service and its grant (and the membership below):
        // re-seeding the device would bump its version.
        let mut http = super::super::catalog_fixture(now);
        http.tenants.clear();
        http.users.clear();
        http.identities.clear();
        // The consumer's sibling-tenant membership is deactivated, so the
        // public route resolves its single tenant without a selection.
        http.memberships = vec![CatalogMembershipRecord {
            tenant_id: sibling_tenant_id(),
            user_id: user_id(),
            role: tunnel_catalog::MembershipRole::Member,
            active: false,
        }];
        http.devices.clear();
        http.credentials.clear();
        http.services = vec![ServiceSpec {
            tenant_id: tenant_id(),
            device_id: device_id(),
            service_id: http_service_id(),
            service_type: crate::HTTP_FORWARD_SERVICE_TYPE.to_owned(),
            display_name: "peer refusal http-forward".to_owned(),
            capabilities: serde_json::json!({crate::HTTP_FORWARD_PROFILE_CAPABILITY: PROFILE}),
            version: 1,
            active: true,
        }];
        http.grants = vec![GrantSpec {
            tenant_id: tenant_id(),
            principal_id: user_id(),
            device_id: device_id(),
            service_id: http_service_id(),
            permissions: PermissionSet {
                operations: BTreeSet::from([crate::HTTP_FORWARD_OPERATION.to_owned()]),
            },
            constraints: serde_json::json!({}),
            expires_at: Some(now + ChronoDuration::minutes(5)),
            active: true,
        }];
        fixture
            .catalog
            .seed_fixture(&http)
            .await
            .expect("seed the http-forward service");

        // The owner's device session, admitted on the fixture's relay.
        let identity = fixture
            .catalog
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
        let registration = fixture
            .handle
            .register_forwarded_control(identity, DEVICE_SPKI.to_owned(), hello)
            .await
            .expect("admit M2 control session");
        let key = registration.key.clone();
        let mut control_rx = registration.rx;
        let ticket = match wire::parse_control(registration.welcome.as_bytes()).expect("WELCOME") {
            ControlMessage::Welcome(welcome) => welcome.attachment_ticket,
            other => panic!("unexpected registration response: {other:?}"),
        };
        // Resolved again: the control admission advanced the owner epoch.
        let data_identity = fixture
            .catalog
            .resolve_device(DEVICE_SPKI, Utc::now())
            .await
            .expect("resolve data device")
            .expect("data device identity");
        let data = fixture
            .handle
            .attach_forwarded_data(data_identity, DEVICE_SPKI.to_owned(), ticket)
            .await
            .expect("attach data carrier");
        let mut data_rx = data.rx;
        drain_queues(&mut control_rx, &mut data_rx).await;

        // The ingress relay: its own actor, the shared catalog, and the
        // fixture's runtime as its peer path to the owner.
        let mut options = RelayOptions::new(Arc::clone(&oidc));
        options.node_id = SOURCE_NODE.to_owned();
        options.boot_id = SOURCE_BOOT.to_owned();
        options.deployment_incarnation = DEPLOYMENT_INCARNATION.to_owned();
        let limits = options.limits.clone();
        let ingress = RelayHandle::spawn(options, fixture.catalog.clone());
        let router = consumer_router_with_peer_and_barriers(
            ingress.clone(),
            fixture.catalog.clone(),
            oidc,
            limits,
            Some(Arc::clone(&fixture.runtime)),
            None,
            None,
            Some(exports()),
            crate::health::ReadinessChecks::default(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        tokio::spawn(async move {
            axum::serve(listener, router.into_make_service())
                .await
                .expect("ingress consumer router");
        });
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("cleanup".to_owned());
        let token = encode(
            &header,
            &Claims {
                iss: ISSUER.to_owned(),
                sub: SUBJECT.to_owned(),
                aud: AUDIENCE.to_owned(),
                exp: usize::try_from(Utc::now().timestamp() + 120).expect("exp"),
                scope: format!(
                    "{} {}",
                    crate::ECHO_OPERATION,
                    crate::HTTP_FORWARD_OPERATION
                ),
            },
            &fixture.consumer_signer,
        )
        .expect("OIDC token");
        Self {
            fixture,
            ingress,
            key,
            control_rx,
            _data_rx: data_rx,
            address,
            token,
        }
    }

    /// Wait for the OPEN the owner queued for the forwarded stream and have
    /// the connector refuse that exact OPEN with `refusal`; with `freeze`, the
    /// owner's session is first frozen with the OPEN in the roster.
    async fn refuse_open(&mut self, refusal: OpenRefusal, freeze: bool) {
        let open = timeout(BUDGET, async {
            loop {
                match self.control_rx.recv().await.expect("control stays live") {
                    ControlOutbound::Text(text) => {
                        let (text, mut charge) = text.into_parts();
                        charge.release();
                        if let ControlMessage::Open(open) =
                            wire::parse_control(text.as_bytes()).expect("control message")
                        {
                            return open;
                        }
                    }
                    ControlOutbound::Close => {}
                }
            }
        })
        .await
        .expect("the forwarded stream's OPEN is queued at the owner");
        if freeze {
            self.fixture
                .handle
                .enter_rotation_freeze_for_test(self.key.clone())
                .await;
        }
        self.fixture
            .handle
            .inbound_control(
                self.key.clone(),
                ControlMessage::Rejected(Rejected::new(
                    "peer-route-test-refusal",
                    open.message_id.clone(),
                    self.key.session_id.clone(),
                    self.key.epoch,
                    open.stream_id,
                    open.operation_id.clone(),
                    refusal.code(),
                    refusal.reason(),
                )),
            )
            .await
            .expect("the connector's REJECTED is delivered");
    }

    /// Open a consumer echo stream on the ingress.
    async fn echo_stream(&self) -> tokio_tungstenite::WebSocketStream<TcpStream> {
        let mut request = format!(
            "ws://{}/v1/devices/{}/services/{}/stream",
            self.address,
            device_id(),
            service_id()
        )
        .into_client_request()
        .expect("client request");
        let headers = request.headers_mut();
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {}", self.token)).expect("header"),
        );
        headers.insert(
            "Sec-WebSocket-Protocol",
            HeaderValue::from_str(ECHO_STREAM_SUBPROTOCOL).expect("header"),
        );
        let socket = TcpStream::connect(self.address).await.expect("connect");
        let (stream, response) = timeout(BUDGET, tokio_tungstenite::client_async(request, socket))
            .await
            .expect("upgrade in time")
            .expect("upgrade accepted");
        assert_eq!(response.status(), 101);
        stream
    }

    /// Send one `http-forward/1` request to the ingress, have the owner's
    /// connector refuse its OPEN, and return the response head and body.
    async fn http_forward_refused(
        &mut self,
        refusal: OpenRefusal,
        freeze: bool,
    ) -> (String, serde_json::Value) {
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
        let request = format!(
            "POST /v1/devices/{}/services/{}/http/mcp HTTP/1.1\r\nHost: 127.0.0.1\r\n\
             Connection: close\r\nAuthorization: Bearer {}\r\n\
             Content-Type: application/json\r\nAccept: application/json, text/event-stream\r\n\
             MCP-Protocol-Version: 2026-07-28\r\nContent-Length: {}\r\n\r\n{body}",
            device_id(),
            http_service_id(),
            self.token,
            body.len(),
        );
        let mut socket = TcpStream::connect(self.address).await.expect("connect");
        socket
            .write_all(request.as_bytes())
            .await
            .expect("write request");
        self.refuse_open(refusal, freeze).await;
        let mut response = Vec::new();
        timeout(BUDGET, socket.read_to_end(&mut response))
            .await
            .expect("answered in time")
            .expect("read response");
        let response = String::from_utf8(response).expect("UTF-8 response");
        let (head, body) = response.split_once("\r\n\r\n").expect("head and body");
        (
            head.to_owned(),
            serde_json::from_str(body).unwrap_or_else(|_| panic!("JSON body: {body}")),
        )
    }

    async fn shutdown(self) {
        self.ingress.shutdown().await.expect("ingress shutdown");
        self.fixture.shutdown().await;
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

/// M6-C213: a forwarded echo stream whose OPEN the owner's connector refuses
/// closes the ingress's consumer with the owner's coded close: 1013
/// `ROTATION_FREEZE` for `GOAWAY` inside a freeze, 1011 `DEVICE_REJECTED`
/// and 1013 `RESOURCE_EXHAUSTED` outside one.
#[tokio::test]
async fn m6c213_route_forwarded_echo_stream_refused_closes_with_the_owners_code() {
    use tunnel_protocol::open_refusal::{CONNECTOR_DRAINING, EXPORT_NOT_ALLOWLISTED, STREAM_LIMIT};
    for (label, refusal, freeze, expected) in [
        (
            "m6c213-echo-freeze",
            CONNECTOR_DRAINING,
            true,
            (1013, "ROTATION_FREEZE"),
        ),
        (
            "m6c213-echo-rejected",
            EXPORT_NOT_ALLOWLISTED,
            false,
            (1011, "DEVICE_REJECTED"),
        ),
        (
            "m6c213-echo-capacity",
            STREAM_LIMIT,
            false,
            (1013, "RESOURCE_EXHAUSTED"),
        ),
    ] {
        let mut relays = TwoRelays::start(label).await;
        let socket = relays.echo_stream().await;
        relays.refuse_open(refusal, freeze).await;
        assert_eq!(
            close_of(socket).await,
            Some((expected.0, expected.1.to_owned())),
            "{label}"
        );
        relays.shutdown().await;
    }
}

/// M6-C213: a forwarded `http-forward/1` request whose OPEN the owner's
/// connector refuses `GOAWAY` inside a freeze answers the ingress's consumer
/// the retryable `503 ROTATION_FREEZE`/`not_dispatched`, as the owner's local
/// consumer is answered.
#[tokio::test]
async fn m6c213_route_forwarded_http_forward_refused_during_a_freeze_is_503_rotation_freeze() {
    let mut relays = TwoRelays::start("m6c213-http-freeze").await;
    let (head, body) = relays
        .http_forward_refused(tunnel_protocol::open_refusal::CONNECTOR_DRAINING, true)
        .await;
    assert!(head.starts_with("HTTP/1.1 503"), "{head}\n{body}");
    assert!(
        head.lines()
            .any(|line| line.eq_ignore_ascii_case("retry-after: 1")),
        "{head}"
    );
    assert_eq!(body["code"], "ROTATION_FREEZE");
    assert_eq!(body["execution"], "not_dispatched");
    assert_eq!(body["retryable"], true);
    assert_eq!(body["retry_after_ms"], 250);
    relays.shutdown().await;
}

/// M6-C213 with M6-C215: refusals outside a freeze cross the hop too:
/// `503 DEVICE_REJECTED` and the retryable `503 RESOURCE_EXHAUSTED`, both
/// `not_dispatched`.
#[tokio::test]
async fn m6c213_route_forwarded_http_forward_refused_outside_a_freeze_keeps_its_code() {
    use tunnel_protocol::open_refusal::{EXPORT_NOT_ALLOWLISTED, STREAM_LIMIT};
    for (label, refusal, code, retry_after) in [
        (
            "m6c213-http-rejected",
            EXPORT_NOT_ALLOWLISTED,
            "DEVICE_REJECTED",
            false,
        ),
        (
            "m6c213-http-capacity",
            STREAM_LIMIT,
            "RESOURCE_EXHAUSTED",
            true,
        ),
    ] {
        let mut relays = TwoRelays::start(label).await;
        let (head, body) = relays.http_forward_refused(refusal, false).await;
        assert!(head.starts_with("HTTP/1.1 503"), "{label}: {head}\n{body}");
        assert_eq!(
            head.lines()
                .any(|line| line.eq_ignore_ascii_case("retry-after: 1")),
            retry_after,
            "{label}: {head}"
        );
        assert_eq!(body["code"], code, "{label}");
        assert_eq!(body["execution"], "not_dispatched", "{label}");
        relays.shutdown().await;
    }
}
