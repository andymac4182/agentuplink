//! Task rows M7-C181, M7-C182 and M7-C184: a relay whose membership no
//! longer entitles it to serve surrenders the device ownership it holds.
//!
//! Each test drives a real [`MembershipRuntime`] (a signed in-memory
//! checkpoint authority and record source) and a real relay actor over a
//! [`MemoryCatalog`], with the production watcher loop
//! ([`ownership_surrender_loop`]) between them. Reconcile passes are run by
//! hand so the confirmation count is deterministic. The time-based bounds
//! (M7-C182 case (b), M7-C184) are shortened through
//! [`MembershipRuntime::set_surrender_bounds`]; their derived production
//! values are pinned separately.

use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use chrono::{Duration as ChronoDuration, Utc};
use tokio::{sync::RwLock, time::timeout};
use tokio_util::sync::CancellationToken;
use tunnel_catalog::{
    ApprovedJwk, Catalog, CatalogFixture, CredentialRecord, FixtureDevice, MembershipRecord,
    MembershipRole, MemoryCatalog, OidcConfig, OidcVerifier, OwnerClaimRequest,
    SignedMembershipRecord as CatalogMembershipRecord, TenantRecord, UserRecord,
};
use tunnel_cluster::membership::{
    MEMBERSHIP_SCHEMA_VERSION, MembershipCheckpoint, MembershipIssuer,
    MembershipRecord as SignedRecord, PrivateEndpointPolicy, RELAY_PEER_ROLE, RelayKey,
    TrustedPublisherKey,
};
use tunnel_protocol::ControlMessage;
use uuid::Uuid;

use super::{
    Command, ControlOutbound, ControlRegistration, LOCAL_IDENTITY_RETIRED,
    LOCAL_MEMBERSHIP_WITHDRAWN, MEMBERSHIP_UNREADY_PROLONGED, RelayHandle,
};
use crate::{
    RelayOptions,
    clock_offset::{ClockOffsetHealth, Measurement},
    membership_runtime::{
        CheckpointAuthority, CheckpointAuthorityError, CheckpointRequest, CheckpointResponse,
        MembershipFuture, MembershipReadiness, MembershipRecordSource, MembershipRuntime,
        MembershipRuntimeConfig, MembershipSourceError, MembershipUnreadyReason,
        OWN_KEY_SURRENDER_CONFIRMATIONS, OwnershipSurrenderCause, SurrenderBounds,
    },
    ownership_surrender::{ownership_surrender_loop, surrender_if_required},
};

const DEPLOYMENT_ID: &str = "c181-deployment";
const DEPLOYMENT_INCARNATION: &str = "c181-incarnation";
const NODE_ID: &str = "relay-a";
/// Another relay in the same deployment.
const PEER_NODE: &str = "relay-b";
const PUBLISHER_KEY_ID: &str = "c181-publisher";
/// The key this relay serves.
const SERVED_SPKI: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
/// A different key the record may approve instead.
const OTHER_SPKI: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
/// The synthetic device's certificate pin.
const DEVICE_SPKI: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
/// How often the watcher polls in these tests.
const POLL: Duration = Duration::from_millis(20);
/// The bound on surrender once confirmed: several polls plus the fenced
/// release on the cleanup worker. The owner lease is 30 s.
const SURRENDER_BOUND: Duration = Duration::from_secs(2);
/// How long a control waits to prove nothing was surrendered: many polls.
const QUIET_WINDOW: Duration = Duration::from_millis(300);

struct SignedAuthority {
    issuer: Arc<MembershipIssuer>,
    next_version: AtomicU64,
    fail: AtomicBool,
    /// When non-zero, answer with this HTTP status instead of a checkpoint.
    fail_status: AtomicU64,
    /// Sign checkpoints that do not name this node (M7-C182, case (a)).
    omit_node: AtomicBool,
    /// The minimum record version the checkpoint requires of this node.
    minimum_version: AtomicU64,
    /// Other nodes the checkpoint names, with their minimum versions.
    others: std::sync::Mutex<BTreeMap<String, u64>>,
}

impl CheckpointAuthority for SignedAuthority {
    fn fetch_checkpoint<'a>(
        &'a self,
        request: CheckpointRequest,
    ) -> MembershipFuture<'a, Result<CheckpointResponse, CheckpointAuthorityError>> {
        Box::pin(async move {
            if self.fail.load(Ordering::Acquire) {
                return Err(CheckpointAuthorityError::Transport);
            }
            let status = self.fail_status.load(Ordering::Acquire);
            if status != 0 {
                return Err(CheckpointAuthorityError::HttpStatus(
                    u16::try_from(status).expect("synthetic HTTP status"),
                ));
            }
            let now = Utc::now();
            let checkpoint = MembershipCheckpoint {
                schema_version: MEMBERSHIP_SCHEMA_VERSION,
                deployment_id: request.deployment_id,
                deployment_incarnation: request.deployment_incarnation,
                checkpoint_version: self.next_version.fetch_add(1, Ordering::AcqRel),
                nonce: request.nonce,
                minimum_versions: {
                    let mut minimums = self
                        .others
                        .lock()
                        .expect("other nodes mutex poisoned")
                        .clone();
                    if !self.omit_node.load(Ordering::Acquire) {
                        minimums.insert(
                            NODE_ID.to_owned(),
                            self.minimum_version.load(Ordering::Acquire),
                        );
                    }
                    minimums
                },
                issued_at: now - ChronoDuration::seconds(1),
                not_before: now - ChronoDuration::seconds(1),
                expires_at: now + ChronoDuration::seconds(30),
            };
            let bytes = self
                .issuer
                .sign_checkpoint_bytes(checkpoint)
                .map_err(|_| CheckpointAuthorityError::InvalidResponse)?;
            CheckpointResponse::new(bytes)
        })
    }
}

#[derive(Clone)]
struct RecordSource {
    records: Arc<RwLock<Vec<CatalogMembershipRecord>>>,
    fail: Arc<AtomicBool>,
}

impl MembershipRecordSource for RecordSource {
    fn read_signed_memberships<'a>(
        &'a self,
    ) -> MembershipFuture<'a, Result<Vec<CatalogMembershipRecord>, MembershipSourceError>> {
        Box::pin(async move {
            if self.fail.load(Ordering::Acquire) {
                return Err(MembershipSourceError::Catalog);
            }
            Ok(self.records.read().await.clone())
        })
    }
}

struct Fixture {
    /// Another relay's fresh record, re-published unchanged with this
    /// relay's, once [`Fixture::add_peer`] has run.
    peer_record: std::sync::Mutex<Option<CatalogMembershipRecord>>,
    issuer: Arc<MembershipIssuer>,
    authority: Arc<SignedAuthority>,
    source: RecordSource,
    membership: Arc<MembershipRuntime>,
    catalog: MemoryCatalog,
    relay: RelayHandle,
    cancel: CancellationToken,
    tenant_id: Uuid,
    device_id: Uuid,
}

impl Fixture {
    async fn new() -> Self {
        Self::build(true, Duration::from_secs(1)).await
    }

    /// A fixture whose runtime accepts `max_clock_skew`.
    async fn with_skew(max_clock_skew: Duration) -> Self {
        Self::build(true, max_clock_skew).await
    }

    /// A fixture whose watcher is not running, so a test can drive the
    /// surrender request by hand.
    async fn without_watcher() -> Self {
        Self::build(false, Duration::from_secs(1)).await
    }

    async fn build(watcher: bool, max_clock_skew: Duration) -> Self {
        let (issuer, _private_key) =
            MembershipIssuer::generate(PUBLISHER_KEY_ID).expect("synthetic membership issuer");
        let issuer = Arc::new(issuer);
        let authority = Arc::new(SignedAuthority {
            issuer: Arc::clone(&issuer),
            next_version: AtomicU64::new(1),
            fail: AtomicBool::new(false),
            fail_status: AtomicU64::new(0),
            omit_node: AtomicBool::new(false),
            minimum_version: AtomicU64::new(1),
            others: std::sync::Mutex::new(BTreeMap::new()),
        });
        let source = RecordSource {
            records: Arc::new(RwLock::new(Vec::new())),
            fail: Arc::new(AtomicBool::new(false)),
        };
        let config = MembershipRuntimeConfig::new(
            DEPLOYMENT_ID,
            DEPLOYMENT_INCARNATION,
            NODE_ID,
            "boot-a",
            PrivateEndpointPolicy::private_ip_only(),
            Duration::from_secs(60),
            Duration::from_secs(20),
            Duration::from_secs(1),
            Duration::from_secs(1),
            max_clock_skew,
        )
        .expect("bounded runtime configuration")
        .with_local_spki_sha256(SERVED_SPKI)
        .expect("synthetic served SPKI");
        let trusted = TrustedPublisherKey::new(
            PUBLISHER_KEY_ID,
            issuer.public_key().expect("issuer public key"),
        )
        .expect("trusted publisher key");
        let membership = MembershipRuntime::with_source(
            Arc::new(source.clone()),
            authority.clone(),
            config,
            [trusted],
        )
        .expect("membership runtime");

        let catalog = MemoryCatalog::new();
        let (fixture, tenant_id, device_id) = catalog_fixture();
        catalog
            .seed_fixture(&fixture)
            .await
            .expect("seed the synthetic catalog");
        let jwk = ApprovedJwk::from_ed25519_der("c181", &[0_u8; 32]).expect("test OIDC key");
        let oidc = OidcConfig::new("https://issuer.example", ["audience".to_owned()], vec![jwk])
            .expect("test OIDC config");
        let cancel = CancellationToken::new();
        let mut options = RelayOptions::new(Arc::new(
            OidcVerifier::new(oidc).expect("test OIDC verifier"),
        ));
        options.shutdown = cancel.clone();
        options.owner_lease = Duration::from_secs(30);
        let relay = RelayHandle::spawn(options, Arc::new(catalog.clone()));

        let fixture = Self {
            peer_record: std::sync::Mutex::new(None),
            issuer,
            authority,
            source,
            membership,
            catalog,
            relay,
            cancel,
            tenant_id,
            device_id,
        };
        fixture.publish(1, SERVED_SPKI).await;
        fixture
            .membership
            .bootstrap()
            .await
            .expect("the served key is approved at startup");
        assert_eq!(fixture.membership.readiness(), MembershipReadiness::Ready);
        if watcher {
            tokio::spawn(ownership_surrender_loop(
                Arc::clone(&fixture.membership),
                fixture.relay.clone(),
                POLL,
                fixture.cancel.child_token(),
            ));
        }
        fixture
    }

    /// Publish this relay's signed record approving exactly `spki`.
    async fn publish(&self, version: u64, spki: &str) {
        let now = Utc::now();
        let record = self.signed(
            NODE_ID,
            version,
            spki,
            now - ChronoDuration::seconds(1),
            now + ChronoDuration::seconds(30),
        );
        let mut records = vec![record];
        records.extend(self.peer_record.lock().expect("peer record").clone());
        *self.source.records.write().await = records;
    }

    /// Name another relay in the checkpoint and publish its fresh record
    /// alongside this relay's (republished at `own_version`), so this relay
    /// is not the only node with evidence: a gap then concerns this node
    /// alone, not a shared publisher outage (M7-C186).
    async fn add_peer(&self, own_version: u64) {
        self.authority
            .others
            .lock()
            .expect("other nodes")
            .insert(PEER_NODE.to_owned(), 1);
        let now = Utc::now();
        *self.peer_record.lock().expect("peer record") = Some(self.signed(
            PEER_NODE,
            1,
            OTHER_SPKI,
            now - ChronoDuration::seconds(1),
            now + ChronoDuration::seconds(50),
        ));
        self.publish(own_version, SERVED_SPKI).await;
        self.ready_pass().await;
    }

    /// Replace the catalog's records.
    async fn set_records(&self, records: Vec<CatalogMembershipRecord>) {
        *self.source.records.write().await = records;
    }

    /// A signed record for `node` approving `spki` inside the given window.
    fn signed(
        &self,
        node: &str,
        version: u64,
        spki: &str,
        not_before: chrono::DateTime<Utc>,
        expires_at: chrono::DateTime<Utc>,
    ) -> CatalogMembershipRecord {
        signed_by(&self.issuer, node, version, spki, not_before, expires_at)
    }

    async fn register(&self) -> ControlRegistration {
        let identity = self
            .catalog
            .resolve_device(DEVICE_SPKI, Utc::now())
            .await
            .expect("device lookup")
            .expect("synthetic device identity");
        let mut hello = tunnel_protocol::Hello::new(
            "c181-registration",
            self.device_id.to_string(),
            u16::from(crate::PROTOCOL_MAJOR),
            0,
        );
        hello.features.push("echo".to_owned());
        self.relay
            .register_forwarded_control(identity, DEVICE_SPKI.to_owned(), hello)
            .await
            .expect("the device registers while the relay is ready")
    }

    async fn owned(&self) -> bool {
        self.catalog
            .current_owner(self.tenant_id, self.device_id, Utc::now())
            .await
            .expect("read the device owner")
            .is_some()
    }

    async fn live_sessions(&self) -> usize {
        self.relay
            .snapshot()
            .await
            .expect("relay snapshot")
            .sessions
            .len()
    }

    /// A successor relay claims the device's owner lease.
    async fn successor_claims(&self) -> bool {
        self.catalog
            .claim_owner(&OwnerClaimRequest {
                deployment_incarnation: DEPLOYMENT_INCARNATION.to_owned(),
                tenant_id: self.tenant_id,
                device_id: self.device_id,
                node_id: "relay-successor".to_owned(),
                boot_id: "boot-successor".to_owned(),
                session_id: "successor-session".to_owned(),
                lease_expires_at: Utc::now() + ChronoDuration::seconds(30),
            })
            .await
            .is_ok()
    }

    /// One reconcile pass that concludes `MissingLocalKey`.
    async fn missing_key_pass(&self) {
        let error = self
            .membership
            .reconcile_once()
            .await
            .expect_err("the served key is not approved");
        assert!(matches!(error, crate::MembershipRuntimeError::PeerRejected));
        assert_eq!(
            self.membership.readiness(),
            MembershipReadiness::Unready(MembershipUnreadyReason::MissingLocalKey)
        );
    }

    async fn shutdown(self) {
        self.cancel.cancel();
        let _ = timeout(Duration::from_secs(5), self.relay.shutdown()).await;
    }
}

/// A record for `node` approving `spki` inside the given window, signed by
/// `issuer` (the trusted publisher, or a foreign key under its key id).
fn signed_by(
    issuer: &MembershipIssuer,
    node: &str,
    version: u64,
    spki: &str,
    not_before: chrono::DateTime<Utc>,
    expires_at: chrono::DateTime<Utc>,
) -> CatalogMembershipRecord {
    let host = if node == NODE_ID {
        "10.0.0.1"
    } else {
        "10.0.0.2"
    };
    let record = SignedRecord {
        schema_version: MEMBERSHIP_SCHEMA_VERSION,
        deployment_id: DEPLOYMENT_ID.to_owned(),
        deployment_incarnation: DEPLOYMENT_INCARNATION.to_owned(),
        node_id: node.to_owned(),
        record_version: version,
        roles: vec![RELAY_PEER_ROLE.to_owned()],
        peer_endpoint: format!("{host}:8443"),
        server_name: host.to_owned(),
        keys: vec![RelayKey {
            key_id: format!("key-{version}"),
            spki_sha256: spki.to_owned(),
            not_before,
            expires_at,
            revoked: false,
        }],
        issued_at: not_before,
        not_before,
        expires_at,
    };
    CatalogMembershipRecord {
        version,
        bytes: issuer
            .sign_membership_bytes(record)
            .expect("synthetic signed membership"),
    }
}

fn catalog_fixture() -> (CatalogFixture, Uuid, Uuid) {
    let tenant_id = Uuid::from_u128(0xC181_0001);
    let user_id = Uuid::from_u128(0xC181_0002);
    let device_id = Uuid::from_u128(0xC181_0003);
    let now = Utc::now();
    (
        CatalogFixture {
            tenants: vec![TenantRecord {
                tenant_id,
                display_name: "c181-tenant".to_owned(),
                active: true,
            }],
            users: vec![UserRecord {
                user_id,
                display_name: "C181 User".to_owned(),
            }],
            memberships: vec![MembershipRecord {
                tenant_id,
                user_id,
                role: MembershipRole::Member,
                active: true,
            }],
            devices: vec![FixtureDevice {
                tenant_id,
                device_id,
                owner_user_id: user_id,
                display_name: "C181 Device".to_owned(),
                active: true,
                last_seen_at: Some(now),
            }],
            credentials: vec![CredentialRecord {
                tenant_id,
                device_id,
                credential_id: Uuid::from_u128(0xC181_0004),
                spki_fingerprint: DEVICE_SPKI.to_owned(),
                serial: Some("c181".to_owned()),
                not_before: now - ChronoDuration::seconds(1),
                expires_at: now + ChronoDuration::hours(1),
                revoked_at: None,
                active: true,
            }],
            ..CatalogFixture::default()
        },
        tenant_id,
        device_id,
    )
}

/// Read control messages until the carrier closes; return the session
/// rejection code, if one was queued.
async fn rejection_code(control: &mut ControlRegistration) -> Option<String> {
    let mut code = None;
    while let Ok(Some(outbound)) = timeout(SURRENDER_BOUND, control.rx.recv()).await {
        match outbound {
            ControlOutbound::Text(mut text) => {
                if let Ok(ControlMessage::Rejected(rejected)) =
                    serde_json::from_slice::<ControlMessage>(text.as_bytes())
                {
                    code = Some(rejected.code);
                }
                text.release();
            }
            ControlOutbound::Close => break,
        }
    }
    code
}

async fn wait_until_released(fixture: &Fixture) -> Option<Duration> {
    let started = tokio::time::Instant::now();
    while started.elapsed() < SURRENDER_BOUND {
        if !fixture.owned().await {
            return Some(started.elapsed());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    None
}

/// **Red first.** The relay's own record stops approving the key it serves.
/// One reconcile pass is not enough to surrender; the confirming pass is.
/// The owned session then closes with the typed reason, the owner lease is
/// released within the bound (the lease itself is 30 s), a successor can
/// claim at once, and a re-sign approving the served key lets the relay
/// serve again. Without the surrender the lease stays claimed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_retired_served_key_surrenders_owned_sessions_and_releases_their_leases() {
    let fixture = Fixture::new().await;
    let mut control = fixture.register().await;
    assert!(fixture.owned().await, "the session holds its owner lease");

    // Pass 1: the served key is gone. Unready, but not yet surrendered.
    fixture.publish(2, OTHER_SPKI).await;
    fixture.missing_key_pass().await;
    assert_eq!(fixture.membership.own_key_missing_passes(), 1);
    assert!(!fixture.membership.own_key_surrender_required());
    tokio::time::sleep(QUIET_WINDOW).await;
    assert!(
        fixture.owned().await,
        "a single reconcile pass must never surrender ownership"
    );
    assert_eq!(fixture.live_sessions().await, 1);

    // Pass 2 confirms it.
    fixture.missing_key_pass().await;
    assert_eq!(
        fixture.membership.own_key_missing_passes(),
        OWN_KEY_SURRENDER_CONFIRMATIONS
    );
    assert!(fixture.membership.own_key_surrender_required());
    let released = wait_until_released(&fixture).await;
    assert!(
        released.is_some(),
        "the relay whose served key was retired kept its owner lease past {SURRENDER_BOUND:?}"
    );
    assert_eq!(
        rejection_code(&mut control).await.as_deref(),
        Some(LOCAL_IDENTITY_RETIRED),
        "the owned session closes with the typed reason"
    );
    assert_eq!(fixture.live_sessions().await, 0);
    assert!(
        fixture.successor_claims().await,
        "a successor claims the released lease immediately"
    );

    // A re-sign approving the served key again: Ready, the count resets, and
    // nothing is surrendered any more.
    fixture.publish(3, SERVED_SPKI).await;
    fixture
        .membership
        .reconcile_once()
        .await
        .expect("the served key is approved again");
    assert_eq!(fixture.membership.readiness(), MembershipReadiness::Ready);
    assert_eq!(fixture.membership.own_key_missing_passes(), 0);
    assert!(!fixture.membership.own_key_surrender_required());
    fixture.shutdown().await;
}

/// After a re-sign approves the served key again, the relay may own devices
/// again: a fresh registration is not surrendered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_relay_serves_again_after_its_key_is_re_approved() {
    let fixture = Fixture::new().await;
    let _first = fixture.register().await;
    fixture.publish(2, OTHER_SPKI).await;
    fixture.missing_key_pass().await;
    fixture.missing_key_pass().await;
    assert!(wait_until_released(&fixture).await.is_some());

    fixture.publish(3, SERVED_SPKI).await;
    fixture
        .membership
        .reconcile_once()
        .await
        .expect("the served key is approved again");
    let _second = fixture.register().await;
    tokio::time::sleep(QUIET_WINDOW).await;
    assert!(
        fixture.owned().await,
        "a re-approved relay owns devices again"
    );
    assert_eq!(fixture.live_sessions().await, 1);
    fixture.shutdown().await;
}

/// **Control.** Transient reconcile failures -- the checkpoint authority
/// unreachable, then the record catalog unreadable, each for more passes
/// than the confirmation count -- withdraw readiness but never surrender.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transient_reconcile_failures_never_close_sessions() {
    let fixture = Fixture::new().await;
    let _control = fixture.register().await;
    let passes = OWN_KEY_SURRENDER_CONFIRMATIONS + 2;

    fixture.authority.fail.store(true, Ordering::Release);
    for _ in 0..passes {
        assert!(fixture.membership.reconcile_once().await.is_err());
    }
    assert_eq!(
        fixture.membership.readiness(),
        MembershipReadiness::Unready(MembershipUnreadyReason::UnknownAuthority)
    );
    fixture.authority.fail.store(false, Ordering::Release);

    fixture.source.fail.store(true, Ordering::Release);
    for _ in 0..passes {
        assert!(fixture.membership.reconcile_once().await.is_err());
    }
    assert_eq!(
        fixture.membership.readiness(),
        MembershipReadiness::Unready(MembershipUnreadyReason::CatalogUnavailable)
    );
    assert_eq!(fixture.membership.own_key_missing_passes(), 0);
    assert!(!fixture.membership.own_key_surrender_required());
    tokio::time::sleep(QUIET_WINDOW).await;
    assert!(fixture.owned().await, "a transient failure kept the lease");
    assert_eq!(fixture.live_sessions().await, 1);
    fixture.shutdown().await;
}

/// **Control.** A transient failure between two own-key passes resets the
/// count, so the surrender needs two fresh consecutive confirmations.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_transient_failure_between_own_key_passes_resets_the_confirmation() {
    let fixture = Fixture::new().await;
    let _control = fixture.register().await;
    fixture.publish(2, OTHER_SPKI).await;
    fixture.missing_key_pass().await;

    fixture.source.fail.store(true, Ordering::Release);
    assert!(fixture.membership.reconcile_once().await.is_err());
    fixture.source.fail.store(false, Ordering::Release);
    assert_eq!(fixture.membership.own_key_missing_passes(), 0);

    fixture.missing_key_pass().await;
    assert_eq!(fixture.membership.own_key_missing_passes(), 1);
    tokio::time::sleep(QUIET_WINDOW).await;
    assert!(
        fixture.owned().await,
        "one pass after a reset must not surrender"
    );
    fixture.missing_key_pass().await;
    assert!(wait_until_released(&fixture).await.is_some());
    fixture.shutdown().await;
}

/// **Control, not counted as red-first.** A clock offset beyond the cluster
/// skew bound makes the relay not ready (M7-C175) but is not a membership
/// condition: nothing closes. Clock-offset health feeds only the `/readyz`
/// health path; the watcher reads membership state alone, which clock health
/// never writes. So no mutation of the surrender logic can turn this red --
/// only rewiring the watcher to a different input could -- and it is kept as
/// documentation of that separation, not as evidence (review of #228).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_clock_offset_not_ready_never_closes_sessions() {
    let fixture = Fixture::new().await;
    let _control = fixture.register().await;
    let clock = ClockOffsetHealth::new();
    for _ in 0..4 {
        clock.record(&Measurement::Offset(chrono::TimeDelta::seconds(60)));
    }
    assert!(!clock.is_ready(), "the clock offset is beyond the bound");
    tokio::time::sleep(QUIET_WINDOW).await;
    assert!(!fixture.membership.own_key_surrender_required());
    assert!(
        fixture.owned().await,
        "a clock-offset unready kept the lease"
    );
    assert_eq!(fixture.live_sessions().await, 1);
    fixture.shutdown().await;
}

// ---- M7-C182: a checkpoint that omits this node, or a record below its
// minimum --------------------------------------------------------------------

/// Bounds for the time-based tests: short enough to wait out, and each far
/// from the other so only the rule under test can fire.
const SHORT_BOUND: Duration = Duration::from_millis(400);
const LONG_BOUND: Duration = Duration::from_secs(3_600);

impl Fixture {
    /// One reconcile pass that concludes `MissingLocalMembership`.
    async fn missing_membership_pass(&self) {
        assert!(
            self.membership.reconcile_once().await.is_err(),
            "local membership is missing"
        );
        assert_eq!(
            self.membership.readiness(),
            MembershipReadiness::Unready(MembershipUnreadyReason::MissingLocalMembership)
        );
    }

    /// One reconcile pass that concludes `UnknownAuthority`: the checkpoint
    /// authority fails while the record catalog stays reachable.
    async fn unknown_authority_pass(&self) {
        self.authority.fail.store(true, Ordering::Release);
        assert!(self.membership.reconcile_once().await.is_err());
        self.authority.fail.store(false, Ordering::Release);
        assert_eq!(
            self.membership.readiness(),
            MembershipReadiness::Unready(MembershipUnreadyReason::UnknownAuthority)
        );
    }

    /// One reconcile pass that concludes `MembershipRejected` for a reason
    /// local to the catalog's contents -- a malformed record envelope beside
    /// this relay's fresh record -- so it is counted toward M7-C184.
    async fn rejected_pass(&self) {
        let original = self.source.records.read().await.clone();
        let mut records = original.clone();
        records.push(CatalogMembershipRecord {
            version: 0,
            bytes: b"{}".to_vec(),
        });
        self.set_records(records).await;
        assert!(self.membership.reconcile_once().await.is_err());
        self.set_records(original).await;
        assert_eq!(
            self.membership.readiness(),
            MembershipReadiness::Unready(MembershipUnreadyReason::MembershipRejected)
        );
    }

    /// One reconcile pass whose checkpoint authority answers `status`.
    async fn authority_status_pass(&self, status: u16) {
        self.authority
            .fail_status
            .store(u64::from(status), Ordering::Release);
        assert!(self.membership.reconcile_once().await.is_err());
        self.authority.fail_status.store(0, Ordering::Release);
        assert_eq!(
            self.membership.readiness(),
            MembershipReadiness::Unready(MembershipUnreadyReason::UnknownAuthority)
        );
    }

    /// One reconcile pass that concludes `CatalogUnavailable`.
    async fn catalog_unavailable_pass(&self) {
        self.source.fail.store(true, Ordering::Release);
        assert!(self.membership.reconcile_once().await.is_err());
        self.source.fail.store(false, Ordering::Release);
        assert_eq!(
            self.membership.readiness(),
            MembershipReadiness::Unready(MembershipUnreadyReason::CatalogUnavailable)
        );
    }

    async fn ready_pass(&self) {
        self.membership
            .reconcile_once()
            .await
            .expect("membership is ready");
        assert_eq!(self.membership.readiness(), MembershipReadiness::Ready);
    }

    fn set_bounds(&self, local_record_below_minimum: Duration, prolonged_unready: Duration) {
        self.membership.set_surrender_bounds(SurrenderBounds {
            local_record_below_minimum,
            prolonged_unready,
        });
    }

    /// Wait a quiet window and assert nothing was surrendered.
    async fn assert_kept(&self, why: &str) {
        tokio::time::sleep(QUIET_WINDOW).await;
        assert!(self.owned().await, "{why}: the owner lease was released");
        assert_eq!(self.live_sessions().await, 1, "{why}: the session closed");
    }
}

/// **Red first (M7-C182, case (a)).** A fresh signed checkpoint that no
/// longer names this node is a signed removal. One pass never surrenders;
/// the confirming pass does, with `LOCAL_MEMBERSHIP_WITHDRAWN`, and the
/// lease is released for a successor. Before M7-C182 the relay kept the
/// session and renewed its lease.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_checkpoint_that_omits_this_node_surrenders_after_two_passes() {
    let fixture = Fixture::new().await;
    let mut control = fixture.register().await;
    // The catalog keeps this node's record, as production does (it never
    // deletes a removed node's record): M7-C185 skips it, so the pass
    // concludes the removal rather than failing every relay's pass.
    fixture.authority.omit_node.store(true, Ordering::Release);

    fixture.missing_membership_pass().await;
    assert_eq!(fixture.membership.ownership_surrender_cause(), None);
    fixture
        .assert_kept("a single node-omitted pass must never surrender")
        .await;

    fixture.missing_membership_pass().await;
    assert_eq!(
        fixture.membership.ownership_surrender_cause(),
        Some(OwnershipSurrenderCause::NodeRemoved)
    );
    assert!(
        wait_until_released(&fixture).await.is_some(),
        "a relay its checkpoint omits kept its owner lease past {SURRENDER_BOUND:?}"
    );
    assert_eq!(
        rejection_code(&mut control).await.as_deref(),
        Some(LOCAL_MEMBERSHIP_WITHDRAWN)
    );
    assert!(fixture.successor_claims().await);

    // Named again: Ready, and nothing is surrendered any more.
    fixture.authority.omit_node.store(false, Ordering::Release);
    fixture.publish(3, SERVED_SPKI).await;
    fixture.ready_pass().await;
    assert_eq!(fixture.membership.ownership_surrender_cause(), None);
    fixture.shutdown().await;
}

/// **Control (M7-C182, case (b)).** The checkpoint names this node at a
/// minimum version whose record has not reached Redis yet (the catalog holds
/// only an older one): the publish race. Unready, but two passes -- or several -- never surrender
/// while the production bound (one record lifetime plus skew) has not
/// elapsed. Red if the record-below-minimum case is confirmed by passes like
/// a node omission.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_record_below_the_checkpoint_minimum_does_not_surrender_on_two_passes() {
    let fixture = Fixture::new().await;
    let _control = fixture.register().await;
    // Another relay's record stays fresh, so the gap is this node's alone
    // (M7-C186), and this relay's own v2 record stays in the catalog below
    // the new minimum, absent for this node only (M7-C185).
    fixture.add_peer(2).await;
    fixture
        .authority
        .minimum_version
        .store(5, Ordering::Release);
    for _ in 0..OWN_KEY_SURRENDER_CONFIRMATIONS + 2 {
        fixture.missing_membership_pass().await;
    }
    assert_eq!(fixture.membership.ownership_surrender_cause(), None);
    fixture
        .assert_kept("the publish race surrendered on passes")
        .await;

    // The publisher's record lands: Ready, and the run resets.
    fixture.publish(5, SERVED_SPKI).await;
    fixture.ready_pass().await;
    assert_eq!(fixture.membership.ownership_surrender_cause(), None);
    fixture.shutdown().await;
}

/// **Red first (M7-C182, case (b)).** A record that stays below the
/// checkpoint's minimum for longer than the bound is no longer a race in
/// flight: the relay surrenders with `LOCAL_MEMBERSHIP_WITHDRAWN`. The bound
/// is measured between passes that each observed the gap, so it is reached
/// only on evidence. Before M7-C182 nothing ever closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_record_below_the_minimum_surrenders_once_it_outlasts_the_publish_race_bound() {
    let fixture = Fixture::new().await;
    let mut control = fixture.register().await;
    fixture.set_bounds(SHORT_BOUND, LONG_BOUND);
    // Another relay's record stays fresh, so the gap is this node's alone
    // (M7-C186), and this relay's own v2 record stays in the catalog below
    // the new minimum, absent for this node only (M7-C185).
    fixture.add_peer(2).await;
    fixture
        .authority
        .minimum_version
        .store(5, Ordering::Release);

    fixture.missing_membership_pass().await;
    fixture.missing_membership_pass().await;
    // Wall time alone is not evidence: with no further pass, nothing closes
    // even after the bound has passed since the first observation.
    tokio::time::sleep(SHORT_BOUND).await;
    assert_eq!(fixture.membership.ownership_surrender_cause(), None);
    fixture
        .assert_kept("the bound was reached without a confirming pass")
        .await;

    fixture.missing_membership_pass().await;
    assert_eq!(
        fixture.membership.ownership_surrender_cause(),
        Some(OwnershipSurrenderCause::LocalRecordBelowMinimum)
    );
    assert!(
        wait_until_released(&fixture).await.is_some(),
        "a relay whose record stayed below the minimum kept its lease"
    );
    assert_eq!(
        rejection_code(&mut control).await.as_deref(),
        Some(LOCAL_MEMBERSHIP_WITHDRAWN)
    );
    fixture.shutdown().await;
}

/// **Control (M7-C182).** A pass with any other conclusion restarts the
/// below-minimum run: the bound must be outlasted by one unbroken run.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_different_conclusion_restarts_the_below_minimum_run() {
    let fixture = Fixture::new().await;
    let _control = fixture.register().await;
    fixture.set_bounds(SHORT_BOUND, LONG_BOUND);
    // Another relay's record stays fresh, so the gap is this node's alone
    // (M7-C186), and this relay's own v2 record stays in the catalog below
    // the new minimum, absent for this node only (M7-C185).
    fixture.add_peer(2).await;
    fixture
        .authority
        .minimum_version
        .store(5, Ordering::Release);
    fixture.missing_membership_pass().await;
    tokio::time::sleep(SHORT_BOUND * 3 / 4).await;
    fixture.catalog_unavailable_pass().await;
    fixture.missing_membership_pass().await;
    tokio::time::sleep(SHORT_BOUND * 3 / 4).await;
    fixture.missing_membership_pass().await;
    assert_eq!(fixture.membership.ownership_surrender_cause(), None);
    fixture
        .assert_kept("two broken runs were summed into one")
        .await;
    fixture.shutdown().await;
}

// ---- M7-C184: a bounded surrender for any prolonged unready state ----------

/// **Red first (M7-C184).** The catalog holds a record this relay rejects
/// while Redis is reachable (`MembershipRejected`), so the relay could renew
/// its leases forever. Once the unready time confirmed by passes exceeds the
/// bound it surrenders with `MEMBERSHIP_UNREADY_PROLONGED`; before that it
/// keeps its sessions. Before M7-C184 nothing ever closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_prolonged_unready_relay_with_redis_reachable_surrenders_after_the_bound() {
    let fixture = Fixture::new().await;
    let mut control = fixture.register().await;
    fixture.set_bounds(LONG_BOUND, SHORT_BOUND);

    fixture.rejected_pass().await;
    tokio::time::sleep(SHORT_BOUND * 5 / 8).await;
    fixture.rejected_pass().await;
    assert_eq!(fixture.membership.ownership_surrender_cause(), None);
    fixture.assert_kept("surrendered before the bound").await;

    fixture.rejected_pass().await;
    assert_eq!(
        fixture.membership.ownership_surrender_cause(),
        Some(OwnershipSurrenderCause::ProlongedUnready)
    );
    assert!(
        wait_until_released(&fixture).await.is_some(),
        "a relay unready past the bound kept its owner lease"
    );
    assert_eq!(
        rejection_code(&mut control).await.as_deref(),
        Some(MEMBERSHIP_UNREADY_PROLONGED)
    );
    fixture.shutdown().await;
}

/// **Control (M7-C184).** Time while the catalog is unreachable never counts:
/// the relay cannot renew then, so leases lapse on their own. An
/// all-unreachable run adds nothing, and neither does an interval with an
/// unreachable pass at either end -- including a gap longer than the whole
/// bound from an unreachable pass to the next counted one. Red if
/// `CatalogUnavailable` counts, or if an unreachable pass still marks itself
/// as the last counted pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn catalog_unavailable_time_never_counts_toward_the_prolonged_unready_bound() {
    let fixture = Fixture::new().await;
    let _control = fixture.register().await;
    fixture.set_bounds(LONG_BOUND, SHORT_BOUND);
    for _ in 0..3 {
        fixture.catalog_unavailable_pass().await;
        tokio::time::sleep(SHORT_BOUND / 2).await;
    }
    fixture.catalog_unavailable_pass().await;
    assert_eq!(fixture.membership.ownership_surrender_cause(), None);

    // Counted, then unreachable, then -- more than the whole bound later --
    // counted again. Neither interval has counted passes at both ends.
    fixture.rejected_pass().await;
    fixture.catalog_unavailable_pass().await;
    tokio::time::sleep(SHORT_BOUND * 5 / 4).await;
    fixture.rejected_pass().await;
    assert_eq!(fixture.membership.ownership_surrender_cause(), None);
    fixture
        .assert_kept("unreachable-catalog time counted toward the bound")
        .await;
    fixture.shutdown().await;
}

/// **Red first (M7-C184's guard).** Unready time already accrued past the
/// bound does not surrender while the latest pass is not a counted one: a
/// relay whose catalog is unreachable *now* cannot renew anyway. The next
/// counted pass surrenders. Red if the cause ignores whether the latest pass
/// counted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accrued_unready_time_does_not_surrender_while_the_latest_pass_is_uncounted() {
    let fixture = Fixture::new().await;
    let _control = fixture.register().await;
    fixture.set_bounds(LONG_BOUND, SHORT_BOUND);
    fixture.rejected_pass().await;
    tokio::time::sleep(SHORT_BOUND * 5 / 4).await;
    fixture.rejected_pass().await;
    fixture.catalog_unavailable_pass().await;
    assert_eq!(
        fixture.membership.ownership_surrender_cause(),
        None,
        "surrendered on accrued time while the catalog is unreachable now"
    );
    fixture.rejected_pass().await;
    assert_eq!(
        fixture.membership.ownership_surrender_cause(),
        Some(OwnershipSurrenderCause::ProlongedUnready)
    );
    assert!(wait_until_released(&fixture).await.is_some());
    fixture.shutdown().await;
}

// ---- M7-C186: shared control-plane outages never accrue ------------------

/// **Control (M7-C186).** The checkpoint authority is unreachable for longer
/// than the bound. Every relay is equally unready, so surrendering would only
/// move devices to relays that cannot serve them: nothing closes. Red if an
/// authority error counts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreachable_checkpoint_authority_never_accrues_toward_surrender() {
    let fixture = Fixture::new().await;
    let _control = fixture.register().await;
    fixture.set_bounds(LONG_BOUND, SHORT_BOUND);
    fixture.unknown_authority_pass().await;
    tokio::time::sleep(SHORT_BOUND * 3 / 4).await;
    fixture.unknown_authority_pass().await;
    tokio::time::sleep(SHORT_BOUND * 3 / 4).await;
    fixture.unknown_authority_pass().await;
    assert_eq!(fixture.membership.ownership_surrender_cause(), None);
    fixture
        .assert_kept("an authority outage counted toward the bound")
        .await;
    fixture.shutdown().await;
}

/// **Control (M7-C186).** The shared publisher has stopped: the checkpoint is
/// fresh, but every record it names has passed its signed lifetime, so every
/// relay's pass fails alike (`MembershipRejected`, a record window error).
/// Nothing accrues and nothing closes. Red if the publisher-outage signature
/// is ignored.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stopped_publisher_never_accrues_toward_surrender() {
    let fixture = Fixture::new().await;
    let _control = fixture.register().await;
    fixture.set_bounds(SHORT_BOUND, SHORT_BOUND);
    let now = Utc::now();
    fixture
        .set_records(vec![fixture.signed(
            NODE_ID,
            2,
            SERVED_SPKI,
            now - ChronoDuration::seconds(50),
            now - ChronoDuration::seconds(10),
        )])
        .await;
    for _ in 0..3 {
        assert!(fixture.membership.reconcile_once().await.is_err());
        assert_eq!(
            fixture.membership.readiness(),
            MembershipReadiness::Unready(MembershipUnreadyReason::MembershipRejected)
        );
        tokio::time::sleep(SHORT_BOUND * 3 / 4).await;
    }
    assert_eq!(fixture.membership.ownership_surrender_cause(), None);
    fixture
        .assert_kept("a stopped publisher counted toward the bound")
        .await;
    fixture.shutdown().await;
}

/// **Control (M7-C184).** A `Ready` pass resets the clock: two unready
/// episodes each shorter than the bound never add up to it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ready_pass_resets_the_prolonged_unready_clock() {
    let fixture = Fixture::new().await;
    let _control = fixture.register().await;
    fixture.set_bounds(LONG_BOUND, SHORT_BOUND);
    fixture.rejected_pass().await;
    tokio::time::sleep(SHORT_BOUND * 3 / 4).await;
    fixture.rejected_pass().await;
    fixture.ready_pass().await;
    fixture.rejected_pass().await;
    tokio::time::sleep(SHORT_BOUND * 3 / 4).await;
    fixture.rejected_pass().await;
    assert_eq!(fixture.membership.ownership_surrender_cause(), None);
    fixture
        .assert_kept("two short episodes were summed across a Ready pass")
        .await;
    fixture.shutdown().await;
}

/// The production bounds are derived, not chosen: one record lifetime plus
/// skew for the publish race (65 s at the configured maxima), and the
/// longest owner lease plus that margin for any prolonged unready state
/// (95 s). The runtime uses exactly the derivation from its configuration.
#[tokio::test]
async fn the_surrender_bounds_are_derived_from_the_record_lifetime_skew_and_owner_lease() {
    let bounds = SurrenderBounds::derive(Duration::from_secs(60), Duration::from_secs(5));
    assert_eq!(bounds.local_record_below_minimum, Duration::from_secs(65));
    assert_eq!(bounds.prolonged_unready, Duration::from_secs(95));
    assert_eq!(
        bounds.prolonged_unready,
        crate::config::MAX_OWNER_LEASE + bounds.local_record_below_minimum
    );
    let fixture = Fixture::new().await;
    // The fixture runs with a 60 s record lifetime and a 1 s skew.
    assert_eq!(
        fixture.membership.surrender_bounds(),
        SurrenderBounds::derive(Duration::from_secs(60), Duration::from_secs(1))
    );
    // Clear of the default rekey convergence hold, which is the same record
    // lifetime plus skew and never makes a relay unready.
    assert!(bounds.prolonged_unready > bounds.local_record_below_minimum);
    fixture.shutdown().await;
}

// ---- Review of #228: the surrender condition is re-checked in the actor ----

/// **Red first.** The watcher saw the confirmed condition and queued the
/// request, but a re-sign restored membership before the actor ran it. The
/// actor re-checks immediately before collecting sessions, so nothing
/// closes. Held deterministically: the actor is parked on a test command
/// while the request queues behind it and the re-sign lands.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_surrender_queued_before_a_re_sign_closes_nothing() {
    let fixture = Fixture::without_watcher().await;
    let _control = fixture.register().await;
    fixture.publish(2, OTHER_SPKI).await;
    fixture.missing_key_pass().await;
    fixture.missing_key_pass().await;
    assert_eq!(
        fixture.membership.ownership_surrender_cause(),
        Some(OwnershipSurrenderCause::OwnKeyRetired)
    );

    // Park the actor.
    let (release, parked) = std::sync::mpsc::channel::<()>();
    let (entered, entered_rx) = tokio::sync::oneshot::channel::<()>();
    fixture
        .relay
        .tx
        .send(Command::TestMutate(Box::new(move |_actor| {
            let _ = entered.send(());
            tokio::task::block_in_place(|| {
                let _ = parked.recv();
            });
        })))
        .await
        .expect("the actor is running");
    entered_rx.await.expect("the actor is parked");

    // The watcher's request: its pre-check passes and the command queues.
    let membership = Arc::clone(&fixture.membership);
    let relay = fixture.relay.clone();
    let queued = tokio::spawn(async move { surrender_if_required(&membership, &relay).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !queued.is_finished(),
        "the request waits behind the parked actor"
    );

    // The re-sign lands while the request is queued.
    fixture.publish(3, SERVED_SPKI).await;
    fixture.ready_pass().await;
    release.send(()).expect("release the actor");

    let outcome = queued
        .await
        .expect("the request task")
        .expect("the actor answered");
    assert_eq!(
        outcome, None,
        "the actor's re-check found nothing to surrender"
    );
    assert!(
        fixture.owned().await,
        "the re-approved relay kept its lease"
    );
    assert_eq!(fixture.live_sessions().await, 1);
    fixture.shutdown().await;
}

// ---- M7-C185: a record the checkpoint does not ask for is not fatal --------

/// **Red first (M7-C185).** The catalog never deletes a removed node's
/// record. A record for a node the checkpoint omits -- and one below its
/// node's minimum -- must not fail this relay's pass: it stays `Ready`.
/// Before M7-C185 every relay concluded `MembershipRejected`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stale_record_for_another_node_leaves_this_relay_ready() {
    let fixture = Fixture::new().await;
    let _control = fixture.register().await;
    let now = Utc::now();
    let own = fixture.signed(
        NODE_ID,
        2,
        SERVED_SPKI,
        now - ChronoDuration::seconds(1),
        now + ChronoDuration::seconds(30),
    );
    let stale = fixture.signed(
        PEER_NODE,
        1,
        OTHER_SPKI,
        now - ChronoDuration::seconds(1),
        now + ChronoDuration::seconds(30),
    );
    // The checkpoint omits relay-b: it was removed.
    fixture.set_records(vec![own.clone(), stale.clone()]).await;
    fixture.ready_pass().await;
    // The checkpoint names relay-b again, at a minimum above its record.
    fixture
        .authority
        .others
        .lock()
        .expect("other nodes")
        .insert(PEER_NODE.to_owned(), 5);
    fixture.ready_pass().await;
    fixture.assert_kept("a stale record for another node").await;
    fixture.shutdown().await;
}

/// **Red first (M7-C185).** The same, with the removed node's record also
/// past its signed lifetime: it is selected out by node before verification,
/// so the window check that runs first inside verification never sees it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_expired_stale_record_for_another_node_leaves_this_relay_ready() {
    let fixture = Fixture::new().await;
    let _control = fixture.register().await;
    let now = Utc::now();
    let own = fixture.signed(
        NODE_ID,
        2,
        SERVED_SPKI,
        now - ChronoDuration::seconds(1),
        now + ChronoDuration::seconds(30),
    );
    let expired = fixture.signed(
        PEER_NODE,
        1,
        OTHER_SPKI,
        now - ChronoDuration::seconds(50),
        now - ChronoDuration::seconds(10),
    );
    fixture.set_records(vec![own, expired]).await;
    fixture.ready_pass().await;
    fixture
        .assert_kept("an expired stale record for another node")
        .await;
    fixture.shutdown().await;
}

/// **Control (M7-C185, narrowed by M7-C187).** A record the checkpoint
/// *does* ask for, still inside its signed lifetime plus the accepted skew,
/// fails the pass if it fails any check. relay-b is named at minimum 1 and
/// its record is signed under the trusted key id by a foreign key: first
/// fresh, then expired half a second ago -- past its lifetime but inside the
/// 1 s skew, so verification still judges it. Both stay fatal
/// (`SignatureInvalid`, `MembershipRejected`). Red if the pre-filter skipped
/// failing named records, or judged expiry without the skew.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_named_record_at_its_minimum_that_fails_a_check_stays_fatal() {
    let fixture = Fixture::new().await;
    let _control = fixture.register().await;
    fixture
        .authority
        .others
        .lock()
        .expect("other nodes")
        .insert(PEER_NODE.to_owned(), 1);
    let (foreign, _private_key) =
        MembershipIssuer::generate(PUBLISHER_KEY_ID).expect("foreign membership issuer");
    let now = Utc::now();
    let own = fixture.signed(
        NODE_ID,
        2,
        SERVED_SPKI,
        now - ChronoDuration::seconds(1),
        now + ChronoDuration::seconds(30),
    );
    for (case, expires_at) in [
        ("fresh", now + ChronoDuration::seconds(30)),
        (
            "expired inside the skew",
            now - ChronoDuration::milliseconds(500),
        ),
    ] {
        let forged = signed_by(
            &foreign,
            PEER_NODE,
            1,
            OTHER_SPKI,
            now - ChronoDuration::seconds(20),
            expires_at,
        );
        fixture.set_records(vec![own.clone(), forged]).await;
        let error = fixture
            .membership
            .reconcile_once()
            .await
            .expect_err("a forged named record inside its lifetime is fatal");
        assert!(
            matches!(
                error,
                crate::MembershipRuntimeError::Membership(
                    tunnel_cluster::membership::MembershipError::SignatureInvalid
                )
            ),
            "{case}: expected a signature failure, got {error:?}"
        );
        assert_eq!(
            fixture.membership.readiness(),
            MembershipReadiness::Unready(MembershipUnreadyReason::MembershipRejected),
            "{case}"
        );
    }
    fixture.shutdown().await;
}

/// **Red first (M7-C187).** The publisher keeps relay-b in the checkpoint
/// but stops re-signing its record. Once that record is past its lifetime
/// plus skew it is absent for relay-b only: this relay stays `Ready`, keeps
/// its device, accrues nothing, and has no route to relay-b and admits no
/// peer as relay-b. Before M7-C187 the lapsed record failed the pass as
/// `MembershipRejected` on every relay, and after M7-C184 the whole cluster
/// surrendered at 95 s.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lapsed_peer_record_leaves_this_relay_ready_without_a_route_to_that_peer() {
    let fixture = Fixture::new().await;
    let _control = fixture.register().await;
    fixture.set_bounds(SHORT_BOUND, SHORT_BOUND);
    fixture
        .authority
        .others
        .lock()
        .expect("other nodes")
        .insert(PEER_NODE.to_owned(), 1);
    let now = Utc::now();
    let own = fixture.signed(
        NODE_ID,
        2,
        SERVED_SPKI,
        now - ChronoDuration::seconds(1),
        now + ChronoDuration::seconds(30),
    );
    let peer_expiry = now + ChronoDuration::seconds(1);
    let peer = fixture.signed(
        PEER_NODE,
        1,
        OTHER_SPKI,
        now - ChronoDuration::seconds(1),
        peer_expiry,
    );
    fixture.set_records(vec![own, peer]).await;
    fixture.ready_pass().await;
    let routes_to_peer = |fixture: &Fixture| {
        fixture
            .membership
            .verified_peer_route_targets()
            .iter()
            .any(|target| target.node_id() == PEER_NODE)
    };
    assert!(
        routes_to_peer(&fixture),
        "relay-b is routable while its record is fresh"
    );

    // The same record, never re-signed, ages past its lifetime and the 1 s
    // skew.
    while Utc::now() <= peer_expiry + ChronoDuration::milliseconds(1_200) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    for _ in 0..3 {
        fixture.ready_pass().await;
        tokio::time::sleep(SHORT_BOUND * 3 / 4).await;
    }
    fixture.ready_pass().await;
    assert!(
        !routes_to_peer(&fixture),
        "a lapsed record must leave no route to relay-b"
    );
    let admission = fixture
        .membership
        .admit_peer(crate::MembershipPeerIdentity::new(
            PEER_NODE, "boot-b", OTHER_SPKI,
        ));
    assert!(
        matches!(admission, Err(crate::MembershipRuntimeError::PeerRejected)),
        "a lapsed record must admit no peer as relay-b, got {:?}",
        admission.map(|_| "admitted")
    );
    assert_eq!(fixture.membership.ownership_surrender_cause(), None);
    fixture
        .assert_kept("a lapsed record for another node")
        .await;
    fixture.shutdown().await;
}

/// **Red first (M7-C187).** A relay that never saw relay-b's record fresh --
/// one started or restarted after it lapsed, as in a rolling deploy -- has
/// nothing to fall back to: the lapsed record is absent for relay-b, and this
/// relay becomes `Ready` with no route to it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lapsed_peer_record_never_seen_fresh_is_absent_for_that_peer() {
    let fixture = Fixture::new().await;
    let _control = fixture.register().await;
    fixture
        .authority
        .others
        .lock()
        .expect("other nodes")
        .insert(PEER_NODE.to_owned(), 1);
    let now = Utc::now();
    let own = fixture.signed(
        NODE_ID,
        2,
        SERVED_SPKI,
        now - ChronoDuration::seconds(1),
        now + ChronoDuration::seconds(30),
    );
    let lapsed = fixture.signed(
        PEER_NODE,
        1,
        OTHER_SPKI,
        now - ChronoDuration::seconds(50),
        now - ChronoDuration::seconds(10),
    );
    fixture.set_records(vec![own, lapsed]).await;
    fixture.ready_pass().await;
    assert!(
        fixture
            .membership
            .verified_peer_route_targets()
            .iter()
            .all(|target| target.node_id() != PEER_NODE),
        "a lapsed record must leave no route to relay-b"
    );
    fixture.shutdown().await;
}

/// **Red first (M7-C187 carve-out).** An already-expired revision is how a
/// publisher withdraws a node's live record. If this relay retains an older
/// verified record for relay-b that is still inside its window, skipping the
/// newer lapsed revision would leave the superseded record routable, so it
/// stays fatal (`Expired`, `MembershipRejected`) as before M7-C187. Red if
/// the pre-filter skipped every lapsed peer record.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lapsed_revision_superseding_a_live_peer_record_stays_fatal() {
    let fixture = Fixture::new().await;
    let _control = fixture.register().await;
    fixture.add_peer(2).await;
    assert!(
        fixture
            .membership
            .verified_peer_route_targets()
            .iter()
            .any(|target| target.node_id() == PEER_NODE),
        "relay-b is routable on its live version 1"
    );
    let now = Utc::now();
    let own = fixture.signed(
        NODE_ID,
        3,
        SERVED_SPKI,
        now - ChronoDuration::seconds(1),
        now + ChronoDuration::seconds(30),
    );
    let withdrawal = fixture.signed(
        PEER_NODE,
        2,
        OTHER_SPKI,
        now - ChronoDuration::seconds(3),
        now - ChronoDuration::seconds(2),
    );
    fixture.set_records(vec![own, withdrawal]).await;
    let error = fixture
        .membership
        .reconcile_once()
        .await
        .expect_err("a lapsed revision superseding a live record is fatal");
    assert!(
        matches!(
            error,
            crate::MembershipRuntimeError::Membership(
                tunnel_cluster::membership::MembershipError::Expired
            )
        ),
        "expected the lapsed revision to be judged, got {error:?}"
    );
    assert_eq!(
        fixture.membership.readiness(),
        MembershipReadiness::Unready(MembershipUnreadyReason::MembershipRejected)
    );
    assert!(
        fixture.membership.verified_peer_route_targets().is_empty(),
        "the superseded record stayed routable"
    );
    fixture.shutdown().await;
}

/// **Red first (M7-C187 carve-out, version condition).** The carve-out
/// only covers a lapsed record *above* the retained version. A lapsed record
/// at an older version than the live one this relay retains -- a stale
/// rewrite of an expired record -- supersedes nothing, so it is absent and
/// relay-b stays routable on its retained, newer version. Red if the
/// carve-out ignores the version order (the pass then fails `Expired`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lapsed_older_peer_record_beside_a_live_retained_version_is_absent() {
    let fixture = Fixture::new().await;
    let _control = fixture.register().await;
    fixture
        .authority
        .others
        .lock()
        .expect("other nodes")
        .insert(PEER_NODE.to_owned(), 1);
    let now = Utc::now();
    let own = fixture.signed(
        NODE_ID,
        2,
        SERVED_SPKI,
        now - ChronoDuration::seconds(1),
        now + ChronoDuration::seconds(30),
    );
    let live_v2 = fixture.signed(
        PEER_NODE,
        2,
        OTHER_SPKI,
        now - ChronoDuration::seconds(1),
        now + ChronoDuration::seconds(50),
    );
    fixture.set_records(vec![own.clone(), live_v2]).await;
    fixture.ready_pass().await;
    let lapsed_v1 = fixture.signed(
        PEER_NODE,
        1,
        OTHER_SPKI,
        now - ChronoDuration::seconds(50),
        now - ChronoDuration::seconds(10),
    );
    fixture.set_records(vec![own, lapsed_v1]).await;
    fixture.ready_pass().await;
    assert!(
        fixture
            .membership
            .verified_peer_route_targets()
            .iter()
            .any(|target| target.node_id() == PEER_NODE),
        "relay-b stays routable on its retained live version 2"
    );
    fixture.shutdown().await;
}

/// **Red first (M7-C187 carve-out bound, review of #233).** The carve-out
/// only protects a retained record that is still inside its window. Here
/// relay-b's version 1 is retained, then lapses past its lifetime plus skew,
/// and only then does the publisher write an already-expired version 2. With
/// nothing routable left to protect, version 2 is absent for relay-b: this
/// relay is `Ready` with no route to relay-b. Without the bound, the
/// withdrawal would block `Ready` on every pass and count toward M7-C184.
/// Red if the carve-out ignores the retained record's expiry.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_withdrawal_after_the_retained_peer_record_lapsed_is_absent() {
    let fixture = Fixture::new().await;
    let _control = fixture.register().await;
    fixture
        .authority
        .others
        .lock()
        .expect("other nodes")
        .insert(PEER_NODE.to_owned(), 1);
    let now = Utc::now();
    let own = fixture.signed(
        NODE_ID,
        2,
        SERVED_SPKI,
        now - ChronoDuration::seconds(1),
        now + ChronoDuration::seconds(30),
    );
    let v1_expiry = now + ChronoDuration::seconds(1);
    let v1 = fixture.signed(
        PEER_NODE,
        1,
        OTHER_SPKI,
        now - ChronoDuration::seconds(1),
        v1_expiry,
    );
    fixture.set_records(vec![own.clone(), v1]).await;
    fixture.ready_pass().await;
    assert!(
        fixture
            .membership
            .verified_peer_route_targets()
            .iter()
            .any(|target| target.node_id() == PEER_NODE),
        "relay-b is routable on its live version 1"
    );
    // Version 1 lapses past its lifetime and the 1 s skew.
    while Utc::now() <= v1_expiry + ChronoDuration::milliseconds(1_200) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let later = Utc::now();
    let withdrawal = fixture.signed(
        PEER_NODE,
        2,
        OTHER_SPKI,
        later - ChronoDuration::seconds(3),
        later - ChronoDuration::seconds(2),
    );
    fixture.set_records(vec![own, withdrawal]).await;
    fixture.ready_pass().await;
    fixture.ready_pass().await;
    assert!(
        fixture
            .membership
            .verified_peer_route_targets()
            .iter()
            .all(|target| target.node_id() != PEER_NODE),
        "a lapsed withdrawal must leave no route to relay-b"
    );
    assert_eq!(fixture.membership.ownership_surrender_cause(), None);
    fixture.shutdown().await;
}

/// **Red first (M7-C187).** Only *another* node's lapsed record is absent:
/// this relay's own record, aged past its lifetime plus skew, keeps its
/// current meaning -- it is still verified, the pass fails on it (`Expired`),
/// readiness reports `CheckpointExpired`, and that accrues toward M7-C184
/// while relay-b's fresh record shows the publisher is alive. Red if the
/// pre-filter also skipped this relay's own lapsed record (the pass then
/// fails later, on the retained record's lapsed key, as `CheckpointExpired`
/// without judging the record).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn this_relays_own_lapsed_record_stays_fatal_beside_a_fresh_peer() {
    let fixture = Fixture::new().await;
    let _control = fixture.register().await;
    fixture
        .authority
        .others
        .lock()
        .expect("other nodes")
        .insert(PEER_NODE.to_owned(), 1);
    fixture.set_bounds(LONG_BOUND, SHORT_BOUND);
    let now = Utc::now();
    let own_expiry = now + ChronoDuration::seconds(1);
    let own = fixture.signed(
        NODE_ID,
        2,
        SERVED_SPKI,
        now - ChronoDuration::seconds(1),
        own_expiry,
    );
    let peer = fixture.signed(
        PEER_NODE,
        1,
        OTHER_SPKI,
        now - ChronoDuration::seconds(1),
        now + ChronoDuration::seconds(50),
    );
    fixture.set_records(vec![own, peer]).await;
    fixture.ready_pass().await;
    // This relay's own record, never re-signed, ages past its lifetime and
    // the 1 s skew while relay-b's stays fresh.
    while Utc::now() <= own_expiry + ChronoDuration::milliseconds(1_200) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    for _ in 0..2 {
        let error = fixture
            .membership
            .reconcile_once()
            .await
            .expect_err("this relay's own lapsed record is fatal");
        assert!(
            matches!(
                error,
                crate::MembershipRuntimeError::Membership(
                    tunnel_cluster::membership::MembershipError::Expired
                )
            ),
            "expected an expired own record, got {error:?}"
        );
        // Its current meaning: the pass fails on the record itself
        // (`Expired`), and readiness reports the lapsed trust window.
        assert_eq!(
            fixture.membership.readiness(),
            MembershipReadiness::Unready(MembershipUnreadyReason::CheckpointExpired)
        );
        tokio::time::sleep(SHORT_BOUND + Duration::from_millis(50)).await;
    }
    assert_eq!(
        fixture.membership.ownership_surrender_cause(),
        Some(OwnershipSurrenderCause::ProlongedUnready)
    );
    fixture.shutdown().await;
}

/// **Red first (M7-C187 with M7-C186).** Skipping lapsed peer records does
/// not hide a publisher outage: with every named record lapsed -- relay-b's
/// skipped, this relay's own failing as `Expired` -- no named record is
/// fresh, so no pass accrues toward M7-C184 and nothing closes. Red if the
/// publisher-outage signature is ignored.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_named_record_lapsed_is_still_a_publisher_outage() {
    let fixture = Fixture::new().await;
    let _control = fixture.register().await;
    fixture
        .authority
        .others
        .lock()
        .expect("other nodes")
        .insert(PEER_NODE.to_owned(), 1);
    fixture.set_bounds(SHORT_BOUND, SHORT_BOUND);
    let now = Utc::now();
    let own = fixture.signed(
        NODE_ID,
        2,
        SERVED_SPKI,
        now - ChronoDuration::seconds(50),
        now - ChronoDuration::seconds(10),
    );
    let peer = fixture.signed(
        PEER_NODE,
        1,
        OTHER_SPKI,
        now - ChronoDuration::seconds(50),
        now - ChronoDuration::seconds(10),
    );
    fixture.set_records(vec![own, peer]).await;
    for _ in 0..3 {
        assert!(fixture.membership.reconcile_once().await.is_err());
        assert_eq!(
            fixture.membership.readiness(),
            MembershipReadiness::Unready(MembershipUnreadyReason::MembershipRejected)
        );
        tokio::time::sleep(SHORT_BOUND * 3 / 4).await;
    }
    assert_eq!(fixture.membership.ownership_surrender_cause(), None);
    fixture
        .assert_kept("every named record lapsed counted toward the bound")
        .await;
    fixture.shutdown().await;
}

/// **Red first (M7-C186, review of #230).** The authority refuses *this*
/// relay -- `403`, `404`, `401`, as it would a decommissioned relay's client
/// certificate.
/// That is about this relay, not a shared outage, so it accrues toward the
/// prolonged-unready surrender; exempting it would recreate M7-C181 through
/// the authority. Red if every authority error counts as shared.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_authority_refusing_this_relay_accrues_toward_surrender() {
    let fixture = Fixture::new().await;
    let mut control = fixture.register().await;
    fixture.set_bounds(LONG_BOUND, SHORT_BOUND);
    // 403, 404, 401: each interval is shorter than the bound, so the
    // surrender needs every one of them counted, 404 included.
    fixture.authority_status_pass(403).await;
    tokio::time::sleep(SHORT_BOUND * 3 / 4).await;
    fixture.authority_status_pass(404).await;
    tokio::time::sleep(SHORT_BOUND * 3 / 4).await;
    fixture.authority_status_pass(401).await;
    assert_eq!(
        fixture.membership.ownership_surrender_cause(),
        Some(OwnershipSurrenderCause::ProlongedUnready)
    );
    assert!(wait_until_released(&fixture).await.is_some());
    assert_eq!(
        rejection_code(&mut control).await.as_deref(),
        Some(MEMBERSHIP_UNREADY_PROLONGED)
    );
    fixture.shutdown().await;
}

/// **Control (M7-C186, review of #230).** An authority that is overloaded or
/// failing -- `503`, `500`, `429`, `408` -- is a shared outage: nothing
/// accrues however long it lasts. One status per run, four passes spanning
/// more than the bound, so counting any single one of them surrenders: red
/// under each single-status exemption mutation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authority_server_errors_and_throttling_never_accrue_toward_surrender() {
    let fixture = Fixture::new().await;
    let _control = fixture.register().await;
    fixture.set_bounds(LONG_BOUND, SHORT_BOUND);
    for status in [503, 500, 429, 408] {
        for pass in 0..4 {
            if pass > 0 {
                tokio::time::sleep(SHORT_BOUND * 3 / 4).await;
            }
            fixture.authority_status_pass(status).await;
        }
        assert_eq!(
            fixture.membership.ownership_surrender_cause(),
            None,
            "a run of authority status {status} counted toward the bound"
        );
    }
    fixture
        .assert_kept("a failing authority counted toward the bound")
        .await;
    fixture.shutdown().await;
}

/// **Control (M7-C186, review of #230).** The publisher has stopped: the
/// checkpoint raised this node's minimum and the catalog holds nothing, so
/// no named record is fresh. The case (b) run does not advance on such
/// passes, however long they last. Red if (b) ignores the shared outage.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_publisher_outage_never_advances_the_below_minimum_run() {
    let fixture = Fixture::new().await;
    let _control = fixture.register().await;
    fixture.set_bounds(SHORT_BOUND, LONG_BOUND);
    fixture
        .authority
        .minimum_version
        .store(5, Ordering::Release);
    fixture.set_records(Vec::new()).await;
    for _ in 0..3 {
        fixture.missing_membership_pass().await;
        tokio::time::sleep(SHORT_BOUND * 3 / 4).await;
    }
    fixture.missing_membership_pass().await;
    assert_eq!(fixture.membership.ownership_surrender_cause(), None);
    fixture
        .assert_kept("a publisher outage advanced the below-minimum run")
        .await;
    fixture.shutdown().await;
}

/// **Control (M7-C186).** A fresh record *below* its node's minimum is not
/// evidence that the publisher is alive: with only this relay's older record
/// in the catalog, the (b) run does not advance. Red if freshness ignores
/// the minimum.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_record_below_its_minimum_is_not_evidence_the_publisher_is_alive() {
    let fixture = Fixture::new().await;
    let _control = fixture.register().await;
    fixture.set_bounds(SHORT_BOUND, LONG_BOUND);
    fixture
        .authority
        .minimum_version
        .store(5, Ordering::Release);
    fixture.publish(2, SERVED_SPKI).await;
    for _ in 0..3 {
        fixture.missing_membership_pass().await;
        tokio::time::sleep(SHORT_BOUND * 3 / 4).await;
    }
    fixture.missing_membership_pass().await;
    assert_eq!(fixture.membership.ownership_surrender_cause(), None);
    fixture.shutdown().await;
}

/// **Red first (M7-C186).** Freshness allows the accepted clock skew, as
/// verification does: another relay's record that expired a second ago (well
/// inside the 5 s skew of this fixture) still shows a live publisher, so this
/// relay's below-minimum run advances and surrenders. Red if freshness drops
/// the skew.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn freshness_allows_the_clock_skew() {
    let fixture = Fixture::with_skew(Duration::from_secs(5)).await;
    let _control = fixture.register().await;
    let bound = Duration::from_millis(250);
    fixture.set_bounds(bound, LONG_BOUND);
    fixture
        .authority
        .others
        .lock()
        .expect("other nodes")
        .insert(PEER_NODE.to_owned(), 1);
    fixture
        .authority
        .minimum_version
        .store(5, Ordering::Release);
    let now = Utc::now();
    let own = fixture.signed(
        NODE_ID,
        2,
        SERVED_SPKI,
        now - ChronoDuration::seconds(1),
        now + ChronoDuration::seconds(30),
    );
    let peer = fixture.signed(
        PEER_NODE,
        1,
        OTHER_SPKI,
        now - ChronoDuration::seconds(50),
        now - ChronoDuration::seconds(1),
    );
    fixture.set_records(vec![own, peer]).await;
    fixture.missing_membership_pass().await;
    tokio::time::sleep(bound + Duration::from_millis(50)).await;
    fixture.missing_membership_pass().await;
    assert_eq!(
        fixture.membership.ownership_surrender_cause(),
        Some(OwnershipSurrenderCause::LocalRecordBelowMinimum)
    );
    fixture.shutdown().await;
}

/// **Control (M7-C185, hosted M7 on #230).** The pre-filter skips only
/// records below their node's minimum or for nodes the checkpoint omits. A
/// record *at* its minimum whose contents conflict with the version this
/// relay already verified -- an equal-version conflict -- still fails the
/// pass as `MembershipRejected`; it is never downgraded to a missing record.
/// Red if the pre-filter also skips records at their minimum.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_equal_version_conflict_at_the_minimum_stays_fatal() {
    let fixture = Fixture::new().await;
    let _control = fixture.register().await;
    // Version 1 was verified at bootstrap; a different version-1 record
    // (another key, other timestamps) conflicts with it.
    let now = Utc::now();
    fixture
        .set_records(vec![fixture.signed(
            NODE_ID,
            1,
            OTHER_SPKI,
            now - ChronoDuration::seconds(2),
            now + ChronoDuration::seconds(20),
        )])
        .await;
    let error = fixture
        .membership
        .reconcile_once()
        .await
        .expect_err("a conflicting record at the minimum is fatal");
    assert!(
        matches!(
            error,
            crate::MembershipRuntimeError::Membership(
                tunnel_cluster::membership::MembershipError::EqualVersionConflict { .. }
            )
        ),
        "expected an equal-version conflict, got {error:?}"
    );
    assert_eq!(
        fixture.membership.readiness(),
        MembershipReadiness::Unready(MembershipUnreadyReason::MembershipRejected)
    );
    fixture.shutdown().await;
}
