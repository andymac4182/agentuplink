//! Task row M7-C181: a relay whose own served peer key is retired surrenders
//! the device ownership it holds.
//!
//! Each test drives a real [`MembershipRuntime`] (a signed in-memory
//! checkpoint authority and record source) and a real relay actor over a
//! [`MemoryCatalog`], with the production watcher loop
//! ([`own_key_surrender_loop`]) between them. Reconcile passes are run by
//! hand so the confirmation count is deterministic.

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

use super::{ControlOutbound, ControlRegistration, LOCAL_IDENTITY_RETIRED, RelayHandle};
use crate::{
    RelayOptions,
    clock_offset::{ClockOffsetHealth, Measurement},
    membership_runtime::{
        CheckpointAuthority, CheckpointAuthorityError, CheckpointRequest, CheckpointResponse,
        MembershipFuture, MembershipReadiness, MembershipRecordSource, MembershipRuntime,
        MembershipRuntimeConfig, MembershipSourceError, MembershipUnreadyReason,
        OWN_KEY_SURRENDER_CONFIRMATIONS,
    },
    own_key_surrender::own_key_surrender_loop,
};

const DEPLOYMENT_ID: &str = "c181-deployment";
const DEPLOYMENT_INCARNATION: &str = "c181-incarnation";
const NODE_ID: &str = "relay-a";
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
            let now = Utc::now();
            let checkpoint = MembershipCheckpoint {
                schema_version: MEMBERSHIP_SCHEMA_VERSION,
                deployment_id: request.deployment_id,
                deployment_incarnation: request.deployment_incarnation,
                checkpoint_version: self.next_version.fetch_add(1, Ordering::AcqRel),
                nonce: request.nonce,
                minimum_versions: BTreeMap::from([(NODE_ID.to_owned(), 1)]),
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
        let (issuer, _private_key) =
            MembershipIssuer::generate(PUBLISHER_KEY_ID).expect("synthetic membership issuer");
        let issuer = Arc::new(issuer);
        let authority = Arc::new(SignedAuthority {
            issuer: Arc::clone(&issuer),
            next_version: AtomicU64::new(1),
            fail: AtomicBool::new(false),
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
            Duration::from_secs(1),
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
        tokio::spawn(own_key_surrender_loop(
            Arc::clone(&fixture.membership),
            fixture.relay.clone(),
            POLL,
            fixture.cancel.child_token(),
        ));
        fixture
    }

    /// Publish this relay's signed record approving exactly `spki`.
    async fn publish(&self, version: u64, spki: &str) {
        let now = Utc::now();
        let not_before = now - ChronoDuration::seconds(1);
        let expires_at = now + ChronoDuration::seconds(30);
        let record = SignedRecord {
            schema_version: MEMBERSHIP_SCHEMA_VERSION,
            deployment_id: DEPLOYMENT_ID.to_owned(),
            deployment_incarnation: DEPLOYMENT_INCARNATION.to_owned(),
            node_id: NODE_ID.to_owned(),
            record_version: version,
            roles: vec![RELAY_PEER_ROLE.to_owned()],
            peer_endpoint: "10.0.0.1:8443".to_owned(),
            server_name: "10.0.0.1".to_owned(),
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
        *self.source.records.write().await = vec![CatalogMembershipRecord {
            version,
            bytes: self
                .issuer
                .sign_membership_bytes(record)
                .expect("synthetic signed membership"),
        }];
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
        assert!(matches!(
            error,
            crate::MembershipRuntimeError::PeerRejected
        ));
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
    assert!(fixture.owned().await, "a re-approved relay owns devices again");
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

/// **Control.** A clock offset beyond the cluster skew bound makes the relay
/// not ready (M7-C175) but is not an own-key retirement: nothing closes.
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
    assert!(fixture.owned().await, "a clock-offset unready kept the lease");
    assert_eq!(fixture.live_sessions().await, 1);
    fixture.shutdown().await;
}
