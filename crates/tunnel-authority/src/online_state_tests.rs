#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{atomic::AtomicUsize, mpsc},
};

use tunnel_cluster::membership::{RelayKey, SignedMembershipCheckpoint};

use super::*;
use crate::online_config::{EndpointPolicy, Node, hex};

const NONCE: &str = "independent-state-test-nonce-1234";
const RUN_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const RUN_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

struct Fixture {
    _directory: tempfile::TempDir,
    root: PathBuf,
    config: Config,
    inventory: Inventory,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        // Darwin commonly gives temp_dir a symlink ancestor. Production path
        // validation remains strict; fixtures use the actual directory path.
        let root = directory.path().canonicalize().unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let (issuer, key) = MembershipIssuer::generate("publisher-test").unwrap();
        let now = Utc::now();
        let inventory = Inventory {
            schema_version: 1,
            deployment_id: "independent-test-deployment".into(),
            redis_namespace: "authority-state-tests".into(),
            deployment_incarnation: "incarnation-a".into(),
            revision: 1,
            publisher_key_id: "publisher-test".into(),
            publisher_public_key: hex(&issuer.public_key().unwrap()),
            nodes: vec![Node {
                node_id: "relay-a".into(),
                peer_endpoint: "10.42.0.1:8443".into(),
                server_name: "relay-a.internal".into(),
                keys: vec![RelayKey {
                    key_id: "relay-a-key".into(),
                    spki_sha256: "11".repeat(32),
                    not_before: now - chrono::Duration::seconds(60),
                    expires_at: now + chrono::Duration::hours(1),
                    revoked: false,
                }],
                checkpoint_client_spkis: vec!["22".repeat(32)],
            }],
        };
        let config = Config {
            schema_version: 1,
            bind: "127.0.0.1:8444".parse().unwrap(),
            state_path: root.join("state.json"),
            signing_key_path: root.join("signing.der"),
            redis_url_path: root.join("unused-redis-url"),
            redis_ca_path: root.join("unused-redis-ca"),
            redis_client_cert_path: None,
            redis_client_key_path: None,
            tls_cert_chain: root.join("unused-tls-chain"),
            tls_private_key: root.join("unused-tls-key"),
            tls_client_ca: root.join("unused-client-ca"),
            endpoint_policy: EndpointPolicy {
                allowed_hosts: vec!["10.42.0.1".into()],
                allowed_server_names: vec!["relay-a.internal".into()],
                allowed_ports: vec![8443],
            },
        };
        let fixture = Self {
            _directory: directory,
            root,
            config,
            inventory,
        };
        fixture.write("signing.der", &key);
        let path = fixture.inventory_file(&fixture.inventory);
        initialize(&fixture.config, &path, RUN_A).unwrap();
        fixture
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.root.join(name);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    fn inventory_file(&self, inventory: &Inventory) -> PathBuf {
        self.write("inventory.json", &serde_json::to_vec(inventory).unwrap())
    }

    fn engine(&self) -> Engine {
        Engine::open(self.config.clone(), Arc::new(AtomicBool::new(false))).unwrap()
    }

    fn coordinator(&self) -> Coordinator {
        let fatal = Arc::new(AtomicBool::new(false));
        Coordinator::new(
            Engine::open(self.config.clone(), fatal.clone()).unwrap(),
            fatal,
        )
    }
}

fn checkpoint(engine: &mut Engine) -> SignedMembershipCheckpoint {
    serde_json::from_slice(&engine.checkpoint(NONCE.into()).unwrap()).unwrap()
}

fn confirm_next(engine: &mut Engine) -> u64 {
    let round = engine.reserve_round().unwrap();
    let version = round.version;
    engine.confirm(round).unwrap();
    version
}

#[test]
fn restart_requires_a_new_confirmed_publication_without_resetting_allocators() {
    let fixture = Fixture::new();
    let mut engine = fixture.engine();
    assert_eq!(confirm_next(&mut engine), 1);
    let first = checkpoint(&mut engine);
    assert_eq!(first.checkpoint_version, 1);
    assert_eq!(first.minimum_versions["relay-a"], 1);
    drop(engine);

    let mut restarted = fixture.engine();
    assert!(
        restarted.state.confirmed.is_some(),
        "confirmation was durable"
    );
    assert!(
        restarted.checkpoint(NONCE.into()).is_err(),
        "durability does not restore process freshness"
    );
    assert_eq!(restarted.state.checkpoint_high_water, 1);
    assert_eq!(confirm_next(&mut restarted), 2);
    let second = checkpoint(&mut restarted);
    assert_eq!(second.checkpoint_version, 2);
    assert_eq!(second.minimum_versions["relay-a"], 2);
}

#[test]
fn abandoning_a_reserved_round_spends_its_version_across_restart() {
    let fixture = Fixture::new();
    let mut engine = fixture.engine();
    let abandoned = engine.reserve_round().unwrap();
    assert_eq!(abandoned.records[0].1.version, 1);
    assert!(engine.checkpoint(NONCE.into()).is_err());
    drop(abandoned);
    drop(engine);

    let mut restarted = fixture.engine();
    assert_eq!(confirm_next(&mut restarted), 2);
    let response = checkpoint(&mut restarted);
    assert_eq!(response.minimum_versions["relay-a"], 2);
    assert_eq!(
        response.checkpoint_version, 1,
        "the allocators are independent"
    );
}

#[test]
fn approval_preserves_both_allocators_and_removes_old_inventory_confirmation() {
    let fixture = Fixture::new();
    let mut engine = fixture.engine();
    confirm_next(&mut engine);
    checkpoint(&mut engine);
    checkpoint(&mut engine);
    drop(engine.reserve_round().unwrap());
    drop(engine);

    let mut revised = fixture.inventory.clone();
    revised.revision = 2;
    revised.nodes[0].checkpoint_client_spkis = vec!["33".repeat(32)];
    let path = fixture.inventory_file(&revised);
    let before = fs::read(&fixture.config.state_path).unwrap();
    assert!(
        approve(&fixture.config, &path, 1, RUN_B).is_err(),
        "a Redis run change cannot silently reapprove an incarnation"
    );
    assert_eq!(fs::read(&fixture.config.state_path).unwrap(), before);
    revised.deployment_incarnation = "incarnation-b".into();
    let path = fixture.inventory_file(&revised);
    approve(&fixture.config, &path, 1, RUN_B).unwrap();

    let mut restarted = fixture.engine();
    assert_eq!(restarted.expected_run(), RUN_B);
    assert_eq!(restarted.state.membership_high_water, 2);
    assert_eq!(restarted.state.checkpoint_high_water, 2);
    assert!(restarted.state.confirmed.is_none());
    assert!(restarted.checkpoint(NONCE.into()).is_err());
    assert!(
        !restarted
            .inventory()
            .permits_client("relay-a", &"22".repeat(32))
    );
    assert!(
        restarted
            .inventory()
            .permits_client("relay-a", &"33".repeat(32))
    );
    assert_eq!(confirm_next(&mut restarted), 3);
    let response = checkpoint(&mut restarted);
    assert_eq!(response.deployment_incarnation, "incarnation-b");
    assert_eq!(response.checkpoint_version, 3);
    assert_eq!(response.minimum_versions["relay-a"], 3);
}

#[test]
fn historical_node_slots_survive_replacements_and_incarnation_changes() {
    let fixture = Fixture::new();
    let mut engine = fixture.engine();
    confirm_next(&mut engine);
    checkpoint(&mut engine);
    checkpoint(&mut engine);
    drop(engine.reserve_round().unwrap());
    drop(engine);

    let mut inventory = fixture.inventory.clone();
    inventory.revision = 2;
    for index in 1..32 {
        let mut node = inventory.nodes[0].clone();
        node.node_id = format!("retained-node-{index}");
        node.keys[0].key_id = format!("retained-key-{index}");
        inventory.nodes.push(node);
    }
    approve(
        &fixture.config,
        &fixture.inventory_file(&inventory),
        1,
        RUN_A,
    )
    .unwrap();
    let after_expansion = fixture.engine();
    assert_eq!(after_expansion.state.known_node_ids.len(), 32);
    assert_eq!(after_expansion.state.membership_high_water, 2);
    assert_eq!(after_expansion.state.checkpoint_high_water, 2);
    drop(after_expansion);

    // Replacing a certificate for one stable logical ID consumes no Redis
    // directory slot, including across independently approved recovery.
    inventory.revision = 3;
    inventory.deployment_incarnation = "incarnation-recovered".into();
    inventory.nodes[0].checkpoint_client_spkis = vec!["44".repeat(32)];
    inventory.nodes[0].keys[0].spki_sha256 = "55".repeat(32);
    approve(
        &fixture.config,
        &fixture.inventory_file(&inventory),
        2,
        RUN_B,
    )
    .unwrap();
    let replaced = fixture.engine();
    assert_eq!(replaced.state.known_node_ids.len(), 32);
    assert_eq!(replaced.state.membership_high_water, 2);
    assert_eq!(replaced.state.checkpoint_high_water, 2);
    assert_eq!(replaced.expected_run(), RUN_B);
    assert!(replaced.state.confirmed.is_none());
    drop(replaced);

    // Current inventory still has only32 nodes, but removing one does not
    // free its historical directory slot. A new incarnation cannot reset it.
    let before = fs::read(&fixture.config.state_path).unwrap();
    inventory.revision = 4;
    inventory.deployment_incarnation = "incarnation-third".into();
    inventory.nodes[31].node_id = "thirty-third-distinct-node".into();
    assert_eq!(inventory.nodes.len(), 32);
    assert!(
        approve(
            &fixture.config,
            &fixture.inventory_file(&inventory),
            3,
            RUN_A
        )
        .is_err()
    );
    assert_eq!(fs::read(&fixture.config.state_path).unwrap(), before);
    let refused = fixture.engine();
    assert_eq!(refused.state.known_node_ids.len(), 32);
    assert_eq!(refused.state.membership_high_water, 2);
    assert_eq!(refused.state.checkpoint_high_water, 2);
    assert_eq!(refused.expected_run(), RUN_B);
}

#[test]
fn same_inventory_abandoned_refresh_cannot_extend_confirmed_authorization() {
    let fixture = Fixture::new();
    let mut engine = fixture.engine();
    confirm_next(&mut engine);
    let first = checkpoint(&mut engine);
    let original_deadline = engine.fresh_deadline;
    let abandoned = engine.reserve_round().unwrap();
    assert_eq!(abandoned.version, 2);
    let second = checkpoint(&mut engine);
    assert_eq!(second.expires_at, first.expires_at);
    assert_eq!(second.minimum_versions, first.minimum_versions);
    assert_eq!(second.checkpoint_version, first.checkpoint_version + 1);
    assert_eq!(engine.fresh_deadline, original_deadline);
    // Move only the independent monotonic clock to its refusal boundary. A
    // still-valid wall-clock expiry and a newer reservation cannot rescue it.
    engine.fresh_deadline = Some(Instant::now() + RESPONSE_MARGIN);
    assert!(engine.checkpoint(NONCE.into()).is_err());
    assert_eq!(
        engine.state.checkpoint_high_water,
        second.checkpoint_version
    );
}

#[test]
fn invalid_inventory_or_nonce_is_refused_before_consuming_versions() {
    let fixture = Fixture::new();
    let mut engine = fixture.engine();
    let before = engine.store.load().unwrap();
    engine.state.inventory.nodes[0].peer_endpoint = "203.0.113.1:8443".into();
    assert!(engine.reserve_round().is_err());
    assert_eq!(engine.state.membership_high_water, 0);
    assert_eq!(engine.store.load().unwrap(), before);
    assert!(!engine.fatal.load(Ordering::SeqCst));
    engine.state.inventory = fixture.inventory.clone();
    confirm_next(&mut engine);
    for nonce in [
        "short".to_owned(),
        "x".repeat(129),
        "invalid nonce with spaces".into(),
    ] {
        assert!(engine.checkpoint(nonce).is_err());
    }
    assert_eq!(checkpoint(&mut engine).checkpoint_version, 1);
}

#[test]
fn expired_and_future_only_keys_refuse_the_whole_round_without_extending_trust() {
    let fixture = Fixture::new();
    let mut engine = fixture.engine();
    confirm_next(&mut engine);
    let confirmed = checkpoint(&mut engine);
    let deadline = engine.fresh_deadline;
    let durable = engine.store.load().unwrap();
    for future_only in [false, true] {
        engine.state.inventory = fixture.inventory.clone();
        let key = &mut engine.state.inventory.nodes[0].keys[0];
        if future_only {
            key.not_before = Utc::now() + chrono::Duration::minutes(5);
        } else {
            // Inside the structural verifier's clock skew: the authority
            // must still use the runtime's strict expired-key refusal.
            key.expires_at = Utc::now() - chrono::Duration::seconds(1);
        }
        assert!(engine.reserve_round().is_err());
        assert_eq!(engine.state.membership_high_water, 1);
        assert_eq!(engine.store.load().unwrap(), durable);
        assert_eq!(engine.fresh_deadline, deadline);
        assert_eq!(
            engine.state.confirmed.as_ref().unwrap().expires_at,
            confirmed.expires_at
        );
        assert!(!engine.fatal.load(Ordering::SeqCst));
    }
    engine.state.inventory = fixture.inventory.clone();
    let still_bounded = checkpoint(&mut engine);
    assert_eq!(still_bounded.expires_at, confirmed.expires_at);
    assert_eq!(still_bounded.minimum_versions, confirmed.minimum_versions);
}

#[tokio::test]
async fn a_fatal_latch_suppresses_even_a_successfully_persisted_checkpoint() {
    let fixture = Fixture::new();
    let coordinator = fixture.coordinator();
    coordinator
        .call(true, |engine| {
            let round = engine.reserve_round()?;
            engine.confirm(round)
        })
        .await
        .unwrap();
    let fatal = coordinator.fatal.clone();
    let result = coordinator
        .call(false, move |engine| {
            fatal.store(true, Ordering::SeqCst);
            engine.checkpoint(NONCE.into())
        })
        .await;
    assert!(
        result.is_err(),
        "completed bytes escaped after the global fatal latch"
    );
    assert_eq!(
        coordinator
            .engine
            .lock()
            .unwrap()
            .state
            .checkpoint_high_water,
        1,
        "undelivered checkpoint allocation stays spent"
    );
}

#[tokio::test]
async fn external_private_state_mutation_latches_fatal_and_is_not_repaired() {
    let fixture = Fixture::new();
    let coordinator = fixture.coordinator();
    fs::write(&fixture.config.state_path, b"external corrupt state").unwrap();
    assert!(
        coordinator
            .call(true, |engine| engine
                .reserve_round()
                .map(|round| round.version))
            .await
            .is_err()
    );
    assert!(coordinator.fatal.load(Ordering::SeqCst));
    assert!(
        coordinator
            .call(false, |_| -> Result<()> {
                panic!("fatal coordinator ran another operation")
            })
            .await
            .is_err()
    );
    assert_eq!(
        fs::read(&fixture.config.state_path).unwrap(),
        b"external corrupt state"
    );
}

#[tokio::test]
async fn unsafe_state_permissions_make_persistence_failure_permanent() {
    let fixture = Fixture::new();
    let coordinator = fixture.coordinator();
    let before = fs::read(&fixture.config.state_path).unwrap();
    fs::set_permissions(
        &fixture.config.state_path,
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(
        coordinator
            .call(true, |engine| engine
                .reserve_round()
                .map(|round| round.version))
            .await
            .is_err()
    );
    assert!(coordinator.fatal.load(Ordering::SeqCst));
    fs::set_permissions(
        &fixture.config.state_path,
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert!(
        coordinator
            .call(true, |_| -> Result<()> {
                panic!("repairing permissions silently cleared the fatal latch")
            })
            .await
            .is_err()
    );
    assert_eq!(fs::read(&fixture.config.state_path).unwrap(), before);
}

struct ReleaseOnDrop(Option<mpsc::Sender<()>>);

impl ReleaseOnDrop {
    fn release(mut self) {
        self.0.take().unwrap().send(()).unwrap();
    }
}

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

async fn eventually(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(STATE_IO_BUDGET * 3, async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("bounded coordinator transition");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_slow_caller_keeps_its_watchdog_and_real_serializer_permit() {
    let fixture = Fixture::new();
    let coordinator = fixture.coordinator();
    let (entered, started) = tokio::sync::oneshot::channel();
    let (release, blocked) = mpsc::channel();
    let release = ReleaseOnDrop(Some(release));
    let caller_coordinator = coordinator.clone();
    let caller = tokio::spawn(async move {
        caller_coordinator
            .call(false, move |engine| {
                let _ = entered.send(());
                blocked
                    .recv_timeout(STATE_IO_BUDGET * 5)
                    .map_err(|_| "test operation was not released")?;
                engine.reserve_round().map(|round| round.version)
            })
            .await
    });
    tokio::time::timeout(STATE_IO_BUDGET, started)
        .await
        .unwrap()
        .unwrap();
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    eventually(|| coordinator.fatal.load(Ordering::SeqCst)).await;
    assert_eq!(
        coordinator.permit.available_permits(),
        0,
        "timeout must not release the actual task's serializer"
    );
    assert!(
        coordinator
            .call(true, |_| -> Result<()> {
                panic!("a cancelled slow task allowed overlapping state work")
            })
            .await
            .is_err()
    );
    release.release();
    eventually(|| coordinator.permit.available_permits() == 1).await;
    assert!(coordinator.fatal.load(Ordering::SeqCst));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn request_cancellation_alone_does_not_latch_global_failure() {
    let fixture = Fixture::new();
    let coordinator = fixture.coordinator();
    let (entered, started) = tokio::sync::oneshot::channel();
    let (release, blocked) = mpsc::channel();
    let release = ReleaseOnDrop(Some(release));
    let caller_coordinator = coordinator.clone();
    let caller = tokio::spawn(async move {
        caller_coordinator
            .call(false, move |engine| {
                let _ = entered.send(());
                blocked
                    .recv_timeout(STATE_IO_BUDGET * 5)
                    .map_err(|_| "test operation was not released")?;
                engine.reserve_round().map(|round| round.version)
            })
            .await
    });
    tokio::time::timeout(STATE_IO_BUDGET, started)
        .await
        .unwrap()
        .unwrap();
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    release.release();
    eventually(|| coordinator.permit.available_permits() == 1).await;
    let next = coordinator
        .call(true, |engine| {
            engine.reserve_round().map(|round| round.version)
        })
        .await
        .unwrap();
    assert_eq!(
        next, 2,
        "the cancelled caller's completed reservation stays spent"
    );
    assert!(!coordinator.fatal.load(Ordering::SeqCst));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_admission_is_bounded_while_publisher_can_join_the_serializer() {
    let fixture = Fixture::new();
    let coordinator = fixture.coordinator();
    let (entered, started) = tokio::sync::oneshot::channel();
    let (release, blocked) = mpsc::channel();
    let release = ReleaseOnDrop(Some(release));
    let blocking_coordinator = coordinator.clone();
    let blocking = tokio::spawn(async move {
        blocking_coordinator
            .call(true, move |_| {
                let _ = entered.send(());
                blocked
                    .recv_timeout(STATE_IO_BUDGET * 5)
                    .map_err(|_| "test operation was not released")
            })
            .await
    });
    tokio::time::timeout(STATE_IO_BUDGET, started)
        .await
        .unwrap()
        .unwrap();
    let completed = Arc::new(AtomicUsize::new(0));
    let mut callers = Vec::new();
    for _ in 0..32 {
        let coordinator = coordinator.clone();
        let completed = completed.clone();
        callers.push(tokio::spawn(async move {
            coordinator
                .call(false, move |_| {
                    completed.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
                .await
        }));
    }
    eventually(|| coordinator.admission.available_permits() == 0).await;
    assert_eq!(completed.load(Ordering::SeqCst), 0);
    assert_eq!(
        coordinator.call(false, |_| Ok(())).await.unwrap_err(),
        "state admission limit"
    );
    let publisher_coordinator = coordinator.clone();
    let publisher = tokio::spawn(async move {
        publisher_coordinator
            .call(true, |engine| {
                engine.reserve_round().map(|round| round.version)
            })
            .await
    });
    release.release();
    blocking.await.unwrap().unwrap();
    for caller in callers {
        caller.await.unwrap().unwrap();
    }
    assert_eq!(publisher.await.unwrap().unwrap(), 1);
    assert_eq!(completed.load(Ordering::SeqCst), 32);
    assert_eq!(coordinator.admission.available_permits(), 32);
    assert!(!coordinator.fatal.load(Ordering::SeqCst));
}

// Timer-budget proof on a current-thread runtime with a paused Tokio clock.
// Real signing/fsync completes behind explicit barriers before each deliberate
// 400ms timer advance. This proves FIFO and queue budgets, not real-time I/O
// margins; the separate real-stall watchdog tests above remain unchanged.
#[tokio::test]
async fn publisher_survives_three_admitted_durable_checkpoint_operations() {
    async fn poll_once<F: std::future::Future>(
        mut future: std::pin::Pin<&mut F>,
    ) -> Option<F::Output> {
        std::future::poll_fn(|cx| {
            std::task::Poll::Ready(match future.as_mut().poll(cx) {
                std::task::Poll::Ready(value) => Some(value),
                std::task::Poll::Pending => None,
            })
        })
        .await
    }

    // Keep this test runnable while blocking work finishes, preventing Tokio's
    // automatic idle-clock advance. Every polling loop has a real deadline;
    // there is no detached spinning task to survive panic or test cancellation.
    async fn real_wait<F: std::future::Future>(future: F, stage: &str) -> F::Output {
        tokio::pin!(future);
        let started = Instant::now();
        loop {
            if let Some(value) = poll_once(future.as_mut()).await {
                return value;
            }
            assert!(
                started.elapsed() < STATE_IO_BUDGET * 3,
                "real-time fixture watchdog: {stage}"
            );
            tokio::task::yield_now().await;
        }
    }

    struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);
    impl<T> Drop for AbortOnDrop<T> {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    struct ActiveOperation(Arc<AtomicUsize>);
    impl Drop for ActiveOperation {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    let fixture = Fixture::new();
    let coordinator = fixture.coordinator();
    coordinator
        .call(true, |engine| {
            let round = engine.reserve_round()?;
            engine.confirm(round)
        })
        .await
        .unwrap();
    tokio::time::pause();
    let active = Arc::new(AtomicUsize::new(0));
    let completed = Arc::new(AtomicUsize::new(0));
    let overlap = Arc::new(AtomicBool::new(false));
    let queue_residence = Arc::new(Mutex::new(Vec::new()));
    let mut releases = std::collections::VecDeque::new();
    let mut checkpointed = std::collections::VecDeque::new();
    let mut http_tasks = Vec::new();

    for index in 0..3 {
        let caller = coordinator.clone();
        let active = active.clone();
        let completed = completed.clone();
        let overlap = overlap.clone();
        let residence = queue_residence.clone();
        let (written, observed) = tokio::sync::oneshot::channel();
        let (release, blocked) = mpsc::channel();
        releases.push_back(ReleaseOnDrop(Some(release)));
        checkpointed.push_back(observed);
        http_tasks.push(AbortOnDrop(tokio::spawn(async move {
            let queued_at = tokio::time::Instant::now();
            caller
                .call(false, move |engine| {
                    residence.lock().unwrap().push((index, queued_at.elapsed()));
                    if active.fetch_add(1, Ordering::SeqCst) != 0 {
                        overlap.store(true, Ordering::SeqCst);
                    }
                    let _active = ActiveOperation(active);
                    // Perform actual signing and the durable checkpoint write.
                    // Only the intentional hold of its serializer is virtual.
                    let real_io_started = Instant::now();
                    let response =
                        engine.checkpoint(format!("queued-checkpoint-nonce-{index:04}"))?;
                    completed.fetch_add(1, Ordering::SeqCst);
                    let _ = written.send(real_io_started.elapsed());
                    blocked
                        .recv_timeout(STATE_IO_BUDGET * 5)
                        .map_err(|_| "test queue was not released")?;
                    Ok(response)
                })
                .await
        })));
        // On this single async thread, observing the consumed HTTP slot means
        // the call has suspended on the occupied fair serializer (or, for the
        // first call, spawned the actual blocking operation).
        real_wait(
            async {
                while coordinator.admission.available_permits() != 31 - index {
                    tokio::task::yield_now().await;
                }
            },
            "HTTP admission",
        )
        .await;
    }
    let first_io = real_wait(
        checkpointed.pop_front().unwrap(),
        "first durable checkpoint",
    )
    .await
    .unwrap();
    assert_eq!(completed.load(Ordering::SeqCst), 1);
    assert_eq!(active.load(Ordering::SeqCst), 1);
    let publisher_coordinator = coordinator.clone();
    let publisher_active = active.clone();
    let publisher_completed = completed.clone();
    let publisher_overlap = overlap.clone();
    let publisher_residence = Arc::new(Mutex::new(None));
    let observed_residence = publisher_residence.clone();
    let publisher_queued_at = tokio::time::Instant::now();
    let mut publisher = Box::pin(publisher_coordinator.call(true, move |engine| {
        *observed_residence.lock().unwrap() = Some(publisher_queued_at.elapsed());
        if publisher_active.fetch_add(1, Ordering::SeqCst) != 0 {
            publisher_overlap.store(true, Ordering::SeqCst);
        }
        let _active = ActiveOperation(publisher_active);
        if publisher_completed.load(Ordering::SeqCst) != 3 {
            return Err("publisher overtook previously admitted HTTP writes");
        }
        engine.reserve_round().map(|round| round.version)
    }));
    // Poll the actual call to Pending, establishing its fair queue position
    // behind all three HTTP calls rather than inferring it from task startup.
    assert!(poll_once(publisher.as_mut()).await.is_none());
    assert_eq!(coordinator.admission.available_permits(), 29);
    assert_eq!(coordinator.permit.available_permits(), 0);

    let mut real_io_times = vec![first_io];
    let mut responses = Vec::new();
    let mut publisher_result = None;
    for (index, task) in http_tasks.iter_mut().enumerate() {
        if index > 0 {
            real_io_times.push(
                real_wait(checkpointed.pop_front().unwrap(), "next durable checkpoint")
                    .await
                    .unwrap(),
            );
        }
        // Completed signing/fsync and the held permit are established before
        // moving the timer clock; host scheduling/disk delay cannot consume
        // another HTTP call's intentional queue-wait margin.
        tokio::time::advance(Duration::from_millis(400)).await;
        if index == 2 {
            assert_eq!(coordinator.permit.available_permits(), 0);
            // Poll while the final operation still holds the permit. An old
            // one-second publisher budget must expire here, never win a race
            // with the subsequent permit release despite being overdue.
            publisher_result = poll_once(publisher.as_mut()).await;
        }
        releases.pop_front().unwrap().release();
        responses.push(real_wait(&mut task.0, "HTTP completion").await.unwrap());
    }
    let publisher_result = match publisher_result {
        Some(result) => result,
        None => real_wait(publisher.as_mut(), "publisher completion").await,
    };
    let versions: Vec<u64> = responses
        .into_iter()
        .map(|response| {
            serde_json::from_slice::<SignedMembershipCheckpoint>(
                &response.expect("HTTP operation stayed within its own wait and I/O budgets"),
            )
            .unwrap()
            .checkpoint_version
        })
        .collect();
    assert_eq!(versions, [1, 2, 3]);
    assert_eq!(
        *queue_residence.lock().unwrap(),
        [
            (0, Duration::ZERO),
            (1, Duration::from_millis(400)),
            (2, Duration::from_millis(800)),
        ]
    );
    assert_eq!(completed.load(Ordering::SeqCst), 3);
    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert!(!overlap.load(Ordering::SeqCst));
    assert!(!coordinator.fatal.load(Ordering::SeqCst));
    assert_eq!(coordinator.admission.available_permits(), 32);
    assert_eq!(coordinator.permit.available_permits(), 1);
    assert_eq!(
        State::decode(&fs::read(&fixture.config.state_path).unwrap())
            .unwrap()
            .checkpoint_high_water,
        3
    );
    assert_eq!(
        publisher_result.expect(
            "publisher must retain its fair queue position behind admitted bounded HTTP writes"
        ),
        2
    );
    let publisher_wait = publisher_residence.lock().unwrap().unwrap();
    assert_eq!(publisher_wait, Duration::from_millis(1200));
    assert!(publisher_wait > STATE_IO_BUDGET);
    assert!(publisher_wait < PUBLISHER_QUEUE_BUDGET);
    eprintln!(
        "C247 simulated_http_queue_ms=[0,400,800] simulated_publisher_queue_ms={} real_checkpoint_ms={:?}",
        publisher_wait.as_millis(),
        real_io_times
            .iter()
            .map(Duration::as_millis)
            .collect::<Vec<_>>()
    );
}
