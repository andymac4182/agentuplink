//! Live re-keying of this relay's private HTTP/3 peer identity (task rows
//! M8-C28, M8-C45..M8-C47).
//!
//! `docs/cluster.md` "Certificate and key lifecycle" describes a planned
//! rotation: authorize the next key before use, publish a signed record with
//! both keys, wait for verification convergence, switch new handshakes to the
//! next certificate, and retire the previous key after an overlap.  Before
//! this module a relay could not take part: it bound one peer certificate for
//! the life of its process.  [`PeerRekey`] is the explicit state machine that
//! drives the relay's half of that procedure without a restart:
//!
//! 1. **Stage** ([`PeerRekey::stage`]): a new certificate and private key are
//!    loaded *locally*, validated against the peer CA, and held.  Nothing is
//!    served with them and nothing about them leaves the process except the
//!    public SPKI digest, which the operator's membership publisher must
//!    approve.  A relay never authorizes its own key and never writes a key --
//!    private or public -- to Redis.
//! 2. **Switch**: once the verified signed record for this node has approved
//!    the staged SPKI **continuously for the convergence hold**, the relay
//!    binds readiness to that SPKI and installs it for new handshakes in one
//!    step of the membership owner task, which no reconciliation pass
//!    overlaps ([`MembershipRuntime::switch_local_serving_spki`]).  Established
//!    connections keep the identity they negotiated.
//! 3. **Overlap**: the predecessor keeps serving what it already carries.
//!    Pooled outbound connections under it are drained, never reused for new
//!    streams, within the peer drain budget.
//! 4. **Retire**: when the verified record stops approving the predecessor
//!    (the publisher withdrew or revoked it) or the overlap elapses, every
//!    remaining outbound connection under it is closed and the machine returns
//!    to `Stable`.
//!
//! Readiness is bound only to the **served** key, never to a staged one: a
//! relay whose served key the record stops approving still fails closed, as
//! before.

use std::{
    collections::VecDeque,
    fmt,
    future::Future,
    pin::Pin,
    sync::{Arc, Weak},
    time::Duration,
};

use tokio::{
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
    time::Instant,
};
use tokio_util::sync::CancellationToken;
use tunnel_transport::{PeerClient, PeerIdentityError, RotatingPeerIdentity, StagedPeerIdentity};

use crate::{
    ClusterConfig,
    membership_runtime::{LocalKeyApproval, LocalServingSwitchError, MembershipRuntime},
    owner_task::OwnerTask,
};

/// The default overlap after a switch before the predecessor is retired
/// locally even if the record still approves it (`docs/cluster.md`:
/// "initially ten minutes").
pub const DEFAULT_PEER_REKEY_OVERLAP: Duration = Duration::from_secs(600);

/// How often the rotation state machine re-reads verified membership state.
pub const DEFAULT_PEER_REKEY_TICK: Duration = Duration::from_secs(1);

/// How many retired SPKIs a process remembers in order to refuse restaging
/// them.  Bounded: a process that rotates more often than this forgets the
/// oldest, which is still far beyond any planned cadence.
pub const MAX_RETIRED_SPKIS: usize = 8;

/// Rotation timing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerRekeyConfig {
    /// How long the verified record must have approved the staged key,
    /// continuously, before new handshakes present it.  The conservative
    /// default is one full membership record lifetime plus the accepted clock
    /// skew: after that, every peer still Ready must hold a record at least as
    /// new as the one that first approved the staged key.
    pub convergence_hold: Duration,
    /// How long the predecessor may keep serving after the switch before it
    /// is retired locally.
    pub overlap: Duration,
    /// State machine tick.
    pub tick: Duration,
}

impl PeerRekeyConfig {
    /// Derive the conservative defaults from the operator's cluster settings,
    /// then apply the optional overrides it carries.
    #[must_use]
    pub fn from_cluster_config(cluster: &ClusterConfig) -> Self {
        let default_hold = Duration::from_secs(
            cluster
                .membership_record_lifetime_seconds
                .saturating_add(cluster.max_clock_skew_seconds),
        );
        Self {
            convergence_hold: cluster
                .peer_rekey_convergence_seconds
                .map_or(default_hold, Duration::from_secs),
            overlap: cluster
                .peer_rekey_overlap_seconds
                .map_or(DEFAULT_PEER_REKEY_OVERLAP, Duration::from_secs),
            tick: DEFAULT_PEER_REKEY_TICK,
        }
    }
}

/// The rotation phase, as a bounded label set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerRekeyPhase {
    /// One identity; nothing staged.
    Stable,
    /// A successor is loaded locally and awaits approval and convergence.
    Staged,
    /// A switch is in progress: the staged identity is being bound and
    /// installed by the membership owner task.  Staging is refused
    /// here, so a trigger that arrives mid-switch is reported rather than
    /// silently overwritten when the switch completes.
    Switching,
    /// The successor serves; the predecessor is draining.
    Overlap,
    /// The predecessor is being retired: its remaining connections are being
    /// closed, which can take the peer drain budget.  Staging is refused.
    Retiring,
}

impl PeerRekeyPhase {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Staged => "staged",
            Self::Switching => "switching",
            Self::Overlap => "overlap",
            Self::Retiring => "retiring",
        }
    }
}

/// Why the predecessor was retired.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerRekeyRetirement {
    /// The verified record no longer approves the predecessor.
    Withdrawn,
    /// The configured overlap elapsed first.
    OverlapElapsed,
}

impl PeerRekeyRetirement {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Withdrawn => "withdrawn",
            Self::OverlapElapsed => "overlap_elapsed",
        }
    }
}

/// Why a staging request was refused.
#[derive(Debug)]
pub enum PeerRekeyError {
    /// A rotation is already staged or overlapping; finish it first.
    InProgress(&'static str),
    /// The staged key is the one already served.
    SameKey,
    /// The staged key was retired by an earlier rotation on this process.
    /// Rolling back to a retired key is refused: a key is retired because
    /// it is being replaced, possibly because it is suspect, so it takes a
    /// fresh key (or a restart with the operator's explicit configuration).
    Retired,
    /// The candidate identity was refused before staging.
    Identity(PeerIdentityError),
}

impl fmt::Display for PeerRekeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InProgress(phase) => write!(
                formatter,
                "a peer-key rotation is already in progress (phase {phase})"
            ),
            Self::SameKey => formatter.write_str("the staged peer key is the key already served"),
            Self::Retired => formatter.write_str(
                "the staged peer key was retired by an earlier rotation and cannot be restaged",
            ),
            Self::Identity(error) => fmt::Display::fmt(error, formatter),
        }
    }
}

impl std::error::Error for PeerRekeyError {}

impl From<PeerIdentityError> for PeerRekeyError {
    fn from(error: PeerIdentityError) -> Self {
        Self::Identity(error)
    }
}

/// Payload-free, key-free rotation diagnostics.  Every digest is a public
/// SPKI pin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerRekeySnapshot {
    pub phase: PeerRekeyPhase,
    pub serving_spki: String,
    pub serving_generation: u64,
    pub staged_spki: Option<String>,
    /// How the verified record treats the staged key, when one is staged.
    pub staged_approval: Option<&'static str>,
    pub previous_spki: Option<String>,
    pub stages: u64,
    pub switches: u64,
    pub retirements: u64,
    pub overlap_elapsed_while_approved: u64,
    pub last_retirement: Option<PeerRekeyRetirement>,
    pub last_refusal: Option<&'static str>,
    pub draining_connections: usize,
}

struct StagedState {
    identity: StagedPeerIdentity,
    spki: String,
    approved_since: Option<Instant>,
    last_approval: LocalKeyApproval,
}

struct OverlapState {
    previous_spki: String,
    serving_generation: u64,
    switched_at: Instant,
}

enum RekeyState {
    Stable,
    Staged(Box<StagedState>),
    Switching,
    Overlap(OverlapState),
    Retiring,
}

/// What moves the rotation from one phase to the next.
enum RekeyEvent {
    /// A validated successor was accepted for staging.
    Stage(Box<StagedState>),
    /// The signed record revoked the staged key.
    AbandonStaged,
    /// The staged key is handed to the membership owner to be served.
    BeginSwitch,
    /// The membership owner bound and installed the successor.
    SwitchInstalled(OverlapState),
    /// The switch was refused; the identity is staged again if the
    /// transport never consumed it.
    SwitchRefused(Option<Box<StagedState>>),
    /// The predecessor's remaining connections start to be closed.
    BeginRetire,
    /// The predecessor's connections are closed.
    Retired,
}

/// The data of the state a transition left.
enum Left {
    Nothing,
    Staged(Box<StagedState>),
    Overlap(OverlapState),
}

impl RekeyState {
    const fn phase(&self) -> PeerRekeyPhase {
        match self {
            Self::Stable => PeerRekeyPhase::Stable,
            Self::Staged(_) => PeerRekeyPhase::Staged,
            Self::Switching => PeerRekeyPhase::Switching,
            Self::Overlap(_) => PeerRekeyPhase::Overlap,
            Self::Retiring => PeerRekeyPhase::Retiring,
        }
    }

    /// The only place the phase changes.  An event that is not legal in
    /// the current state is refused and the state is handed back unchanged.
    fn on_event(self, event: RekeyEvent) -> Result<(Self, Left), Self> {
        match (self, event) {
            (Self::Stable, RekeyEvent::Stage(staged)) => Ok((Self::Staged(staged), Left::Nothing)),
            (Self::Staged(staged), RekeyEvent::AbandonStaged) => {
                Ok((Self::Stable, Left::Staged(staged)))
            }
            (Self::Staged(staged), RekeyEvent::BeginSwitch) => {
                Ok((Self::Switching, Left::Staged(staged)))
            }
            (Self::Switching, RekeyEvent::SwitchInstalled(overlap)) => {
                Ok((Self::Overlap(overlap), Left::Nothing))
            }
            (Self::Switching, RekeyEvent::SwitchRefused(Some(staged))) => {
                Ok((Self::Staged(staged), Left::Nothing))
            }
            (Self::Switching, RekeyEvent::SwitchRefused(None)) => Ok((Self::Stable, Left::Nothing)),
            (Self::Overlap(overlap), RekeyEvent::BeginRetire) => {
                Ok((Self::Retiring, Left::Overlap(overlap)))
            }
            (Self::Retiring, RekeyEvent::Retired) => Ok((Self::Stable, Left::Nothing)),
            (state, _) => Err(state),
        }
    }
}

#[derive(Default)]
struct Counters {
    stages: u64,
    switches: u64,
    retirements: u64,
    /// Retirements by overlap timeout while the record still approved the
    /// predecessor: peers still trust it until the publisher withdraws it.
    overlap_elapsed_while_approved: u64,
    /// Most recently retired SPKIs, bounded by [`MAX_RETIRED_SPKIS`].
    retired: VecDeque<String>,
    last_retirement: Option<PeerRekeyRetirement>,
    last_refusal: Option<&'static str>,
}

/// How many commands may wait for the rotation owner task.  A caller waits
/// while the queue is full.
const REKEY_COMMAND_QUEUE: usize = 16;

/// How many ticks the owner holds behind the switch or retirement in
/// flight.  At this bound the owner stops taking commands until that pass
/// completes, so further callers wait in the bounded command queue instead.
/// The relay itself runs one ticker, which waits for each tick.
const MAX_WAITING_TICKS: usize = 16;

/// The relay's peer-key rotation coordinator.
///
/// One owning task holds the rotation state.  Staging, the retirement test
/// seam and ticks are commands on its bounded queue; the phase and the
/// diagnostics are read from the snapshot it publishes after every change.
/// A switch or a retirement runs as the owner's one child future, so the
/// owner keeps answering staging requests and readers keep seeing the phase
/// while a retirement takes the peer drain budget, and a switch/retire pass
/// is never interleaved with another because the owner holds at most one.
pub struct PeerRekey {
    shared: Arc<RekeyShared>,
    owner: OwnerTask<RekeyCommand>,
}

/// What the coordinator handle, its owning task and a pass share.  Only the
/// owning task writes `published`.
struct RekeyShared {
    identity: Arc<RotatingPeerIdentity>,
    membership: Arc<MembershipRuntime>,
    peer_client: Option<PeerClient>,
    peer_ca_pem: Vec<u8>,
    config: PeerRekeyConfig,
    published: watch::Sender<Arc<RekeyView>>,
}

/// The rotation state readers sample.
struct RekeyView {
    phase: PeerRekeyPhase,
    staged_spki: Option<String>,
    staged_approval: Option<&'static str>,
    previous_spki: Option<String>,
    stages: u64,
    switches: u64,
    retirements: u64,
    overlap_elapsed_while_approved: u64,
    last_retirement: Option<PeerRekeyRetirement>,
    last_refusal: Option<&'static str>,
}

impl RekeyView {
    fn of(state: &RekeyState, counters: &Counters) -> Self {
        let (staged_spki, staged_approval, previous_spki) = match state {
            RekeyState::Stable | RekeyState::Switching | RekeyState::Retiring => (None, None, None),
            RekeyState::Staged(staged) => (
                Some(staged.spki.clone()),
                Some(staged.last_approval.label()),
                None,
            ),
            RekeyState::Overlap(overlap) => (None, None, Some(overlap.previous_spki.clone())),
        };
        Self {
            phase: state.phase(),
            staged_spki,
            staged_approval,
            previous_spki,
            stages: counters.stages,
            switches: counters.switches,
            retirements: counters.retirements,
            overlap_elapsed_while_approved: counters.overlap_elapsed_while_approved,
            last_retirement: counters.last_retirement,
            last_refusal: counters.last_refusal,
        }
    }
}

/// One request to the rotation owner task.
enum RekeyCommand {
    Stage {
        staged: StagedPeerIdentity,
        reply: oneshot::Sender<Result<String, PeerRekeyError>>,
    },
    /// Record a refusal decided before anything reached the owner.
    Refuse {
        label: &'static str,
        reply: oneshot::Sender<()>,
    },
    HoldNextRetirement {
        hold: Arc<RetireHold>,
        reply: oneshot::Sender<()>,
    },
    Tick {
        reply: oneshot::Sender<()>,
    },
}

/// A test seam that parks a retirement where it closes the predecessor's
/// connections, which can take the peer drain budget in production.  Never
/// installed by the relay itself.
#[doc(hidden)]
#[derive(Default)]
pub struct RetireHold {
    pub entered: tokio::sync::Notify,
    pub release: tokio::sync::Notify,
}

impl fmt::Debug for PeerRekey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerRekey")
            .field("phase", &self.phase())
            .field("identity", &self.shared.identity)
            .finish_non_exhaustive()
    }
}

impl PeerRekey {
    /// Build a coordinator for a relay whose peer server and client
    /// configurations both resolve through `identity`.  `peer_client` is the
    /// relay's outbound pool, which must have been built
    /// [`with_local_identity`](PeerClient::with_local_identity) on the same
    /// slot so superseded connections drain.
    #[must_use]
    pub fn new(
        identity: Arc<RotatingPeerIdentity>,
        membership: Arc<MembershipRuntime>,
        peer_client: Option<PeerClient>,
        peer_ca_pem: Vec<u8>,
        config: PeerRekeyConfig,
    ) -> Arc<Self> {
        Arc::new(Self {
            shared: Arc::new(RekeyShared {
                identity,
                membership,
                peer_client,
                peer_ca_pem,
                config,
                published: watch::Sender::new(Arc::new(RekeyView::of(
                    &RekeyState::Stable,
                    &Counters::default(),
                ))),
            }),
            owner: OwnerTask::new(),
        })
    }

    /// Send one command to the owning task, starting it on first use, and
    /// wait for its answer.  `None` means the owning task is gone.
    async fn request<R>(
        &self,
        command: impl FnOnce(oneshot::Sender<R>) -> RekeyCommand,
    ) -> Option<R> {
        let shared = Arc::clone(&self.shared);
        self.owner
            .request(
                REKEY_COMMAND_QUEUE,
                move |commands| RekeyOwner::new(&shared).run(commands),
                command,
            )
            .await
    }

    fn view(&self) -> Arc<RekeyView> {
        Arc::clone(&self.shared.published.borrow())
    }

    /// Park the next retirement at its connection close until released.
    #[doc(hidden)]
    pub async fn hold_next_retirement(&self, hold: Arc<RetireHold>) {
        let _ = self
            .request(|reply| RekeyCommand::HoldNextRetirement { hold, reply })
            .await;
    }

    /// The current phase.
    #[must_use]
    pub fn phase(&self) -> PeerRekeyPhase {
        self.view().phase
    }

    /// The configured timing.
    #[must_use]
    pub fn config(&self) -> PeerRekeyConfig {
        self.shared.config
    }

    /// Validate PEM input against the local peer CA and stage it.
    ///
    /// The caller clears its PEM buffers afterwards; this keeps only the
    /// parsed signing key, in memory.
    pub async fn stage_pem(
        &self,
        certificate_pem: &[u8],
        private_key_pem: &[u8],
    ) -> Result<String, PeerRekeyError> {
        match StagedPeerIdentity::from_pem(
            certificate_pem,
            private_key_pem,
            &self.shared.peer_ca_pem,
        ) {
            Ok(staged) => self.stage(staged).await,
            Err(error) => {
                let _ = self
                    .request(|reply| RekeyCommand::Refuse {
                        label: "staged_identity_invalid",
                        reply,
                    })
                    .await;
                Err(error.into())
            }
        }
    }

    /// Stage an already validated successor identity and return its public
    /// SPKI digest -- the value the membership publisher must approve.
    ///
    /// Answered while a switch or a retirement is in flight: staging is then
    /// refused as in progress rather than made to wait for it.
    pub async fn stage(&self, staged: StagedPeerIdentity) -> Result<String, PeerRekeyError> {
        self.request(|reply| RekeyCommand::Stage { staged, reply })
            .await
            // The owning task is gone with its runtime: nothing was staged.
            .unwrap_or(Err(PeerRekeyError::InProgress("stopped")))
    }

    /// Advance the state machine once from verified membership state.
    ///
    /// Returns when the switch or retirement this tick started, if any, has
    /// completed.  A tick that arrives while one is in flight waits for it
    /// and is then evaluated in turn.
    pub async fn tick(&self) -> PeerRekeySnapshot {
        let _ = self.request(|reply| RekeyCommand::Tick { reply }).await;
        self.snapshot()
    }

    /// Payload-free rotation diagnostics.
    #[must_use]
    pub fn snapshot(&self) -> PeerRekeySnapshot {
        let view = self.view();
        PeerRekeySnapshot {
            phase: view.phase,
            serving_spki: self.shared.identity.current_spki().to_hex(),
            serving_generation: self.shared.identity.generation(),
            staged_spki: view.staged_spki.clone(),
            staged_approval: view.staged_approval,
            previous_spki: view.previous_spki.clone(),
            stages: view.stages,
            switches: view.switches,
            retirements: view.retirements,
            overlap_elapsed_while_approved: view.overlap_elapsed_while_approved,
            last_retirement: view.last_retirement,
            last_refusal: view.last_refusal,
            draining_connections: self
                .shared
                .peer_client
                .as_ref()
                .map_or(0, PeerClient::draining_connection_count),
        }
    }

    /// Run the state machine every `config.tick` until `cancel` fires.
    pub fn spawn(self: &Arc<Self>, cancel: CancellationToken) -> JoinHandle<()> {
        let rekey = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(rekey.shared.config.tick);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    () = cancel.cancelled() => return,
                    _ = interval.tick() => {
                        rekey.tick().await;
                    }
                }
            }
        })
    }
}

enum Action {
    None,
    Switch,
    AbandonRevoked,
    Retire(PeerRekeyRetirement),
    RetireStillApproved,
}

/// A staged identity on its way to the membership owner.  If the
/// installation never takes it -- the switch was refused first -- dropping
/// this hands the identity back so it can be staged again.
struct IdentityInFlight {
    identity: Option<StagedPeerIdentity>,
    unused: Option<oneshot::Sender<StagedPeerIdentity>>,
}

impl IdentityInFlight {
    fn take(&mut self) -> Option<StagedPeerIdentity> {
        self.unused = None;
        self.identity.take()
    }
}

impl Drop for IdentityInFlight {
    fn drop(&mut self) {
        if let (Some(identity), Some(unused)) = (self.identity.take(), self.unused.take()) {
            let _ = unused.send(identity);
        }
    }
}

/// What a finished switch hands back to the owning task.
struct SwitchDone {
    previous_spki: String,
    spki: String,
    approved_since: Option<Instant>,
    result: Result<u64, LocalServingSwitchError<PeerIdentityError>>,
    /// The staged identity, if the transport never consumed it.
    unconsumed: Option<StagedPeerIdentity>,
}

/// What a finished retirement hands back to the owning task.
struct RetireDone {
    previous_spki: String,
    cause: PeerRekeyRetirement,
    closed: usize,
}

enum PassDone {
    Switch(Box<SwitchDone>),
    Retire(RetireDone),
}

/// The one switch or retirement in flight and the tick waiting for it.
struct InFlight {
    work: Pin<Box<dyn Future<Output = PassDone> + Send>>,
    reply: oneshot::Sender<()>,
}

/// Drive the pass in flight to completion.  Pending for ever while there is
/// none.
async fn drive(pass: &mut Option<InFlight>) -> PassDone {
    match pass.as_mut() {
        Some(pass) => pass.work.as_mut().await,
        None => std::future::pending().await,
    }
}

async fn switch_pass(shared: Arc<RekeyShared>, staged: Box<StagedState>) -> PassDone {
    let previous_spki = shared.identity.current_spki().to_hex();
    let StagedState {
        identity: staged_identity,
        spki,
        approved_since,
        last_approval: _,
    } = *staged;
    let (unused, mut returned) = oneshot::channel();
    let mut in_flight = IdentityInFlight {
        identity: Some(staged_identity),
        unused: Some(unused),
    };
    let identity = Arc::clone(&shared.identity);
    let result = shared
        .membership
        .switch_local_serving_spki(&spki, move || {
            let staged = in_flight.take().ok_or(PeerIdentityError::KeyMismatch)?;
            identity.install(staged)
        })
        .await;
    PassDone::Switch(Box::new(SwitchDone {
        previous_spki,
        spki,
        approved_since,
        result,
        // The installation closure has been run or dropped by now, so an
        // identity it never took has already been handed back.
        unconsumed: returned.try_recv().ok(),
    }))
}

async fn retire_pass(
    shared: Arc<RekeyShared>,
    hold: Option<Arc<RetireHold>>,
    previous_spki: String,
    generation: u64,
    cause: PeerRekeyRetirement,
) -> PassDone {
    if let Some(hold) = hold {
        hold.entered.notify_one();
        hold.release.notified().await;
    }
    let closed = match &shared.peer_client {
        Some(client) => client.retire_local_generations_before(generation).await,
        None => 0,
    };
    PassDone::Retire(RetireDone {
        previous_spki,
        cause,
        closed,
    })
}

/// The task that owns the rotation state.
///
/// It holds the shared half weakly, so dropping the last coordinator handle
/// releases the membership runtime and the transport handles at once rather
/// than when this task is next polled.  Only a pass in flight holds it
/// strongly, until it completes.
struct RekeyOwner {
    shared: Weak<RekeyShared>,
    state: RekeyState,
    counters: Counters,
    retire_hold: Option<Arc<RetireHold>>,
    pass: Option<InFlight>,
    waiting_ticks: VecDeque<oneshot::Sender<()>>,
}

impl RekeyOwner {
    fn new(shared: &Arc<RekeyShared>) -> Self {
        Self {
            shared: Arc::downgrade(shared),
            state: RekeyState::Stable,
            counters: Counters::default(),
            retire_hold: None,
            pass: None,
            waiting_ticks: VecDeque::new(),
        }
    }

    async fn run(mut self, mut commands: mpsc::Receiver<RekeyCommand>) {
        let mut open = true;
        // After the last handle is gone a pass still in flight is driven to
        // completion rather than abandoned half-way.
        while open || self.pass.is_some() {
            tokio::select! {
                command = commands.recv(),
                    if open && self.waiting_ticks.len() < MAX_WAITING_TICKS =>
                {
                    match command {
                        Some(command) => self.on_command(command),
                        None => open = false,
                    }
                }
                done = drive(&mut self.pass), if self.pass.is_some() => self.on_pass_done(done),
            }
        }
    }

    /// Publish the state as it is now.  Every command is answered after this.
    fn publish(&self) {
        // With no coordinator handle left there is no reader to publish to.
        if let Some(shared) = self.shared.upgrade() {
            shared
                .published
                .send_replace(Arc::new(RekeyView::of(&self.state, &self.counters)));
        }
    }

    /// Apply `event` through the transition function.  `None` means the
    /// event was not legal in the current state, which is left unchanged.
    fn apply(&mut self, event: RekeyEvent) -> Option<Left> {
        match std::mem::replace(&mut self.state, RekeyState::Stable).on_event(event) {
            Ok((next, left)) => {
                self.state = next;
                Some(left)
            }
            Err(unchanged) => {
                self.state = unchanged;
                None
            }
        }
    }

    fn refuse(&mut self, label: &'static str) {
        self.counters.last_refusal = Some(label);
    }

    fn on_command(&mut self, command: RekeyCommand) {
        // A command is sent through a coordinator handle, which holds the
        // shared half; without one the dropped reply reads as stopped.
        let Some(shared) = self.shared.upgrade() else {
            return;
        };
        match command {
            RekeyCommand::Stage { staged, reply } => {
                let result = self.stage(&shared, staged);
                self.publish();
                let _ = reply.send(result);
            }
            RekeyCommand::Refuse { label, reply } => {
                self.refuse(label);
                self.publish();
                let _ = reply.send(());
            }
            RekeyCommand::HoldNextRetirement { hold, reply } => {
                self.retire_hold = Some(hold);
                let _ = reply.send(());
            }
            RekeyCommand::Tick { reply } => {
                if self.pass.is_some() || !self.waiting_ticks.is_empty() {
                    self.waiting_ticks.push_back(reply);
                } else {
                    self.tick(&shared, reply);
                }
            }
        }
    }

    fn stage(
        &mut self,
        shared: &RekeyShared,
        staged: StagedPeerIdentity,
    ) -> Result<String, PeerRekeyError> {
        if let Err(error) = shared.identity.check_replacement(&staged) {
            self.refuse("staged_identity_mismatch");
            return Err(error.into());
        }
        let spki = staged.spki_sha256().to_hex();
        if !matches!(self.state, RekeyState::Stable) {
            let phase = self.state.phase().label();
            self.refuse("rotation_in_progress");
            return Err(PeerRekeyError::InProgress(phase));
        }
        if spki == shared.identity.current_spki().to_hex() {
            self.refuse("staged_same_key");
            return Err(PeerRekeyError::SameKey);
        }
        if self.counters.retired.iter().any(|retired| retired == &spki) {
            self.refuse("staged_retired_key");
            return Err(PeerRekeyError::Retired);
        }
        let staged = RekeyEvent::Stage(Box::new(StagedState {
            identity: staged,
            spki: spki.clone(),
            approved_since: None,
            last_approval: LocalKeyApproval::Absent,
        }));
        if self.apply(staged).is_none() {
            // Unreachable: the state was `Stable` just above.
            self.refuse("rotation_in_progress");
            return Err(PeerRekeyError::InProgress(self.state.phase().label()));
        }
        self.counters.stages += 1;
        tracing::info!(
            phase = "staged",
            staged_spki_sha256 = %spki,
            serving_spki_sha256 = %shared.identity.current_spki(),
            "peer identity staged; awaiting a signed membership record approving it"
        );
        Ok(spki)
    }

    /// Decide what this tick does from verified membership state.
    fn evaluate(&mut self, shared: &RekeyShared, now: Instant) -> Action {
        match &mut self.state {
            RekeyState::Stable | RekeyState::Switching | RekeyState::Retiring => Action::None,
            RekeyState::Staged(staged) => {
                let approval = shared.membership.local_key_approval(&staged.spki);
                staged.last_approval = approval;
                match approval {
                    LocalKeyApproval::Approved { .. } => {
                        let since = *staged.approved_since.get_or_insert(now);
                        // M8-C65: the publisher withdrew the served key
                        // before the hold elapsed. The relay is already
                        // unready (`MissingLocalKey`) and nothing it serves
                        // is approved any more; peers converging on the
                        // same record reject the predecessor too, so the
                        // hold protects nobody and waiting it out only
                        // prolongs unreadiness. Switch now to the key the
                        // same verified record approves.
                        let served_withdrawn = matches!(
                            shared
                                .membership
                                .local_key_approval(&shared.identity.current_spki().to_hex()),
                            LocalKeyApproval::Absent
                                | LocalKeyApproval::Revoked
                                | LocalKeyApproval::OutsideWindow
                        );
                        if served_withdrawn
                            || now.saturating_duration_since(since)
                                >= shared.config.convergence_hold
                        {
                            Action::Switch
                        } else {
                            Action::None
                        }
                    }
                    LocalKeyApproval::Revoked => Action::AbandonRevoked,
                    // A transient unready state (a failed catalog read, a
                    // checkpoint refresh in flight) is not an observation
                    // that approval was lost: it neither advances the
                    // switch nor restarts the hold.  Peers converge on the
                    // record whether or not this relay can read it right
                    // now, and the switch itself still requires this relay
                    // to be Ready with a record approving the key.
                    LocalKeyApproval::NotReady => Action::None,
                    // Observed unapproved while Ready: the hold restarts.
                    LocalKeyApproval::Absent | LocalKeyApproval::OutsideWindow => {
                        staged.approved_since = None;
                        Action::None
                    }
                }
            }
            RekeyState::Overlap(overlap) => {
                match shared.membership.local_key_approval(&overlap.previous_spki) {
                    LocalKeyApproval::Absent
                    | LocalKeyApproval::Revoked
                    | LocalKeyApproval::OutsideWindow => {
                        Action::Retire(PeerRekeyRetirement::Withdrawn)
                    }
                    // A transient unready state is not evidence the
                    // predecessor was withdrawn.
                    approval @ (LocalKeyApproval::NotReady | LocalKeyApproval::Approved { .. }) => {
                        if now.saturating_duration_since(overlap.switched_at)
                            >= shared.config.overlap
                        {
                            if approval.is_approved() {
                                Action::RetireStillApproved
                            } else {
                                Action::Retire(PeerRekeyRetirement::OverlapElapsed)
                            }
                        } else {
                            Action::None
                        }
                    }
                }
            }
        }
    }

    /// Advance the state machine once.  `reply` is answered when the tick is
    /// complete: at once, or when the pass it starts has finished.
    fn tick(&mut self, shared: &Arc<RekeyShared>, reply: oneshot::Sender<()>) {
        match self.evaluate(shared, Instant::now()) {
            Action::None => {}
            Action::AbandonRevoked => {
                if let Some(Left::Staged(staged)) = self.apply(RekeyEvent::AbandonStaged) {
                    tracing::warn!(
                        phase = "stable",
                        staged_spki_sha256 = %staged.spki,
                        "staged peer identity was revoked by the signed record; discarded"
                    );
                }
                self.refuse("staged_key_revoked");
            }
            Action::Switch => return self.begin_switch(shared, reply),
            Action::Retire(cause) => return self.begin_retire(shared, cause, reply),
            Action::RetireStillApproved => {
                self.counters.overlap_elapsed_while_approved += 1;
                tracing::warn!(
                    phase = "overlap",
                    "the rotation overlap elapsed while the signed record still approves the \
                     predecessor key; this relay stops using it, but peers keep trusting it \
                     until the membership publisher withdraws it"
                );
                return self.begin_retire(shared, PeerRekeyRetirement::OverlapElapsed, reply);
            }
        }
        self.publish();
        let _ = reply.send(());
    }

    fn begin_switch(&mut self, shared: &Arc<RekeyShared>, reply: oneshot::Sender<()>) {
        let Some(Left::Staged(staged)) = self.apply(RekeyEvent::BeginSwitch) else {
            self.publish();
            let _ = reply.send(());
            return;
        };
        self.publish();
        self.pass = Some(InFlight {
            work: Box::pin(switch_pass(Arc::clone(shared), staged)),
            reply,
        });
    }

    fn begin_retire(
        &mut self,
        shared: &Arc<RekeyShared>,
        cause: PeerRekeyRetirement,
        reply: oneshot::Sender<()>,
    ) {
        let Some(Left::Overlap(overlap)) = self.apply(RekeyEvent::BeginRetire) else {
            self.publish();
            let _ = reply.send(());
            return;
        };
        // Record the key as retired before the pass starts, so no trigger
        // can restage it while its connections are still being closed; the
        // `Retiring` phase additionally refuses any staging until then.
        if self.counters.retired.len() >= MAX_RETIRED_SPKIS {
            self.counters.retired.pop_front();
        }
        self.counters
            .retired
            .push_back(overlap.previous_spki.clone());
        let hold = self.retire_hold.take();
        self.publish();
        self.pass = Some(InFlight {
            work: Box::pin(retire_pass(
                Arc::clone(shared),
                hold,
                overlap.previous_spki,
                overlap.serving_generation,
                cause,
            )),
            reply,
        });
    }

    fn on_pass_done(&mut self, done: PassDone) {
        match done {
            PassDone::Switch(done) => self.finish_switch(*done),
            PassDone::Retire(done) => self.finish_retire(done),
        }
        self.publish();
        if let Some(pass) = self.pass.take() {
            let _ = pass.reply.send(());
        }
        // Ticks that waited for this pass are evaluated in turn; one that
        // starts a pass of its own leaves the rest waiting behind it.
        while self.pass.is_none() {
            let Some(reply) = self.waiting_ticks.pop_front() else {
                break;
            };
            // With the coordinator handle gone no waiting tick has a caller.
            let Some(shared) = self.shared.upgrade() else {
                self.waiting_ticks.clear();
                break;
            };
            self.tick(&shared, reply);
        }
    }

    fn finish_switch(&mut self, done: SwitchDone) {
        let SwitchDone {
            previous_spki,
            spki,
            approved_since,
            result,
            unconsumed,
        } = done;
        match result {
            Ok(generation) => {
                self.apply(RekeyEvent::SwitchInstalled(OverlapState {
                    previous_spki: previous_spki.clone(),
                    serving_generation: generation,
                    switched_at: Instant::now(),
                }));
                self.counters.switches += 1;
                tracing::info!(
                    phase = "overlap",
                    serving_spki_sha256 = %spki,
                    previous_spki_sha256 = %previous_spki,
                    serving_generation = generation,
                    "peer identity switched; new handshakes present the successor"
                );
            }
            Err(error) => {
                let label = match &error {
                    LocalServingSwitchError::InvalidDigest => "switch_invalid_digest",
                    LocalServingSwitchError::NotApproved(_) => "switch_not_approved",
                    LocalServingSwitchError::Install(_) => "switch_install_failed",
                };
                // Put the staged identity back (if install never consumed it).
                // A refusal because the runtime was momentarily not Ready keeps
                // the hold already served; any other refusal restarts it.
                let keep_hold = matches!(
                    error,
                    LocalServingSwitchError::NotApproved(LocalKeyApproval::NotReady)
                );
                // With no identity handed back, the transport consumed and
                // refused it: nothing is staged any more, and the operator
                // must stage again.
                self.apply(RekeyEvent::SwitchRefused(unconsumed.map(|identity| {
                    Box::new(StagedState {
                        identity,
                        spki,
                        approved_since: keep_hold.then_some(approved_since).flatten(),
                        last_approval: LocalKeyApproval::NotReady,
                    })
                })));
                self.refuse(label);
                tracing::warn!(reason = label, "peer identity switch refused");
            }
        }
    }

    fn finish_retire(&mut self, done: RetireDone) {
        self.counters.retirements += 1;
        self.counters.last_retirement = Some(done.cause);
        self.apply(RekeyEvent::Retired);
        tracing::info!(
            phase = "stable",
            retired_spki_sha256 = %done.previous_spki,
            cause = done.cause.label(),
            closed_connections = done.closed,
            "previous peer identity retired"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn overlap() -> OverlapState {
        OverlapState {
            previous_spki: "previous".to_owned(),
            serving_generation: 2,
            switched_at: Instant::now(),
        }
    }

    fn phase_after(state: RekeyState, event: RekeyEvent) -> Result<PeerRekeyPhase, PeerRekeyPhase> {
        state
            .on_event(event)
            .map(|(next, _)| next.phase())
            .map_err(|unchanged| unchanged.phase())
    }

    /// Every legal transition that needs no staged private key, and that
    /// each state refuses the events of the others unchanged.  The staged
    /// transitions (`Stable -> Staged -> Switching`, the refusal back to
    /// `Staged`, and the revoked discard) need a real identity and are
    /// driven end to end by `tests/m7_readiness.rs`.
    #[test]
    fn rekey_transition_table() {
        use PeerRekeyPhase::{Overlap, Retiring, Stable, Switching};

        assert_eq!(
            phase_after(
                RekeyState::Switching,
                RekeyEvent::SwitchInstalled(overlap())
            ),
            Ok(Overlap)
        );
        assert_eq!(
            phase_after(RekeyState::Switching, RekeyEvent::SwitchRefused(None)),
            Ok(Stable)
        );
        assert_eq!(
            phase_after(RekeyState::Overlap(overlap()), RekeyEvent::BeginRetire),
            Ok(Retiring)
        );
        assert_eq!(
            phase_after(RekeyState::Retiring, RekeyEvent::Retired),
            Ok(Stable)
        );
        // Leaving `Overlap` hands back the predecessor it was draining.
        assert!(matches!(
            RekeyState::Overlap(overlap()).on_event(RekeyEvent::BeginRetire),
            Ok((RekeyState::Retiring, Left::Overlap(left))) if left.previous_spki == "previous"
        ));

        // Illegal events leave the state as it was.
        for (state, event, unchanged) in [
            (RekeyState::Stable, RekeyEvent::BeginSwitch, Stable),
            (RekeyState::Stable, RekeyEvent::AbandonStaged, Stable),
            (RekeyState::Stable, RekeyEvent::BeginRetire, Stable),
            (RekeyState::Stable, RekeyEvent::Retired, Stable),
            (
                RekeyState::Stable,
                RekeyEvent::SwitchInstalled(overlap()),
                Stable,
            ),
            (RekeyState::Stable, RekeyEvent::SwitchRefused(None), Stable),
            (RekeyState::Switching, RekeyEvent::BeginSwitch, Switching),
            (RekeyState::Switching, RekeyEvent::BeginRetire, Switching),
            (RekeyState::Switching, RekeyEvent::Retired, Switching),
            (
                RekeyState::Overlap(overlap()),
                RekeyEvent::BeginSwitch,
                Overlap,
            ),
            (
                RekeyState::Overlap(overlap()),
                RekeyEvent::SwitchInstalled(overlap()),
                Overlap,
            ),
            (RekeyState::Overlap(overlap()), RekeyEvent::Retired, Overlap),
            (RekeyState::Retiring, RekeyEvent::BeginRetire, Retiring),
            (RekeyState::Retiring, RekeyEvent::BeginSwitch, Retiring),
            (
                RekeyState::Retiring,
                RekeyEvent::SwitchInstalled(overlap()),
                Retiring,
            ),
        ] {
            assert_eq!(phase_after(state, event), Err(unchanged));
        }
    }
}
