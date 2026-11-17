use crate::error::{HarnessError, Result};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::{Notify, broadcast, mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{timeout, timeout_at};

/// A stable identifier assigned to one accepted TCP connection.
///
/// IDs start at one and are allocated in listener-accept order without
/// retaining an ever-growing history of connections.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConnectionId(pub u64);

impl ConnectionId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl From<u64> for ConnectionId {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<ConnectionId> for u64 {
    fn from(value: ConnectionId) -> Self {
        value.0
    }
}

/// The bounded active-connection record exposed by the proxy.
///
/// `source_addr` is the peer address observed by the proxy when it accepts
/// the client socket.  It is intentionally only retained while the
/// connection is active, so callers can map a carrier's local address to the
/// stable connection ID without assigning protocol roles from ordinal order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProxyConnection {
    pub id: ConnectionId,
    pub source_addr: SocketAddr,
}

// Commands are deliberately bounded.  A test that floods the control surface
// receives a bounded-capacity error instead of creating an unbounded command
// backlog or one task per command.
const PROXY_COMMAND_CAPACITY: usize = 32;
const CONNECTION_COMMAND_CAPACITY: usize = 8;
const MAX_ACTIVE_CONNECTIONS: u64 = 1024;
const MAX_RECENT_CONNECTION_IDS: usize = 16;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(1);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const PAUSE_TIMEOUT: Duration = Duration::from_secs(30);

/// The accept loop's published connection bookkeeping.
///
/// The accept loop is the only writer: it records every accept and every
/// completed connection, so the tail of recent IDs and the active peer records
/// change together and a handle samples one consistent view.
#[derive(Default)]
struct ConnectionView {
    recent_connection_ids: VecDeque<ConnectionId>,
    active: HashMap<ConnectionId, ProxyConnection>,
}

/// What a finished connection task hands back to the accept loop: its ID, its
/// outcome, and the reply of the `close` command that ended it, if any.
type ConnectionOutcome = (
    ConnectionId,
    Result<()>,
    Option<oneshot::Sender<Result<()>>>,
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    ClientToTarget,
    TargetToClient,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FaultAction {
    Pause(Duration),
    DropBytes(u64),
    CloseAfterBytes(u64),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FaultRule {
    pub direction: Direction,
    pub action: FaultAction,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FaultScript {
    pub rules: Vec<FaultRule>,
}

impl FaultScript {
    pub fn with_rule(mut self, direction: Direction, action: FaultAction) -> Self {
        self.rules.push(FaultRule { direction, action });
        self
    }

    fn for_direction(&self, direction: Direction) -> DirectionFault {
        let mut fault = DirectionFault::default();
        for rule in self.rules.iter().filter(|rule| rule.direction == direction) {
            match rule.action {
                FaultAction::Pause(duration) => fault.pause = Some(duration),
                FaultAction::DropBytes(bytes) => {
                    fault.drop_bytes = fault.drop_bytes.saturating_add(bytes)
                }
                FaultAction::CloseAfterBytes(bytes) => {
                    fault.close_after = Some(
                        fault
                            .close_after
                            .map_or(bytes, |current| current.min(bytes)),
                    )
                }
            }
        }
        fault
    }
}

#[derive(Clone, Debug)]
pub struct ProxyConfig {
    pub bind_addr: SocketAddr,
    pub fault_script: FaultScript,
    pub read_buffer_bytes: usize,
    /// Optional kernel receive-buffer request on the socket connected to the
    /// target. Set before connect so paused response reads exert bounded
    /// backpressure; the operating system may adjust the requested size.
    pub target_receive_buffer_bytes: Option<u32>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            fault_script: FaultScript::default(),
            read_buffer_bytes: 16 * 1024,
            target_receive_buffer_bytes: None,
        }
    }
}

#[derive(Default)]
struct StatsInner {
    accepted: AtomicU64,
    active: AtomicU64,
    peak_active: AtomicU64,
    completed: AtomicU64,
    last_connection_id: AtomicU64,
    bytes_client_to_target: AtomicU64,
    bytes_target_to_client: AtomicU64,
    dropped_client_to_target: AtomicU64,
    dropped_target_to_client: AtomicU64,
    paused_client_to_target: AtomicU64,
    paused_target_to_client: AtomicU64,
    closes: AtomicU64,
}

/// A cheap snapshot suitable for assertions and diagnostics.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProxyStats {
    pub accepted: u64,
    pub active: u64,
    pub completed: u64,
    pub bytes_client_to_target: u64,
    pub bytes_target_to_client: u64,
    pub dropped_client_to_target: u64,
    pub dropped_target_to_client: u64,
    pub paused_client_to_target: u64,
    pub paused_target_to_client: u64,
    pub closes: u64,
}

impl ProxyStats {
    fn snapshot(inner: &StatsInner) -> Self {
        Self {
            accepted: inner.accepted.load(Ordering::Acquire),
            active: inner.active.load(Ordering::Relaxed),
            completed: inner.completed.load(Ordering::Relaxed),
            bytes_client_to_target: inner.bytes_client_to_target.load(Ordering::Relaxed),
            bytes_target_to_client: inner.bytes_target_to_client.load(Ordering::Relaxed),
            dropped_client_to_target: inner.dropped_client_to_target.load(Ordering::Relaxed),
            dropped_target_to_client: inner.dropped_target_to_client.load(Ordering::Relaxed),
            paused_client_to_target: inner.paused_client_to_target.load(Ordering::Relaxed),
            paused_target_to_client: inner.paused_target_to_client.load(Ordering::Relaxed),
            closes: inner.closes.load(Ordering::Relaxed),
        }
    }
}

/// A bounded diagnostic snapshot for M2 fault control and assertions.
///
/// The existing `ProxyStats` shape remains unchanged for M1 callers.  This
/// snapshot adds the M2 connection-ID tail, peak active count, and bounded
/// active peer records; accepted connections are never retained indefinitely.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProxyDiagnostics {
    pub stats: ProxyStats,
    pub peak_active: u64,
    pub last_connection_id: Option<ConnectionId>,
    pub recent_connection_ids: Vec<ConnectionId>,
    pub active_connections: Vec<ProxyConnection>,
}

impl std::ops::Deref for ProxyDiagnostics {
    type Target = ProxyStats;

    fn deref(&self) -> &Self::Target {
        &self.stats
    }
}

impl ProxyDiagnostics {
    fn snapshot(inner: &StatsInner, connections: &watch::Receiver<ConnectionView>) -> Self {
        let view = connections.borrow();
        Self {
            stats: ProxyStats::snapshot(inner),
            peak_active: inner.peak_active.load(Ordering::Relaxed),
            last_connection_id: match inner.last_connection_id.load(Ordering::Relaxed) {
                0 => None,
                value => Some(ConnectionId(value)),
            },
            recent_connection_ids: view.recent_connection_ids.iter().copied().collect(),
            active_connections: sorted_active_connections(&view),
        }
    }
}

enum ProxyCommand {
    Close {
        connection_id: ConnectionId,
        reply: oneshot::Sender<Result<()>>,
    },
    Pause {
        direction: Direction,
        connection_id: ConnectionId,
        reply: oneshot::Sender<Result<()>>,
    },
    Resume {
        direction: Direction,
        connection_id: ConnectionId,
        reply: oneshot::Sender<Result<()>>,
    },
    PauseAll {
        reply: oneshot::Sender<Result<()>>,
    },
    ResumeAll {
        reply: oneshot::Sender<Result<()>>,
    },
}

enum ConnectionCommand {
    Close {
        reply: oneshot::Sender<Result<()>>,
    },
    Pause {
        direction: Direction,
        reply: oneshot::Sender<Result<()>>,
    },
    Resume {
        direction: Direction,
        reply: oneshot::Sender<Result<()>>,
    },
}

/// Command replies one connection task still owes.
///
/// The task that runs a connection handles its commands and drives both of
/// its copy directions, so it owns these outright.
#[derive(Default)]
struct PendingReplies {
    /// The `close` that ended the connection; the accept loop answers it once
    /// the connection is out of the active set.
    close: Option<oneshot::Sender<Result<()>>>,
    /// A pause accepted before its direction reached the pause barrier.
    pause_client_to_target: Option<oneshot::Sender<Result<()>>>,
    pause_target_to_client: Option<oneshot::Sender<Result<()>>>,
}

impl PendingReplies {
    /// Answer every pending pause whose direction has since settled it.
    fn settle(&mut self, client_to_target: &DirectionControl, target_to_client: &DirectionControl) {
        client_to_target.settle_pause(&mut self.pause_client_to_target);
        target_to_client.settle_pause(&mut self.pause_target_to_client);
    }
}

#[derive(Clone)]
struct GlobalPauseControls {
    client_to_target: Arc<GlobalPauseGate>,
    target_to_client: Arc<GlobalPauseGate>,
}

impl Default for GlobalPauseControls {
    fn default() -> Self {
        Self {
            client_to_target: Arc::new(GlobalPauseGate::default()),
            target_to_client: Arc::new(GlobalPauseGate::default()),
        }
    }
}

impl GlobalPauseControls {
    /// Stop both directions and wait until no forwarding write is in flight.
    ///
    /// Only the accept loop calls this and [`Self::resume_all`], one command
    /// at a time, so it is the single writer of both `paused` flags.
    async fn pause_all(&self) -> Result<()> {
        let client_was = self.client_to_target.paused.swap(true, Ordering::SeqCst);
        let target_was = self.target_to_client.paused.swap(true, Ordering::SeqCst);
        self.client_to_target.changed.notify_waiters();
        self.target_to_client.changed.notify_waiters();
        let drained = async {
            tokio::join!(
                self.client_to_target.drained(),
                self.target_to_client.drained()
            );
        };
        if tokio::time::timeout(COMMAND_TIMEOUT, drained)
            .await
            .is_err()
        {
            // A write that could not finish in time keeps the barrier from
            // being installed; leave the proxy as the command found it.
            self.client_to_target
                .paused
                .store(client_was, Ordering::SeqCst);
            self.target_to_client
                .paused
                .store(target_was, Ordering::SeqCst);
            self.client_to_target.changed.notify_waiters();
            self.target_to_client.changed.notify_waiters();
            return Err(HarnessError::Timeout(
                "global proxy pause timed out".to_owned(),
            ));
        }
        Ok(())
    }

    async fn resume_all(&self) -> Result<()> {
        self.client_to_target.paused.store(false, Ordering::SeqCst);
        self.target_to_client.paused.store(false, Ordering::SeqCst);
        self.client_to_target.changed.notify_waiters();
        self.target_to_client.changed.notify_waiters();
        Ok(())
    }
}

/// One direction's global pause barrier.
///
/// Forwarding never waits on other forwarding: each write only counts itself
/// in and out. A pause raises `paused` and then waits for the count of writes
/// already in flight to reach zero; a write that starts afterwards sees
/// `paused` and backs off before touching the socket. Both sides use `SeqCst`
/// so that either the pause sees the write's count or the write sees the
/// pause.
struct GlobalPauseGate {
    paused: AtomicBool,
    changed: Notify,
    /// Forwarding writes of this direction currently inside the socket write.
    forwarding: AtomicU64,
    /// Signalled when `forwarding` reaches zero while a pause is being set.
    quiet: Notify,
}

impl Default for GlobalPauseGate {
    fn default() -> Self {
        Self {
            paused: AtomicBool::new(false),
            changed: Notify::new(),
            forwarding: AtomicU64::new(0),
            quiet: Notify::new(),
        }
    }
}

/// Marks one forwarding write as in flight until dropped, including when the
/// connection is torn down in the middle of the write.
struct ForwardInFlight<'a>(&'a GlobalPauseGate);

impl Drop for ForwardInFlight<'_> {
    fn drop(&mut self) {
        if self.0.forwarding.fetch_sub(1, Ordering::SeqCst) == 1
            && self.0.paused.load(Ordering::SeqCst)
        {
            self.0.quiet.notify_one();
        }
    }
}

impl GlobalPauseGate {
    fn is_paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }

    /// Count a forwarding write in, unless a global pause is set.
    fn begin_forward(&self) -> Option<ForwardInFlight<'_>> {
        self.forwarding.fetch_add(1, Ordering::SeqCst);
        let in_flight = ForwardInFlight(self);
        if self.is_paused() {
            None
        } else {
            Some(in_flight)
        }
    }

    /// Wait until no forwarding write of this direction is in flight.
    async fn drained(&self) {
        loop {
            let quiet = self.quiet.notified();
            tokio::pin!(quiet);
            quiet.as_mut().enable();
            if self.forwarding.load(Ordering::SeqCst) == 0 {
                return;
            }
            quiet.await;
        }
    }
}

struct ConnectionControl {
    shutdown: broadcast::Receiver<()>,
    commands: mpsc::Receiver<ConnectionCommand>,
    replies: PendingReplies,
}

struct ConnectionBuffers {
    read_buffer_bytes: usize,
    target_receive_buffer_bytes: Option<u32>,
}

struct AcceptContext {
    listener: TcpListener,
    target_addr: SocketAddr,
    faults: FaultScript,
    read_buffer_bytes: usize,
    target_receive_buffer_bytes: Option<u32>,
    stats: Arc<StatsInner>,
    connections: watch::Sender<ConnectionView>,
    global_pause: GlobalPauseControls,
}

/// A TCP proxy that leaves TLS opaque and can inject bounded transport faults.
pub struct TcpProxy;

impl TcpProxy {
    pub async fn bind(target_addr: SocketAddr, config: ProxyConfig) -> Result<ProxyHandle> {
        if config.read_buffer_bytes == 0 || config.read_buffer_bytes > 1024 * 1024 {
            return Err(HarnessError::InvalidInput(
                "proxy read_buffer_bytes must be between 1 and 1 MiB".to_owned(),
            ));
        }
        if config
            .target_receive_buffer_bytes
            .is_some_and(|bytes| !(1024..=1024 * 1024).contains(&bytes))
        {
            return Err(HarnessError::InvalidInput(
                "proxy target_receive_buffer_bytes must be between 1 KiB and 1 MiB".to_owned(),
            ));
        }
        let listener = TcpListener::bind(config.bind_addr).await?;
        let local_addr = listener.local_addr()?;
        let target_text = target_addr.to_string();
        let local_text = local_addr.to_string();
        crate::c11_capture::record_sentinel("private_endpoint", target_text.as_bytes())?;
        crate::c11_capture::record_sentinel("private_endpoint", local_text.as_bytes())?;
        let (shutdown_tx, _) = broadcast::channel(2);
        let (command_tx, command_rx) = mpsc::channel(PROXY_COMMAND_CAPACITY);
        let stats = Arc::new(StatsInner::default());
        let (publish_connections, connections) = watch::channel(ConnectionView::default());
        let global_pause = GlobalPauseControls::default();
        let accept_stats = Arc::clone(&stats);
        let accept_global_pause = global_pause.clone();
        let accept_faults = config.fault_script.clone();
        let read_buffer_bytes = config.read_buffer_bytes;
        let target_receive_buffer_bytes = config.target_receive_buffer_bytes;
        let accept_shutdown = shutdown_tx.subscribe();
        let accept_task = tokio::spawn(async move {
            accept_loop(
                AcceptContext {
                    listener,
                    target_addr,
                    faults: accept_faults,
                    read_buffer_bytes,
                    target_receive_buffer_bytes,
                    stats: accept_stats,
                    connections: publish_connections,
                    global_pause: accept_global_pause,
                },
                accept_shutdown,
                command_rx,
            )
            .await;
        });
        Ok(ProxyHandle {
            local_addr,
            target_addr,
            stats,
            connections,
            shutdown_tx,
            command_tx,
            accept_task: Some(accept_task),
        })
    }
}

pub struct ProxyHandle {
    local_addr: SocketAddr,
    target_addr: SocketAddr,
    stats: Arc<StatsInner>,
    connections: watch::Receiver<ConnectionView>,
    shutdown_tx: broadcast::Sender<()>,
    command_tx: mpsc::Sender<ProxyCommand>,
    accept_task: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for ProxyHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyHandle")
            .field("local_addr", &self.local_addr)
            .field("target_addr", &self.target_addr)
            .field("stats", &self.stats())
            .finish()
    }
}

impl ProxyHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn target_addr(&self) -> SocketAddr {
        self.target_addr
    }

    pub fn stats(&self) -> ProxyStats {
        ProxyStats::snapshot(&self.stats)
    }

    /// Return a bounded diagnostic snapshot suitable for status endpoints.
    pub fn diagnostics(&self) -> ProxyDiagnostics {
        ProxyDiagnostics::snapshot(&self.stats, &self.connections)
    }

    /// Return the currently active accepted connections and their client peer
    /// addresses.  The result is bounded by the proxy's active-connection
    /// limit and contains no historical address mapping.
    pub fn connections(&self) -> Vec<ProxyConnection> {
        sorted_active_connections(&self.connections.borrow())
    }

    /// Close exactly one accepted connection.  The command is sent through a
    /// bounded queue and has a hard response deadline.
    pub async fn close(&self, connection_id: impl Into<ConnectionId>) -> Result<()> {
        let connection_id = connection_id.into();
        let (reply, response) = oneshot::channel();
        self.send_command(ProxyCommand::Close {
            connection_id,
            reply,
        })
        .await?;
        await_command_response(response).await
    }

    /// Pause forwarding in one direction of exactly one accepted connection.
    /// The pause is automatically failed closed after the bounded pause
    /// deadline if no matching `resume` command arrives.
    pub async fn pause(
        &self,
        direction: Direction,
        connection_id: impl Into<ConnectionId>,
    ) -> Result<()> {
        let connection_id = connection_id.into();
        let (reply, response) = oneshot::channel();
        self.send_command(ProxyCommand::Pause {
            direction,
            connection_id,
            reply,
        })
        .await?;
        await_command_response(response).await
    }

    /// Resume forwarding in one direction of exactly one accepted connection.
    pub async fn resume(
        &self,
        direction: Direction,
        connection_id: impl Into<ConnectionId>,
    ) -> Result<()> {
        let connection_id = connection_id.into();
        let (reply, response) = oneshot::channel();
        self.send_command(ProxyCommand::Resume {
            direction,
            connection_id,
            reply,
        })
        .await?;
        await_command_response(response).await
    }

    /// Pause forwarding in both directions for every current connection and
    /// for connections accepted while the pause remains active.  The bounded
    /// command is acknowledged after both global barriers are installed.
    pub async fn pause_all(&self) -> Result<()> {
        let (reply, response) = oneshot::channel();
        self.send_command(ProxyCommand::PauseAll { reply }).await?;
        await_command_response(response).await
    }

    /// Resume both directions for every connection covered by [`Self::pause_all`].
    pub async fn resume_all(&self) -> Result<()> {
        let (reply, response) = oneshot::channel();
        self.send_command(ProxyCommand::ResumeAll { reply }).await?;
        await_command_response(response).await
    }

    async fn send_command(&self, command: ProxyCommand) -> Result<()> {
        tokio::time::timeout(COMMAND_TIMEOUT, self.command_tx.send(command))
            .await
            .map_err(|_| HarnessError::Timeout("proxy command queue send timed out".to_owned()))?
            .map_err(|_| HarnessError::Proxy("proxy command loop is closed".to_owned()))
    }

    pub async fn shutdown(mut self) -> Result<()> {
        let _ = record_c11_proxy_snapshot(&self);
        retire_c11_proxy_sentinels(&self);
        let _ = self.shutdown_tx.send(());
        if let Some(task) = self.accept_task.take() {
            task.await
                .map_err(|error| HarnessError::Proxy(error.to_string()))?;
        }
        Ok(())
    }

    /// Shut down the accept loop with a caller-owned absolute deadline.
    ///
    /// Unlike [`Self::shutdown`], this keeps the task in the handle when a
    /// deadline or forced-join bound is exceeded.  A successor-owner fixture
    /// can therefore retain the proxy until a later forced cleanup pass
    /// instead of detaching its accept task when an outer scenario is
    /// cancelled.
    pub async fn shutdown_until(&mut self, deadline: tokio::time::Instant) -> Result<()> {
        let _ = record_c11_proxy_snapshot(self);
        retire_c11_proxy_sentinels(self);
        let _ = self.shutdown_tx.send(());
        let Some(task) = self.accept_task.as_mut() else {
            return Ok(());
        };
        match timeout_at(deadline, &mut *task).await {
            Ok(Ok(())) => {
                self.accept_task.take();
                Ok(())
            }
            Ok(Err(error)) => {
                self.accept_task.take();
                Err(HarnessError::Proxy(error.to_string()))
            }
            Err(_) => {
                task.abort();
                match timeout(Duration::from_secs(1), &mut *task).await {
                    Ok(Ok(())) => {
                        self.accept_task.take();
                        Err(HarnessError::Timeout(
                            "proxy accept task required forced abort cleanup".into(),
                        ))
                    }
                    Ok(Err(error)) => {
                        self.accept_task.take();
                        Err(HarnessError::Proxy(format!(
                            "proxy accept task forced abort join failed: {error}"
                        )))
                    }
                    Err(_) => Err(HarnessError::Timeout(
                        "proxy accept task did not join after forced abort".into(),
                    )),
                }
            }
        }
    }
}

async fn await_command_response(response: oneshot::Receiver<Result<()>>) -> Result<()> {
    tokio::time::timeout(COMMAND_TIMEOUT, response)
        .await
        .map_err(|_| HarnessError::Timeout("proxy command response timed out".to_owned()))?
        .map_err(|_| HarnessError::Proxy("proxy command response was dropped".to_owned()))?
}

/// Retire this proxy's endpoint sentinels once its listener is closed.
///
/// The listening port returns to the operating system here, which is free to
/// hand it to anything else in the same run, including a managed child's own
/// ephemeral client socket. The C11 scanner compares exact bytes, so leaving
/// the value recorded turns that ordinary reuse into a reported leak of an
/// endpoint that no longer exists. Only the local listener is retired: the
/// target address belongs to something this proxy does not own and may still
/// be live.
fn retire_c11_proxy_sentinels(handle: &ProxyHandle) {
    let _ = crate::c11_capture::retire_sentinel(
        "private_endpoint",
        handle.local_addr.to_string().as_bytes(),
    );
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(());
        if let Some(task) = self.accept_task.take() {
            task.abort();
        }
    }
}

async fn accept_loop(
    context: AcceptContext,
    mut shutdown: broadcast::Receiver<()>,
    mut commands: mpsc::Receiver<ProxyCommand>,
) {
    let AcceptContext {
        listener,
        target_addr,
        faults,
        read_buffer_bytes,
        target_receive_buffer_bytes,
        stats,
        connections: view,
        global_pause,
    } = context;
    let mut connections: JoinSet<ConnectionOutcome> = JoinSet::new();
    let mut routes = HashMap::new();
    loop {
        let accepted = tokio::select! {
            _ = shutdown.recv() => break,
            Some(joined) = connections.join_next() => {
                if let Ok(outcome) = joined {
                    routes.remove(&outcome.0);
                    record_completion(&stats, &view, outcome);
                }
                continue;
            }
            command = commands.recv() => {
                match command {
                    Some(command) => route_command(command, &routes, &global_pause).await,
                    None => break,
                }
                continue;
            }
            result = listener.accept() => result,
        };
        let (client, source_addr) = match accepted {
            Ok(connection) => connection,
            Err(error) => {
                eprintln!("tunnel-test-harness proxy accept failed: {error}");
                continue;
            }
        };
        let connection_stats = Arc::clone(&stats);
        let connection_faults = faults.clone();
        let connection_id = record_accept(&stats, &view, source_addr);
        let active = stats.active.load(Ordering::Relaxed);
        if active > MAX_ACTIVE_CONNECTIONS {
            // The listener has accepted the socket and assigned it a stable
            // ID, but refuses to retain an unbounded number of live routes.
            // Dropping the stream is the bounded overload behavior.
            stats.active.fetch_sub(1, Ordering::Relaxed);
            stats.completed.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let (connection_commands_tx, connection_commands_rx) =
            mpsc::channel(CONNECTION_COMMAND_CAPACITY);
        let connection_shutdown = shutdown.resubscribe();
        let connection_global_pause = global_pause.clone();
        routes.insert(connection_id, connection_commands_tx);
        connections.spawn(async move {
            let mut connection_control = ConnectionControl {
                shutdown: connection_shutdown,
                commands: connection_commands_rx,
                replies: PendingReplies::default(),
            };
            let result = proxy_connection(
                client,
                target_addr,
                connection_faults,
                ConnectionBuffers {
                    read_buffer_bytes,
                    target_receive_buffer_bytes,
                },
                Arc::clone(&connection_stats),
                &mut connection_control,
                connection_global_pause,
            )
            .await;
            if let Err(error) = &result {
                eprintln!("tunnel-test-harness proxy connection ended: {error}");
            }
            (
                connection_id,
                result,
                connection_control.replies.close.take(),
            )
        });
    }
    // A shutdown signal is forwarded to every active connection.  Join all
    // of them before the listener task completes so a test cannot leave a
    // TLS-pass-through socket or its copy tasks behind.
    while let Some(joined) = connections.join_next().await {
        if let Ok(outcome) = joined {
            record_completion(&stats, &view, outcome);
        }
    }
}

/// Take one finished connection out of the books, then answer the `close`
/// that ended it, so the caller's next snapshot no longer shows it.
fn record_completion(
    stats: &StatsInner,
    view: &watch::Sender<ConnectionView>,
    (connection_id, _result, close_reply): ConnectionOutcome,
) {
    stats.active.fetch_sub(1, Ordering::Relaxed);
    view.send_modify(|view| {
        view.active.remove(&connection_id);
    });
    stats.completed.fetch_add(1, Ordering::Relaxed);
    if let Some(reply) = close_reply {
        let _ = reply.send(Ok(()));
    }
}

fn record_accept(
    stats: &StatsInner,
    view: &watch::Sender<ConnectionView>,
    source_addr: SocketAddr,
) -> ConnectionId {
    let connection_id = stats.accepted.load(Ordering::Relaxed) + 1;
    stats
        .last_connection_id
        .store(connection_id, Ordering::Relaxed);
    let active = stats.active.fetch_add(1, Ordering::Relaxed) + 1;
    update_peak(&stats.peak_active, active);
    view.send_modify(|view| {
        view.recent_connection_ids
            .push_back(ConnectionId(connection_id));
        while view.recent_connection_ids.len() > MAX_RECENT_CONNECTION_IDS {
            view.recent_connection_ids.pop_front();
        }
        if active <= MAX_ACTIVE_CONNECTIONS {
            view.active.insert(
                ConnectionId(connection_id),
                ProxyConnection {
                    id: ConnectionId(connection_id),
                    source_addr,
                },
            );
        }
    });
    stats.accepted.store(connection_id, Ordering::Release);
    ConnectionId(connection_id)
}

fn record_c11_proxy_snapshot(proxy: &ProxyHandle) -> Result<()> {
    let diagnostics = proxy.diagnostics();
    let stats = diagnostics.stats;
    let text = format!(
        "route=tcp_proxy accepted={} active={} completed={} bytes_client_to_target={} bytes_target_to_client={} dropped_client_to_target={} dropped_target_to_client={} paused_client_to_target={} paused_target_to_client={} closes={} peak_active={} active_records={}",
        stats.accepted,
        stats.active,
        stats.completed,
        stats.bytes_client_to_target,
        stats.bytes_target_to_client,
        stats.dropped_client_to_target,
        stats.dropped_target_to_client,
        stats.paused_client_to_target,
        stats.paused_target_to_client,
        stats.closes,
        diagnostics.peak_active,
        diagnostics.active_connections.len(),
    );
    crate::c11_capture::record_snapshot("tcp_proxy", text.as_bytes())
}

fn sorted_active_connections(view: &ConnectionView) -> Vec<ProxyConnection> {
    let mut snapshot: Vec<ProxyConnection> = view.active.values().copied().collect();
    snapshot.sort_by_key(|connection| connection.id);
    snapshot
}

fn update_peak(peak: &AtomicU64, current: u64) {
    let mut observed = peak.load(Ordering::Relaxed);
    while current > observed {
        match peak.compare_exchange_weak(observed, current, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(next) => observed = next,
        }
    }
}

async fn route_command(
    command: ProxyCommand,
    routes: &HashMap<ConnectionId, mpsc::Sender<ConnectionCommand>>,
    global_pause: &GlobalPauseControls,
) {
    let (connection_id, command) = match command {
        ProxyCommand::Close {
            connection_id,
            reply,
        } => (connection_id, ConnectionCommand::Close { reply }),
        ProxyCommand::Pause {
            direction,
            connection_id,
            reply,
        } => (connection_id, ConnectionCommand::Pause { direction, reply }),
        ProxyCommand::Resume {
            direction,
            connection_id,
            reply,
        } => (
            connection_id,
            ConnectionCommand::Resume { direction, reply },
        ),
        ProxyCommand::PauseAll { reply } => {
            let _ = reply.send(global_pause.pause_all().await);
            return;
        }
        ProxyCommand::ResumeAll { reply } => {
            let _ = reply.send(global_pause.resume_all().await);
            return;
        }
    };
    let sender = match routes.get(&connection_id) {
        Some(sender) => sender,
        None => {
            reject_connection_command(
                command,
                format!("connection {connection_id:?} is not active"),
            );
            return;
        }
    };
    if let Err(error) = sender.try_send(command) {
        match error {
            mpsc::error::TrySendError::Full(command) => {
                reject_connection_command(command, "connection command queue is full".to_owned());
            }
            mpsc::error::TrySendError::Closed(command) => {
                reject_connection_command(command, "connection command loop is closed".to_owned());
            }
        }
    }
}

fn reject_connection_command(command: ConnectionCommand, message: String) {
    let result = Err(HarnessError::Proxy(message));
    match command {
        ConnectionCommand::Close { reply }
        | ConnectionCommand::Pause { reply, .. }
        | ConnectionCommand::Resume { reply, .. } => {
            let _ = reply.send(result);
        }
    }
}

async fn proxy_connection(
    client: TcpStream,
    target_addr: SocketAddr,
    faults: FaultScript,
    buffers: ConnectionBuffers,
    stats: Arc<StatsInner>,
    control: &mut ConnectionControl,
    global_pause: GlobalPauseControls,
) -> Result<()> {
    let ConnectionBuffers {
        read_buffer_bytes,
        target_receive_buffer_bytes,
    } = buffers;
    // Raised by a copy direction when it settles a pause this task still owes
    // a reply for.
    let settled = Arc::new(Notify::new());
    let client_to_target = Arc::new(DirectionControl::new(Arc::clone(&settled)));
    let target_to_client = Arc::new(DirectionControl::new(Arc::clone(&settled)));
    let target_connect = async {
        if let Some(bytes) = target_receive_buffer_bytes {
            let socket = if target_addr.is_ipv4() {
                TcpSocket::new_v4()?
            } else {
                TcpSocket::new_v6()?
            };
            socket.set_recv_buffer_size(bytes)?;
            socket.connect(target_addr).await
        } else {
            TcpStream::connect(target_addr).await
        }
    };
    tokio::pin!(target_connect);
    let connect_deadline = Instant::now() + CONNECT_TIMEOUT;
    let target = loop {
        let remaining = connect_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(HarnessError::Timeout(
                "proxy target connection timed out".to_owned(),
            ));
        }
        tokio::select! {
            target = tokio::time::timeout(remaining, &mut target_connect) => {
                break target
                    .map_err(|_| HarnessError::Timeout("proxy target connection timed out".to_owned()))??;
            },
            Some(command) = control.commands.recv() => {
                if handle_connection_command(
                    command,
                    &stats,
                    &client_to_target,
                    &target_to_client,
                    false,
                    &mut control.replies,
                ) {
                    return Ok(());
                }
            },
            _ = control.shutdown.recv() => return Ok(()),
        }
    };
    let (client_read, client_write) = client.into_split();
    let (target_read, target_write) = target.into_split();
    let up = copy_direction(
        client_read,
        target_write,
        Direction::ClientToTarget,
        faults.for_direction(Direction::ClientToTarget),
        read_buffer_bytes,
        Arc::clone(&stats),
        DirectionControls {
            local: Arc::clone(&client_to_target),
            global: Arc::clone(&global_pause.client_to_target),
        },
    );
    let down = copy_direction(
        target_read,
        client_write,
        Direction::TargetToClient,
        faults.for_direction(Direction::TargetToClient),
        read_buffer_bytes,
        Arc::clone(&stats),
        DirectionControls {
            local: Arc::clone(&target_to_client),
            global: Arc::clone(&global_pause.target_to_client),
        },
    );
    let joined = async {
        tokio::pin!(up);
        tokio::pin!(down);
        tokio::select! {
            result = &mut up => match result {
                Ok(()) => down.await,
                Err(error) => Err(error),
            },
            result = &mut down => match result {
                Ok(()) => up.await,
                Err(error) => Err(error),
            },
        }
    };
    tokio::pin!(joined);
    // Both copy directions run inside this task, so anything they settled
    // happened before whichever branch is handled next; answer those pauses
    // first so a command never overtakes an outcome that preceded it.
    loop {
        tokio::select! {
            joined = &mut joined => {
                control
                    .replies
                    .settle(&client_to_target, &target_to_client);
                return joined;
            },
            Some(command) = control.commands.recv() => {
                control
                    .replies
                    .settle(&client_to_target, &target_to_client);
                if handle_connection_command(
                    command,
                    &stats,
                    &client_to_target,
                    &target_to_client,
                    true,
                    &mut control.replies,
                ) {
                    return Ok(());
                }
            },
            _ = control.shutdown.recv() => {
                control
                    .replies
                    .settle(&client_to_target, &target_to_client);
                return Ok(());
            },
            _ = settled.notified() => {
                control
                    .replies
                    .settle(&client_to_target, &target_to_client);
            },
        }
    }
}

/// How a copy direction settled the pause its connection task is waiting on.
const PAUSE_UNSETTLED: u8 = 0;
const PAUSE_AT_BARRIER: u8 = 1;
const PAUSE_EXPIRED: u8 = 2;

/// One direction's pause switches.
///
/// The connection task and the copy direction it drives share only
/// independent flags here. The reply a pause is waiting on stays with the
/// connection task ([`PendingReplies`]); the copy direction records the first
/// thing that settles it in `pause_outcome` and raises `settled`.
struct DirectionControl {
    paused: AtomicBool,
    at_barrier: AtomicBool,
    ended: AtomicBool,
    changed: Notify,
    /// Hard pause deadline in nanoseconds after `epoch`, plus one; zero when
    /// no pause is armed.
    deadline: AtomicU64,
    epoch: Instant,
    /// First settlement since the pending pause reply was stored.
    pause_outcome: AtomicU8,
    /// The error this direction ended with, set before `ended`.
    end_error: OnceLock<String>,
    settled: Arc<Notify>,
}

impl DirectionControl {
    fn new(settled: Arc<Notify>) -> Self {
        Self {
            paused: AtomicBool::new(false),
            at_barrier: AtomicBool::new(false),
            ended: AtomicBool::new(false),
            changed: Notify::new(),
            deadline: AtomicU64::new(0),
            epoch: Instant::now(),
            pause_outcome: AtomicU8::new(PAUSE_UNSETTLED),
            end_error: OnceLock::new(),
            settled,
        }
    }

    fn arm_deadline(&self) {
        let deadline = (Instant::now() + PAUSE_TIMEOUT).saturating_duration_since(self.epoch);
        let nanos = u64::try_from(deadline.as_nanos()).unwrap_or(u64::MAX - 1);
        self.deadline
            .store(nanos.saturating_add(1), Ordering::Release);
    }

    fn pause(
        &self,
        pending: &mut Option<oneshot::Sender<Result<()>>>,
        reply: oneshot::Sender<Result<()>>,
        immediate: bool,
    ) {
        if self.ended.load(Ordering::Acquire) {
            let _ = reply.send(Ok(()));
            return;
        }
        let mut reject = Some(reply);
        if self.paused.load(Ordering::Acquire) {
            if self.at_barrier.load(Ordering::Acquire) {
                if let Some(reply) = reject.take() {
                    let _ = reply.send(Ok(()));
                }
            } else if pending.is_none() {
                self.pause_outcome.store(PAUSE_UNSETTLED, Ordering::Release);
                *pending = reject.take();
            }
        } else {
            self.arm_deadline();
            if !immediate {
                self.pause_outcome.store(PAUSE_UNSETTLED, Ordering::Release);
                *pending = reject.take();
            }
            self.at_barrier.store(false, Ordering::Release);
            self.paused.store(true, Ordering::Release);
            if immediate {
                self.at_barrier.store(true, Ordering::Release);
                if let Some(reply) = reject.take() {
                    let _ = reply.send(Ok(()));
                }
            }
        }
        if let Some(reply) = reject {
            let _ = reply.send(Err(HarnessError::Proxy(
                "duplicate pause command is already pending".to_owned(),
            )));
        }
        self.changed.notify_one();
    }

    fn resume(
        &self,
        pending: &mut Option<oneshot::Sender<Result<()>>>,
        reply: oneshot::Sender<Result<()>>,
    ) {
        self.paused.store(false, Ordering::Release);
        self.at_barrier.store(false, Ordering::Release);
        self.deadline.store(0, Ordering::Release);
        if let Some(pause_reply) = pending.take() {
            let _ = pause_reply.send(Err(HarnessError::Proxy(
                "pause superseded by resume".to_owned(),
            )));
        }
        self.changed.notify_one();
        let _ = reply.send(Ok(()));
    }

    /// Record the first thing that settles the pending pause reply.
    fn settle(&self, outcome: u8) {
        if self
            .pause_outcome
            .compare_exchange(
                PAUSE_UNSETTLED,
                outcome,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            self.settled.notify_one();
        }
    }

    fn expire_pause(&self) {
        self.paused.store(false, Ordering::Release);
        self.at_barrier.store(false, Ordering::Release);
        self.deadline.store(0, Ordering::Release);
        self.settle(PAUSE_EXPIRED);
        self.changed.notify_one();
    }

    fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Acquire)
    }

    fn pause_remaining(&self) -> Option<Duration> {
        let deadline = self.deadline.load(Ordering::Acquire).checked_sub(1)?;
        Some(
            (self.epoch + Duration::from_nanos(deadline)).saturating_duration_since(Instant::now()),
        )
    }

    fn reach_barrier(&self) {
        if !self.is_paused() {
            return;
        }
        self.at_barrier.store(true, Ordering::Release);
        self.settle(PAUSE_AT_BARRIER);
    }

    fn end(&self, result: &Result<()>) {
        if let Err(error) = result {
            let _ = self.end_error.set(error.to_string());
        }
        self.ended.store(true, Ordering::Release);
        self.settled.notify_one();
    }

    /// Answer the pending pause if this direction has settled it: reaching
    /// the barrier, expiring, or (failing either) ending.
    fn settle_pause(&self, pending: &mut Option<oneshot::Sender<Result<()>>>) {
        if pending.is_none() {
            return;
        }
        let outcome = match self.pause_outcome.load(Ordering::Acquire) {
            PAUSE_AT_BARRIER => Ok(()),
            PAUSE_EXPIRED => Err(HarnessError::Timeout(
                "proxy direction pause exceeded its hard timeout".to_owned(),
            )),
            _ if self.ended.load(Ordering::Acquire) => match self.end_error.get() {
                None => Ok(()),
                Some(error) => Err(HarnessError::Proxy(error.clone())),
            },
            _ => return,
        };
        if let Some(reply) = pending.take() {
            let _ = reply.send(outcome);
        }
    }

    fn cancel_pause(pending: &mut Option<oneshot::Sender<Result<()>>>) {
        if let Some(reply) = pending.take() {
            let _ = reply.send(Err(HarnessError::Proxy(
                "connection closed while pause was pending".to_owned(),
            )));
        }
    }
}

fn handle_connection_command(
    command: ConnectionCommand,
    stats: &StatsInner,
    client_to_target: &DirectionControl,
    target_to_client: &DirectionControl,
    immediate_pause: bool,
    replies: &mut PendingReplies,
) -> bool {
    match command {
        ConnectionCommand::Close { reply } => {
            stats.closes.fetch_add(1, Ordering::Relaxed);
            DirectionControl::cancel_pause(&mut replies.pause_client_to_target);
            DirectionControl::cancel_pause(&mut replies.pause_target_to_client);
            replies.close = Some(reply);
            true
        }
        ConnectionCommand::Pause { direction, reply } => {
            // Count before the direction control can acknowledge: callers
            // read `stats()` as soon as `pause` returns to prove the exact
            // direction was paused, and the reply wakes them on another
            // worker thread (task row M7-C103).  The oneshot reply orders
            // this increment before the caller's read.
            increment_pause(stats, direction);
            match direction {
                Direction::ClientToTarget => {
                    client_to_target.pause(
                        &mut replies.pause_client_to_target,
                        reply,
                        immediate_pause,
                    );
                }
                Direction::TargetToClient => {
                    target_to_client.pause(
                        &mut replies.pause_target_to_client,
                        reply,
                        immediate_pause,
                    );
                }
            }
            false
        }
        ConnectionCommand::Resume { direction, reply } => {
            match direction {
                Direction::ClientToTarget => {
                    client_to_target.resume(&mut replies.pause_client_to_target, reply);
                }
                Direction::TargetToClient => {
                    target_to_client.resume(&mut replies.pause_target_to_client, reply);
                }
            }
            false
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct DirectionFault {
    pause: Option<Duration>,
    drop_bytes: u64,
    close_after: Option<u64>,
}

#[derive(Clone)]
struct DirectionControls {
    local: Arc<DirectionControl>,
    global: Arc<GlobalPauseGate>,
}

async fn copy_direction<R, W>(
    reader: R,
    writer: W,
    direction: Direction,
    fault: DirectionFault,
    read_buffer_bytes: usize,
    stats: Arc<StatsInner>,
    controls: DirectionControls,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let result = copy_direction_inner(
        reader,
        writer,
        direction,
        fault,
        read_buffer_bytes,
        stats,
        controls.clone(),
    )
    .await;
    controls.local.end(&result);
    result
}

async fn copy_direction_inner<R, W>(
    mut reader: R,
    mut writer: W,
    direction: Direction,
    mut fault: DirectionFault,
    read_buffer_bytes: usize,
    stats: Arc<StatsInner>,
    controls: DirectionControls,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let control = &controls.local;
    let global_control = &controls.global;
    let mut buffer = vec![0_u8; read_buffer_bytes];
    let mut observed = 0_u64;
    loop {
        wait_if_paused(control, global_control).await?;
        let read = loop {
            let notified = control.changed.notified();
            tokio::pin!(notified);
            let global_notified = global_control.changed.notified();
            tokio::pin!(global_notified);
            if controls_paused(control, global_control) {
                wait_if_paused(control, global_control).await?;
                continue;
            }
            tokio::select! {
                read = reader.read(&mut buffer) => break read?,
                _ = &mut notified => {
                    // A pause command must interrupt an otherwise idle read
                    // so its hard timeout remains effective even with no
                    // incoming application bytes.
                    continue;
                }
                _ = &mut global_notified => {
                    // A global pause or resume must interrupt an otherwise
                    // idle read for every current and newly accepted route.
                    continue;
                }
            }
        };
        if read == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        let read = read as u64;
        observed = observed.saturating_add(read);
        add_bytes(&stats, direction, read);
        if let Some(pause) = fault.pause {
            increment_pause(&stats, direction);
            tokio::time::sleep(pause).await;
            fault.pause = None;
        }
        // A command may have arrived while the read was in progress.  Check
        // again before writing so paused traffic never crosses the proxy.
        wait_if_paused(control, global_control).await?;
        let mut start = 0_usize;
        if fault.drop_bytes > 0 {
            let drop = fault.drop_bytes.min(read) as usize;
            fault.drop_bytes -= drop as u64;
            start = drop;
            add_dropped(&stats, direction, drop as u64);
        }
        if let Some(close_after) = fault.close_after
            && observed >= close_after
        {
            stats.closes.fetch_add(1, Ordering::Relaxed);
            writer.shutdown().await?;
            return Ok(());
        }
        if start < read as usize {
            write_with_control(
                &mut writer,
                &buffer[start..read as usize],
                control,
                global_control,
            )
            .await?;
        }
    }
}

fn controls_paused(control: &DirectionControl, global_control: &GlobalPauseGate) -> bool {
    control.is_paused() || global_control.is_paused()
}

async fn wait_if_paused(
    control: &DirectionControl,
    global_control: &GlobalPauseGate,
) -> Result<()> {
    while controls_paused(control, global_control) {
        let remaining = control.pause_remaining();
        if remaining.is_some_and(|remaining| remaining.is_zero()) {
            if control.is_paused() {
                control.expire_pause();
            }
            return Err(HarnessError::Timeout(
                "proxy direction pause exceeded its hard timeout".to_owned(),
            ));
        }
        if control.is_paused() {
            control.reach_barrier();
        }
        let notified = control.changed.notified();
        let global_notified = global_control.changed.notified();
        if !control.is_paused() && !global_control.is_paused() {
            continue;
        }
        tokio::pin!(notified);
        tokio::pin!(global_notified);
        let notified = async {
            tokio::select! {
                _ = &mut notified => {},
                _ = &mut global_notified => {},
            }
        };
        if let Some(remaining) = remaining {
            if tokio::time::timeout(remaining, notified).await.is_err() {
                if control.is_paused() {
                    control.expire_pause();
                }
                return Err(HarnessError::Timeout(
                    "proxy direction pause exceeded its hard timeout".to_owned(),
                ));
            }
        } else {
            notified.await;
        }
    }
    Ok(())
}

async fn write_with_control<W>(
    writer: &mut W,
    bytes: &[u8],
    control: &DirectionControl,
    global_control: &GlobalPauseGate,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut offset = 0_usize;
    while offset < bytes.len() {
        wait_if_paused(control, global_control).await?;
        let Some(_in_flight) = global_control.begin_forward() else {
            continue;
        };
        let written = writer.write(&bytes[offset..]).await?;
        if written == 0 {
            return Err(HarnessError::Proxy(
                "proxy target closed while forwarding bytes".to_owned(),
            ));
        }
        offset += written;
    }
    Ok(())
}

fn add_bytes(stats: &StatsInner, direction: Direction, bytes: u64) {
    match direction {
        Direction::ClientToTarget => {
            stats
                .bytes_client_to_target
                .fetch_add(bytes, Ordering::Relaxed);
        }
        Direction::TargetToClient => {
            stats
                .bytes_target_to_client
                .fetch_add(bytes, Ordering::Relaxed);
        }
    }
}

fn add_dropped(stats: &StatsInner, direction: Direction, bytes: u64) {
    match direction {
        Direction::ClientToTarget => {
            stats
                .dropped_client_to_target
                .fetch_add(bytes, Ordering::Relaxed);
        }
        Direction::TargetToClient => {
            stats
                .dropped_target_to_client
                .fetch_add(bytes, Ordering::Relaxed);
        }
    }
}

fn increment_pause(stats: &StatsInner, direction: Direction) {
    match direction {
        Direction::ClientToTarget => {
            stats
                .paused_client_to_target
                .fetch_add(1, Ordering::Relaxed);
        }
        Direction::TargetToClient => {
            stats
                .paused_target_to_client
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ConnectionId, Direction, FaultAction, FaultScript, MAX_RECENT_CONNECTION_IDS, ProxyConfig,
        ProxyConnection, ProxyHandle, TcpProxy,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::{mpsc, oneshot};
    use tokio::task::JoinSet;
    use tokio::time::{Duration, sleep, timeout};

    async fn wait_for_accepts(proxy: &ProxyHandle, count: u64) {
        for _ in 0..100 {
            if proxy.stats().accepted >= count {
                return;
            }
            sleep(Duration::from_millis(1)).await;
        }
        panic!(
            "proxy did not accept {count} connections: {:?}",
            proxy.stats()
        );
    }

    async fn spawn_echo_target(listener: TcpListener, count: usize) {
        let mut workers = JoinSet::new();
        for _ in 0..count {
            let (mut stream, _) = listener.accept().await.expect("accept");
            workers.spawn(async move {
                let mut buffer = [0_u8; 1024];
                loop {
                    let read = stream.read(&mut buffer).await.expect("read");
                    if read == 0 {
                        return;
                    }
                    stream.write_all(&buffer[..read]).await.expect("write");
                }
            });
        }
        while workers.join_next().await.is_some() {}
    }

    #[tokio::test]
    async fn opaque_proxy_forwards_bytes_and_records_counts() {
        let target = TcpListener::bind(("127.0.0.1", 0)).await.expect("target");
        let target_addr = target.local_addr().expect("target addr");
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.expect("accept");
            let mut bytes = [0_u8; 5];
            stream.read_exact(&mut bytes).await.expect("read");
            stream.write_all(&bytes).await.expect("write");
        });
        let proxy = TcpProxy::bind(target_addr, ProxyConfig::default())
            .await
            .expect("proxy");
        let mut client = tokio::net::TcpStream::connect(proxy.local_addr())
            .await
            .expect("client");
        client.write_all(b"a\0b\xff\0").await.expect("client write");
        let mut response = [0_u8; 5];
        client.read_exact(&mut response).await.expect("client read");
        assert_eq!(&response, b"a\0b\xff\0");
        client.shutdown().await.expect("client shutdown");
        target_task.await.expect("target task");
        let stats = proxy.stats();
        assert_eq!(stats.accepted, 1);
        assert!(stats.bytes_client_to_target >= 5);
        assert!(stats.bytes_target_to_client >= 5);
        proxy.shutdown().await.expect("shutdown");
    }

    /// `shutdown` tears down live proxied connections, not just the listener.
    ///
    /// A fixture that intercepts a socket through a `TcpProxy` and then hands
    /// that socket to something longer-lived must keep the proxy alive for as
    /// long as the socket is in use.  Shutting the proxy down closes both
    /// halves of the connection underneath the holder, which a server on the
    /// other end sees as the peer disconnecting.  EC-041's control handoff
    /// regressed exactly this way, so the behaviour is pinned here.
    #[tokio::test]
    async fn shutdown_closes_established_proxied_connections() {
        let target = TcpListener::bind(("127.0.0.1", 0)).await.expect("target");
        let target_addr = target.local_addr().expect("target addr");
        let (peer_closed_tx, peer_closed_rx) = oneshot::channel();
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.expect("accept");
            let mut bytes = [0_u8; 4];
            stream.read_exact(&mut bytes).await.expect("read");
            stream.write_all(&bytes).await.expect("write");
            // Block until the proxy drops this connection: a clean end of
            // stream here is the server observing its peer disappear.
            let mut rest = Vec::new();
            let trailing = stream.read_to_end(&mut rest).await.expect("read to end");
            let _ = peer_closed_tx.send(trailing);
        });
        let proxy = TcpProxy::bind(target_addr, ProxyConfig::default())
            .await
            .expect("proxy");
        let mut client = tokio::net::TcpStream::connect(proxy.local_addr())
            .await
            .expect("client");
        client.write_all(b"live").await.expect("client write");
        let mut response = [0_u8; 4];
        client.read_exact(&mut response).await.expect("client read");
        assert_eq!(&response, b"live", "the connection is established and live");

        proxy.shutdown().await.expect("shutdown");

        // The target end of the proxied connection is closed by the shutdown.
        let trailing = timeout(Duration::from_secs(5), peer_closed_rx)
            .await
            .expect("target observes the proxied connection close")
            .expect("target task reports the close");
        assert_eq!(trailing, 0, "no trailing bytes precede the close");

        // The client end is closed too, so the holder of the socket cannot go
        // on using it after the proxy it came from was shut down.
        let mut after = [0_u8; 1];
        let read = timeout(Duration::from_secs(5), client.read(&mut after))
            .await
            .expect("client read completes")
            .expect("client read");
        assert_eq!(read, 0, "the client half is closed by the proxy shutdown");
        target_task.await.expect("target task");
    }

    #[tokio::test]
    async fn drop_fault_is_visible() {
        let target = TcpListener::bind(("127.0.0.1", 0)).await.expect("target");
        let target_addr = target.local_addr().expect("target addr");
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.expect("accept");
            let mut bytes = [0_u8; 2];
            let _ = stream.read_exact(&mut bytes).await;
        });
        let config = ProxyConfig {
            fault_script: FaultScript::default()
                .with_rule(Direction::ClientToTarget, FaultAction::DropBytes(2)),
            ..ProxyConfig::default()
        };
        let proxy = TcpProxy::bind(target_addr, config).await.expect("proxy");
        let mut client = tokio::net::TcpStream::connect(proxy.local_addr())
            .await
            .expect("client");
        client.write_all(b"drop").await.expect("client write");
        client.shutdown().await.expect("client shutdown");
        target_task.await.expect("target task");
        assert!(proxy.stats().dropped_client_to_target >= 2);
        proxy.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn targeted_close_only_closes_the_selected_serialized_connection() {
        let target = TcpListener::bind(("127.0.0.1", 0)).await.expect("target");
        let target_addr = target.local_addr().expect("target addr");
        let target_task = tokio::spawn(spawn_echo_target(target, 2));
        let proxy = TcpProxy::bind(target_addr, ProxyConfig::default())
            .await
            .expect("proxy");

        let mut control = tokio::net::TcpStream::connect(proxy.local_addr())
            .await
            .expect("control");
        let control_source = control.local_addr().expect("control source");
        wait_for_accepts(&proxy, 1).await;
        let mut data = tokio::net::TcpStream::connect(proxy.local_addr())
            .await
            .expect("data");
        let data_source = data.local_addr().expect("data source");
        wait_for_accepts(&proxy, 2).await;
        let diagnostics = proxy.diagnostics();
        assert_eq!(diagnostics.recent_connection_ids[0], ConnectionId::new(1));
        assert_eq!(diagnostics.last_connection_id, Some(ConnectionId::new(2)));
        assert_eq!(
            diagnostics.active_connections,
            vec![
                ProxyConnection {
                    id: ConnectionId::new(1),
                    source_addr: control_source,
                },
                ProxyConnection {
                    id: ConnectionId::new(2),
                    source_addr: data_source,
                },
            ]
        );

        proxy.close(ConnectionId::new(2)).await.expect("close data");
        assert_eq!(proxy.stats().active, 1);
        assert_eq!(
            proxy.connections(),
            vec![ProxyConnection {
                id: ConnectionId::new(1),
                source_addr: control_source,
            }]
        );
        let mut closed = [0_u8; 1];
        assert_eq!(data.read(&mut closed).await.expect("data eof"), 0);

        control.write_all(b"control").await.expect("control write");
        let mut response = [0_u8; 7];
        control
            .read_exact(&mut response)
            .await
            .expect("control read");
        assert_eq!(&response, b"control");
        assert_eq!(proxy.stats().closes, 1);

        drop(data);
        control.shutdown().await.expect("control shutdown");
        proxy.shutdown().await.expect("shutdown");
        target_task.await.expect("target task");
    }

    #[tokio::test]
    async fn targeted_pause_and_resume_only_stall_one_direction() {
        let target = TcpListener::bind(("127.0.0.1", 0)).await.expect("target");
        let target_addr = target.local_addr().expect("target addr");
        let target_task = tokio::spawn(spawn_echo_target(target, 2));
        let proxy = TcpProxy::bind(target_addr, ProxyConfig::default())
            .await
            .expect("proxy");
        let mut control = tokio::net::TcpStream::connect(proxy.local_addr())
            .await
            .expect("control");
        wait_for_accepts(&proxy, 1).await;
        let mut data = tokio::net::TcpStream::connect(proxy.local_addr())
            .await
            .expect("data");
        wait_for_accepts(&proxy, 2).await;
        let id = proxy
            .diagnostics()
            .last_connection_id
            .expect("data connection id");

        proxy
            .pause(Direction::ClientToTarget, id)
            .await
            .expect("pause");
        data.write_all(b"paused").await.expect("data write");
        let mut response = [0_u8; 6];
        assert!(
            timeout(Duration::from_millis(50), data.read(&mut response))
                .await
                .is_err()
        );
        control.write_all(b"control").await.expect("control write");
        let mut control_response = [0_u8; 7];
        control
            .read_exact(&mut control_response)
            .await
            .expect("control read");
        assert_eq!(&control_response, b"control");
        proxy
            .resume(Direction::ClientToTarget, id)
            .await
            .expect("resume");
        data.read_exact(&mut response).await.expect("resumed read");
        assert_eq!(&response, b"paused");
        assert_eq!(proxy.stats().paused_client_to_target, 1);

        control.shutdown().await.expect("control shutdown");
        data.shutdown().await.expect("data shutdown");
        proxy.shutdown().await.expect("shutdown");
        target_task.await.expect("target task");
    }

    /// Task row M7-C103: an acknowledged pause must already be counted.
    ///
    /// Callers read `stats()` straight after `pause` returns to prove the
    /// exact direction was paused (the queue-saturation gate does).  The ack
    /// used to be sent before the counter was incremented, so on a
    /// multi-threaded runtime the woken caller could read the old count.  The
    /// check runs many times because each iteration only opens the window.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_acknowledged_pause_is_already_counted() {
        const ITERATIONS: u64 = 2_000;
        let target = TcpListener::bind(("127.0.0.1", 0)).await.expect("target");
        let target_addr = target.local_addr().expect("target addr");
        let target_task = tokio::spawn(spawn_echo_target(target, 1));
        let proxy = TcpProxy::bind(target_addr, ProxyConfig::default())
            .await
            .expect("proxy");
        let mut client = tokio::net::TcpStream::connect(proxy.local_addr())
            .await
            .expect("client");
        wait_for_accepts(&proxy, 1).await;
        // One round trip, so the route is fully established before pausing.
        client.write_all(b"x").await.expect("client write");
        let mut byte = [0_u8; 1];
        client.read_exact(&mut byte).await.expect("client read");
        let id = proxy
            .diagnostics()
            .last_connection_id
            .expect("connection id");

        let mut uncounted = 0_u64;
        for iteration in 1..=ITERATIONS {
            proxy
                .pause(Direction::TargetToClient, id)
                .await
                .expect("pause");
            if proxy.stats().paused_target_to_client < iteration {
                uncounted += 1;
            }
            proxy
                .resume(Direction::TargetToClient, id)
                .await
                .expect("resume");
            // Let the counter settle so every iteration starts from `iteration`.
            for _ in 0..1_000 {
                if proxy.stats().paused_target_to_client >= iteration {
                    break;
                }
                tokio::task::yield_now().await;
            }
        }
        assert_eq!(
            uncounted, 0,
            "{uncounted} of {ITERATIONS} acknowledged pauses were not yet counted"
        );
        assert_eq!(proxy.stats().paused_target_to_client, ITERATIONS);

        client.shutdown().await.expect("client shutdown");
        proxy.shutdown().await.expect("shutdown");
        target_task.await.expect("target task");
    }

    #[tokio::test]
    async fn snapshots_are_bounded_and_record_peak_active_connections() {
        let target = TcpListener::bind(("127.0.0.1", 0)).await.expect("target");
        let target_addr = target.local_addr().expect("target addr");
        let target_task = tokio::spawn(spawn_echo_target(target, 3));
        let proxy = TcpProxy::bind(target_addr, ProxyConfig::default())
            .await
            .expect("proxy");
        let mut clients = Vec::new();
        for _ in 0..3 {
            clients.push(
                tokio::net::TcpStream::connect(proxy.local_addr())
                    .await
                    .expect("client"),
            );
        }
        wait_for_accepts(&proxy, 3).await;
        // Accepted client sockets do not prove that every upstream target
        // connection has completed yet.  Exercise one opaque byte on each
        // route before teardown so the target helper cannot wait forever for
        // an upstream accept that shutdown canceled before it started.
        for (index, client) in clients.iter_mut().enumerate() {
            let payload = [index as u8 + 1];
            client.write_all(&payload).await.expect("client write");
            let mut response = [0_u8; 1];
            client.read_exact(&mut response).await.expect("client read");
            assert_eq!(response, payload);
        }
        let snapshot = proxy.diagnostics();
        assert_eq!(snapshot.peak_active, 3);
        assert_eq!(snapshot.last_connection_id, Some(ConnectionId::new(3)));
        assert!(snapshot.recent_connection_ids.len() <= MAX_RECENT_CONNECTION_IDS);
        assert_eq!(
            snapshot.recent_connection_ids,
            vec![
                ConnectionId::new(1),
                ConnectionId::new(2),
                ConnectionId::new(3),
            ]
        );
        assert_eq!(snapshot.active_connections.len(), 3);
        for (index, client) in clients.iter().enumerate() {
            assert_eq!(
                snapshot.active_connections[index].id,
                ConnectionId::new(index as u64 + 1)
            );
            assert_eq!(
                snapshot.active_connections[index].source_addr,
                client.local_addr().expect("client source")
            );
        }

        drop(clients);
        timeout(Duration::from_secs(2), proxy.shutdown())
            .await
            .expect("proxy shutdown bounded")
            .expect("shutdown");
        timeout(Duration::from_secs(2), target_task)
            .await
            .expect("target task bounded")
            .expect("target task");
    }

    #[tokio::test]
    async fn pause_all_blocks_existing_and_new_connections_until_resume() {
        let target = TcpListener::bind(("127.0.0.1", 0)).await.expect("target");
        let target_addr = target.local_addr().expect("target addr");
        let (accepted_tx, mut accepted_rx) = mpsc::channel(2);
        let (started_tx, mut started_rx) = mpsc::channel(2);
        let (read_tx, mut read_rx) = mpsc::channel(2);
        let (start_tx, start_rx) = oneshot::channel();
        let target_task = tokio::spawn(async move {
            let mut streams = Vec::new();
            for index in 0..2 {
                let (stream, _) = target.accept().await.expect("target accept");
                accepted_tx
                    .send(index)
                    .await
                    .expect("target accepted signal");
                streams.push(stream);
            }
            start_rx.await.expect("target start");
            let mut workers = JoinSet::new();
            for (index, mut stream) in streams.into_iter().enumerate() {
                let started_tx = started_tx.clone();
                let read_tx = read_tx.clone();
                workers.spawn(async move {
                    started_tx.send(index).await.expect("target started signal");
                    stream
                        .write_all(&[0xa0 + index as u8])
                        .await
                        .expect("target write");
                    let mut payload = [0_u8; 1];
                    stream.read_exact(&mut payload).await.expect("target read");
                    read_tx
                        .send((index, payload[0]))
                        .await
                        .expect("target read signal");
                    stream.write_all(&payload).await.expect("target echo");
                });
            }
            drop(started_tx);
            drop(read_tx);
            while workers.join_next().await.is_some() {}
        });
        let proxy = TcpProxy::bind(target_addr, ProxyConfig::default())
            .await
            .expect("proxy");
        let mut existing = tokio::net::TcpStream::connect(proxy.local_addr())
            .await
            .expect("existing client");
        wait_for_accepts(&proxy, 1).await;
        timeout(Duration::from_secs(1), accepted_rx.recv())
            .await
            .expect("existing target accepted")
            .expect("existing target acceptance signal");

        proxy.pause_all().await.expect("pause all");

        let mut new = tokio::net::TcpStream::connect(proxy.local_addr())
            .await
            .expect("new client");
        wait_for_accepts(&proxy, 2).await;
        timeout(Duration::from_secs(1), accepted_rx.recv())
            .await
            .expect("new target accepted")
            .expect("new target acceptance signal");
        existing.write_all(&[0x11]).await.expect("existing write");
        new.write_all(&[0x22]).await.expect("new write");
        start_tx.send(()).expect("target start send");
        timeout(Duration::from_secs(1), started_rx.recv())
            .await
            .expect("first target worker started")
            .expect("first target worker signal");
        timeout(Duration::from_secs(1), started_rx.recv())
            .await
            .expect("second target worker started")
            .expect("second target worker signal");

        let mut existing_blocked = [0_u8; 1];
        assert!(
            timeout(
                Duration::from_millis(100),
                existing.read(&mut existing_blocked)
            )
            .await
            .is_err()
        );
        let mut new_blocked = [0_u8; 1];
        assert!(
            timeout(Duration::from_millis(100), new.read(&mut new_blocked))
                .await
                .is_err()
        );
        assert!(
            timeout(Duration::from_millis(100), read_rx.recv())
                .await
                .is_err()
        );

        proxy.resume_all().await.expect("resume all");
        let first_read = timeout(Duration::from_secs(1), read_rx.recv())
            .await
            .expect("first target read")
            .expect("first target read signal");
        let second_read = timeout(Duration::from_secs(1), read_rx.recv())
            .await
            .expect("second target read")
            .expect("second target read signal");
        assert_eq!(
            vec![first_read, second_read]
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>(),
            [(0, 0x11), (1, 0x22)].into_iter().collect()
        );

        let mut existing_response = [0_u8; 2];
        existing
            .read_exact(&mut existing_response)
            .await
            .expect("existing response");
        assert_eq!(existing_response, [0xa0, 0x11]);
        let mut new_response = [0_u8; 2];
        new.read_exact(&mut new_response)
            .await
            .expect("new response");
        assert_eq!(new_response, [0xa1, 0x22]);

        drop(existing);
        drop(new);
        proxy.shutdown().await.expect("proxy shutdown");
        timeout(Duration::from_secs(1), target_task)
            .await
            .expect("target task bounded")
            .expect("target task");
    }
}
