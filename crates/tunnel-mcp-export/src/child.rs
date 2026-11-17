//! Supervision of one MCP stdio child process.
//!
//! * The executable, arguments, environment and working directory come only
//!   from validated configuration.  The environment is cleared before the
//!   explicit and inherited names are set; nothing runs through a shell.
//! * stdout is reserved for newline-delimited JSON-RPC.  Each line must be one
//!   strict JSON object of at most the message limit, or the child is killed
//!   and its consumers see an interruption.
//! * stderr is drained so the child cannot block on it, and only its byte
//!   count is kept: it is never forwarded, logged or retained.
//! * The child is started in its own process group, and every end of its
//!   life (kill, crash, normal exit, session end) signals the whole group
//!   with `SIGKILL`, so a wrapper (`npx`, `uvx`, a shell script) cannot leave
//!   the real server or its helpers running.  The group signal goes through
//!   `rustix` (a maintained safe wrapper), keeping this crate
//!   `forbid(unsafe_code)`.  A descendant that leaves the group (`setsid`,
//!   `setpgid`, a daemon double fork) is outside this boundary and is not
//!   killed.  The group is signalled after the leader is reaped; POSIX keeps
//!   a process-group ID from being reused while any member lives, so the
//!   signal reaches only surviving members of this group.
//! * That group kill only happens on an end of life **this process lives to
//!   see**.  A `SIGKILL`, a `process::exit` or a crash of the device runs no
//!   `Drop` at all, so before this it left the whole group orphaned — not
//!   only an escaping descendant, but the ordinary `npx` wrapper's real
//!   server, the case the group kill exists for.  Each child is therefore
//!   also watched by a [`tunnel_deadman`] sentinel: a sibling process holding
//!   the read end of a pipe this process holds the write end of, which
//!   `SIGKILL`s the group when that pipe reaches end of file for any reason.
//!   The sentinel is stood down only after the child has been killed and
//!   reaped.  **It does not widen the group kill's reach**: a descendant that
//!   left the group escapes the sentinel exactly as it escapes the
//!   supervisor, and `docs/tasks.md` M3-09 records which mechanisms would and
//!   would not close that on which platform.
//! * Dropping the [`ChildHandle`] sends the process group `SIGKILL`
//!   synchronously, in `Drop`, while the leader is not known to be reaped;
//!   the supervisor task reaps the leader.  The synchronous signal is what
//!   holds when a runtime is torn down without polling that task (task row
//!   M6-C28, ported from `tunnel-acp-export`).
//!   Nothing is shared across child I/O but the child's published phase: a
//!   writer task owns stdin, a reader task owns stdout and a supervisor task
//!   owns the process.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::{mpsc, watch};
use tunnel_mcp::json::compact_object;

use crate::config::StdioBackend;

/// Queued lines towards the child's stdin.
pub const STDIN_QUEUE: usize = 32;
/// Queued messages from the child's stdout.
pub const STDOUT_QUEUE: usize = 32;

/// One JSON-RPC message the child wrote.  `Debug` prints no payload.
pub struct ChildMessage {
    pub compact: Bytes,
    pub value: Value,
}

impl std::fmt::Debug for ChildMessage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ChildMessage")
            .field("bytes", &self.compact.len())
            .finish()
    }
}

/// Why the child's message stream ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChildEnd {
    /// stdout reached end of file (the child exited or closed it).
    Closed,
    /// A stdout line was not one strict JSON object.
    InvalidOutput,
    /// A stdout line exceeded the message limit.
    OversizedMessage,
    /// stdout failed to read.
    ReadFailed,
}

/// An event from the child's stdout.
#[derive(Debug)]
pub enum ChildEvent {
    Message(ChildMessage),
    Ended(ChildEnd),
}

/// Payload-free counters shared by every child of one export.
#[derive(Debug, Default)]
pub struct ChildCounters {
    pub spawned: AtomicU64,
    pub spawn_failed: AtomicU64,
    pub exited: AtomicU64,
    pub killed: AtomicU64,
    pub invalid_output: AtomicU64,
    pub stderr_bytes: AtomicU64,
    pub running: AtomicU64,
    /// Process-group kills sent (each end of a child's life sends one).
    pub group_kills: AtomicU64,
    /// Children for which a parent-death sentinel was armed.  A child counted
    /// in `spawned` but not here is one whose group survives this process
    /// being `SIGKILL`ed.
    pub deadman_armed: AtomicU64,
    /// Sentinels that **reported** standing down after their child was killed
    /// and reaped.  Counted from the sentinel's own exit status, not from the
    /// supervisor having asked, so a sentinel that fired on the way out is
    /// not recorded here.
    pub deadman_stood_down: AtomicU64,
}

/// A spawn failure.  Carries no path or OS message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpawnError;

/// Where one child process is in its life.
///
/// A kill can be asked for before the reap or after it, and the I/O tasks
/// stop on the request either way -- after a natural exit that is what ends a
/// reader whose pipe a descendant outside the group still holds open.  So
/// "reaped" remembers whether a stop was ever requested.  Whether stdin is
/// still open is orthogonal and is the stdin queue's own state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChildPhase {
    /// Spawned; nobody has asked for it to end and it has not been reaped.
    Running,
    /// A kill was asked for and the reap has not happened yet.
    KillRequested,
    /// Reaped, its group signalled and its sentinel resolved.
    Exited {
        /// Whether a kill was asked for, before the reap or after it.
        stop_requested: bool,
    },
}

/// What can happen to a child's phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChildTransition {
    /// The owner, the reader or a dropped handle asked for the child to end.
    KillRequested,
    /// The supervising task reaped the process.
    Reaped,
}

/// A transition the phase refuses: a repeated kill request, or a second reap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IllegalChildTransition;

impl ChildPhase {
    /// The only place a child's phase changes.
    ///
    /// # Errors
    /// [`IllegalChildTransition`] when the event changes nothing: a kill
    /// already requested, or a process already reaped.
    pub const fn on_event(self, event: ChildTransition) -> Result<Self, IllegalChildTransition> {
        match (self, event) {
            (Self::Running, ChildTransition::KillRequested) => Ok(Self::KillRequested),
            (Self::Running, ChildTransition::Reaped) => Ok(Self::Exited {
                stop_requested: false,
            }),
            (Self::KillRequested, ChildTransition::Reaped)
            | (
                Self::Exited {
                    stop_requested: false,
                },
                ChildTransition::KillRequested,
            ) => Ok(Self::Exited {
                stop_requested: true,
            }),
            (Self::KillRequested, ChildTransition::KillRequested)
            | (
                Self::Exited {
                    stop_requested: true,
                },
                ChildTransition::KillRequested,
            )
            | (Self::Exited { .. }, ChildTransition::Reaped) => Err(IllegalChildTransition),
        }
    }

    /// Whether anything has asked for the child to end.
    #[must_use]
    pub const fn stop_requested(self) -> bool {
        matches!(
            self,
            Self::KillRequested
                | Self::Exited {
                    stop_requested: true
                }
        )
    }

    /// Whether the process has been reaped.
    #[must_use]
    pub const fn is_exited(self) -> bool {
        matches!(self, Self::Exited { .. })
    }
}

/// The one published phase of a child, and the only way to change it.
///
/// Every holder shares one `watch` value.  Each writer applies exactly one
/// [`ChildPhase::on_event`] step to it; nothing else is ever done under the
/// channel, so readers sample a phase and never a half-applied one.
#[derive(Clone, Debug)]
pub(crate) struct PhaseCell(watch::Sender<ChildPhase>);

impl PhaseCell {
    fn new() -> Self {
        Self(watch::Sender::new(ChildPhase::Running))
    }

    /// Apply one transition.  Returns whether the phase changed.
    fn apply(&self, event: ChildTransition) -> bool {
        self.0
            .send_if_modified(|phase| match phase.on_event(event) {
                Ok(next) => {
                    *phase = next;
                    true
                }
                Err(IllegalChildTransition) => false,
            })
    }

    /// Ask for the child to end.  Idempotent.
    pub(crate) fn request_kill(&self) {
        let _ = self.apply(ChildTransition::KillRequested);
    }

    fn get(&self) -> ChildPhase {
        *self.0.borrow()
    }

    /// Resolves once a stop has been requested, whenever that was.
    pub(crate) async fn stop_requested(&self) {
        let mut phase = self.0.subscribe();
        let _ = phase.wait_for(|phase| phase.stop_requested()).await;
    }

    /// Resolves once the process has been reaped.
    async fn exited(&self) {
        let mut phase = self.0.subscribe();
        let _ = phase.wait_for(|phase| phase.is_exited()).await;
    }
}

/// The owner's handle.  Dropping it kills the child's process group.
#[derive(Debug)]
pub struct ChildHandle {
    stdin: mpsc::Sender<Bytes>,
    phase: PhaseCell,
    pid: Option<u32>,
}

impl ChildHandle {
    /// Queue one compact JSON-RPC message as a line.  `Err` when the child's
    /// stdin is gone.
    pub async fn send(&self, compact: &[u8]) -> Result<(), ()> {
        let mut line = Vec::with_capacity(compact.len() + 1);
        line.extend_from_slice(compact);
        line.push(b'\n');
        self.stdin.send(Bytes::from(line)).await.map_err(|_| ())
    }

    /// Kill the child now.
    pub fn kill(&self) {
        self.phase.request_kill();
    }

    /// The child's current phase.
    #[must_use]
    pub fn phase(&self) -> ChildPhase {
        self.phase.get()
    }

    /// Resolves once the process has been reaped.
    pub async fn wait_exited(&self) {
        self.phase.exited().await;
    }

    /// The handle the export's own tasks use to end this child.
    pub(crate) fn kill_switch(&self) -> PhaseCell {
        self.phase.clone()
    }
}

impl Drop for ChildHandle {
    /// Kill the child's process group **synchronously, here** (task row
    /// M6-C28, the port of `tunnel-acp-export`'s M8-C07 fix).
    ///
    /// Cancelling the token is not enough: the task that acts on it is a
    /// tokio task, and when a runtime is torn down -- returning from `main`
    /// straight after a kill request, a panic unwinding `main`, a panicking
    /// `#[tokio::test]` -- that task is dropped rather than run.
    /// `kill_on_drop` then kills the **leader only**, and the group is left to
    /// the sentinel, or alive when none is installed.  This is one `rustix`
    /// syscall, so it can run in `Drop` on any thread with no runtime at all.
    ///
    /// The signal is sent only while `exited` says the leader has not been
    /// reaped, which **narrows** the window in which `pid` could name some
    /// other group; it does not close it.  POSIX keeps a process-group ID from
    /// being reused while any member lives, but that argument assumes the
    /// supervisor task is the only reaper, and it is not: during runtime
    /// teardown tokio's own orphan reaper can reap the `kill_on_drop`ped
    /// leader before this runs, while `exited` is still false.  The remaining
    /// race is microseconds wide and needs pid wraparound on top, so it is
    /// theoretical -- but it is narrowed, not eliminated.
    fn drop(&mut self) {
        self.phase.request_kill();
        if !self.phase.get().is_exited() {
            let _ = kill_group(self.pid);
        }
    }
}

/// Spawn the configured child.
///
/// # Errors
/// [`SpawnError`] when the process cannot be started.
pub fn spawn(
    backend: &StdioBackend,
    message_limit: u64,
    counters: &Arc<ChildCounters>,
) -> Result<(ChildHandle, mpsc::Receiver<ChildEvent>), SpawnError> {
    let mut command = Command::new(&backend.command);
    command
        .args(&backend.args)
        .env_clear()
        .current_dir(&backend.workspace)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    for name in &backend.inherit_env {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command.envs(&backend.env);
    let mut child = command.spawn().map_err(|_| {
        counters.spawn_failed.fetch_add(1, Ordering::Relaxed);
        SpawnError
    })?;
    let (Some(stdin), Some(stdout), Some(stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        counters.spawn_failed.fetch_add(1, Ordering::Relaxed);
        return Err(SpawnError);
    };
    let group = child.id();
    counters.spawned.fetch_add(1, Ordering::Relaxed);
    counters.running.fetch_add(1, Ordering::Relaxed);
    // Armed before any task can end the child.  A window remains, between the
    // spawn above and this line, in which a device crash leaves this group
    // unwatched; it is microseconds and cannot be closed without arming the
    // sentinel before the pid it watches exists, but it is not zero and is not
    // claimed to be.
    let deadman = group.and_then(tunnel_deadman::Deadman::arm);
    if deadman.is_some() {
        counters.deadman_armed.fetch_add(1, Ordering::Relaxed);
    }

    let phase = PhaseCell::new();
    let (stdin_tx, stdin_rx) = mpsc::channel(STDIN_QUEUE);
    let (events_tx, events_rx) = mpsc::channel(STDOUT_QUEUE);

    tokio::spawn(write_stdin(stdin, stdin_rx, phase.clone()));
    tokio::spawn(read_stdout(
        stdout,
        events_tx,
        message_limit,
        phase.clone(),
        Arc::clone(counters),
    ));
    tokio::spawn(drain_stderr(stderr, Arc::clone(counters)));
    let supervisor_counters = Arc::clone(counters);
    let mut supervised = ReapGuard {
        phase: phase.clone(),
        group,
        reaped: false,
        child,
    };
    tokio::spawn(async move {
        tokio::select! {
            _ = supervised.child.wait() => {}
            () = supervised.phase.stop_requested() => {
                supervisor_counters.killed.fetch_add(1, Ordering::Relaxed);
                // Signal the group while its leader is still unreaped, so the
                // group id cannot have been reissued to another process.
                let _ = kill_group(group);
                let _ = supervised.child.start_kill();
                let _ = supervised.child.wait().await;
            }
        }
        // The leader is reaped and the group signal follows with no await
        // between: from here the guard must not signal the group again.
        supervised.reaped = true;
        // Whatever ended the leader, no member of its group may outlive it.
        if kill_group(group) {
            supervisor_counters
                .group_kills
                .fetch_add(1, Ordering::Relaxed);
        }
        supervisor_counters.exited.fetch_add(1, Ordering::Relaxed);
        supervisor_counters.running.fetch_sub(1, Ordering::Relaxed);
        // Only now: the leader is reaped and the group is signalled, so the
        // sentinel has nothing left to watch.  (It *does* briefly outlive the
        // freed group id — that is a trade the deadman module documents, not
        // the reason for this ordering.)
        //
        // **Standing it down any earlier reopens the trigger hole for the
        // length of the gap.**  The sentinel exits on the stand-down token
        // *without signalling anything* — `tunnel_deadman::watch` returns
        // before it reaches `kill_group` — so between an early stand-down and
        // the kill above, the group would be alive and unwatched, and a
        // `SIGKILL` of this process in that interval would leak it.
        //
        // Nothing observable distinguishes the two orderings, which was
        // measured rather than assumed: with the block hoisted above the kill,
        // all six tests in `tunnel-mcp-fixture`'s `process_residue` stay green,
        // `deadman_stood_down` included — in both orderings the group dies from
        // the `kill_group` above and the sentinel exits stood-down.  So
        // `docs/tasks.md` M3-09 names this ordering as held by construction
        // with no test, instead of pretending a test covers it.
        if let Some(deadman) = deadman {
            // `stand_down` writes a byte and reaps; it blocks only for as long
            // as the sentinel takes to exit, but it does block, so it does not
            // belong on a runtime worker.  The counter follows the sentinel's
            // own exit status, never the fact that it was asked: a sentinel
            // that fired anyway must not be recorded as an orderly shutdown.
            if tokio::task::spawn_blocking(move || deadman.stand_down())
                .await
                .unwrap_or(false)
            {
                supervisor_counters
                    .deadman_stood_down
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        // The guard publishes `Reaped`, here and on no other orderly path.
        drop(supervised);
    });

    Ok((
        ChildHandle {
            stdin: stdin_tx,
            phase,
            pid: group,
        },
        events_rx,
    ))
}

/// Publishes the terminal phase when the supervising task ends, **however it
/// ends**.
///
/// Every holder of the phase keeps the channel open, so a supervising task
/// that is dropped instead of run to its end -- a runtime torn down, a panic
/// -- would otherwise leave [`ChildHandle::wait_exited`] pending for ever.  The task
/// owns this guard from the moment it is created, before it is first polled,
/// so there is no way for the task to go away without the phase reaching
/// `Exited`.
///
/// On that abnormal path the guard also signals the group, while the leader
/// is still unreaped: `child` is a field, so it is dropped (and
/// `kill_on_drop` kills the leader) only after this `Drop` has run.  The
/// owner's handle skips its own group signal once the phase says exited, so
/// the signal must not be left to it.
struct ReapGuard {
    phase: PhaseCell,
    group: Option<u32>,
    /// Whether the task reaped the leader; it signals the group itself then.
    reaped: bool,
    child: tokio::process::Child,
}

impl Drop for ReapGuard {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = kill_group(self.group);
        }
        let _ = self.phase.apply(ChildTransition::Reaped);
    }
}

/// Send `SIGKILL` to the process group led by `leader`.  Returns whether a
/// group signal was attempted.
#[cfg(unix)]
fn kill_group(leader: Option<u32>) -> bool {
    let Some(pid) = leader
        .and_then(|pid| i32::try_from(pid).ok())
        .and_then(rustix::process::Pid::from_raw)
    else {
        return false;
    };
    // ESRCH (no surviving member) is expected and ignored.
    let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    true
}

#[cfg(not(unix))]
fn kill_group(_leader: Option<u32>) -> bool {
    false
}

async fn write_stdin(
    mut stdin: tokio::process::ChildStdin,
    mut lines: mpsc::Receiver<Bytes>,
    kill: PhaseCell,
) {
    loop {
        let line = tokio::select! {
            () = kill.stop_requested() => return,
            line = lines.recv() => line,
        };
        let Some(line) = line else { return };
        let written = tokio::select! {
            () = kill.stop_requested() => return,
            written = async {
                stdin.write_all(&line).await?;
                stdin.flush().await
            } => written,
        };
        if written.is_err() {
            return;
        }
    }
}

async fn read_stdout(
    stdout: tokio::process::ChildStdout,
    events: mpsc::Sender<ChildEvent>,
    limit: u64,
    kill: PhaseCell,
    counters: Arc<ChildCounters>,
) {
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    let mut reader = BufReader::new(stdout);
    let mut line: Vec<u8> = Vec::new();
    let end = loop {
        let buffer = tokio::select! {
            () = kill.stop_requested() => break ChildEnd::Closed,
            buffer = reader.fill_buf() => buffer,
        };
        let buffer = match buffer {
            Ok(buffer) => buffer,
            Err(_) => break ChildEnd::ReadFailed,
        };
        if buffer.is_empty() {
            break ChildEnd::Closed;
        }
        let (take, complete) = match buffer.iter().position(|byte| *byte == b'\n') {
            Some(index) => (index, true),
            None => (buffer.len(), false),
        };
        if line.len().saturating_add(take) > limit {
            break ChildEnd::OversizedMessage;
        }
        line.extend_from_slice(&buffer[..take]);
        reader.consume(if complete { take + 1 } else { take });
        if !complete {
            continue;
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            line.clear();
            continue;
        }
        let Ok(compact) = compact_object(&line) else {
            break ChildEnd::InvalidOutput;
        };
        let Ok(value) = serde_json::from_slice::<Value>(&compact) else {
            break ChildEnd::InvalidOutput;
        };
        line.clear();
        let message = ChildEvent::Message(ChildMessage {
            compact: Bytes::from(compact),
            value,
        });
        if events.send(message).await.is_err() {
            // Nobody listens any more: the owner dropped the child.
            return;
        }
    };
    if matches!(end, ChildEnd::InvalidOutput | ChildEnd::OversizedMessage) {
        counters.invalid_output.fetch_add(1, Ordering::Relaxed);
        kill.request_kill();
    }
    let _ = events.send(ChildEvent::Ended(end)).await;
}

async fn drain_stderr(mut stderr: tokio::process::ChildStderr, counters: Arc<ChildCounters>) {
    let mut buffer = [0u8; 4096];
    loop {
        match stderr.read(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(read) => {
                counters
                    .stderr_bytes
                    .fetch_add(read as u64, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod phase_tests {
    use super::{ChildPhase, ChildTransition, IllegalChildTransition, PhaseCell};

    const NATURAL: ChildPhase = ChildPhase::Exited {
        stop_requested: false,
    };
    const STOPPED: ChildPhase = ChildPhase::Exited {
        stop_requested: true,
    };

    #[test]
    fn every_legal_transition_reaches_the_phase_it_names() {
        use ChildTransition::{KillRequested, Reaped};
        assert_eq!(
            ChildPhase::Running.on_event(KillRequested),
            Ok(ChildPhase::KillRequested)
        );
        assert_eq!(ChildPhase::Running.on_event(Reaped), Ok(NATURAL));
        assert_eq!(ChildPhase::KillRequested.on_event(Reaped), Ok(STOPPED));
        // A kill asked for after a natural exit is remembered, so an I/O task
        // still waiting on an inherited pipe stops.
        assert_eq!(NATURAL.on_event(KillRequested), Ok(STOPPED));
    }

    #[test]
    fn a_repeated_request_and_a_second_reap_are_refused() {
        use ChildTransition::{KillRequested, Reaped};
        assert_eq!(
            ChildPhase::KillRequested.on_event(KillRequested),
            Err(IllegalChildTransition)
        );
        assert_eq!(STOPPED.on_event(KillRequested), Err(IllegalChildTransition));
        assert_eq!(NATURAL.on_event(Reaped), Err(IllegalChildTransition));
        assert_eq!(STOPPED.on_event(Reaped), Err(IllegalChildTransition));
    }

    #[test]
    fn the_predicates_read_the_phase() {
        assert!(!ChildPhase::Running.stop_requested());
        assert!(!ChildPhase::Running.is_exited());
        assert!(ChildPhase::KillRequested.stop_requested());
        assert!(!ChildPhase::KillRequested.is_exited());
        assert!(!NATURAL.stop_requested());
        assert!(NATURAL.is_exited());
        assert!(STOPPED.stop_requested());
        assert!(STOPPED.is_exited());
    }

    #[test]
    fn the_cell_applies_one_step_and_reports_a_refusal_as_no_change() {
        let cell = PhaseCell::new();
        assert_eq!(cell.get(), ChildPhase::Running);
        assert!(cell.apply(ChildTransition::KillRequested));
        assert!(!cell.apply(ChildTransition::KillRequested));
        assert_eq!(cell.get(), ChildPhase::KillRequested);
        assert!(cell.apply(ChildTransition::Reaped));
        assert!(!cell.apply(ChildTransition::Reaped));
        assert_eq!(cell.get(), STOPPED);
    }
}

#[cfg(all(test, unix))]
mod supervisor_gone_tests {
    use std::sync::Arc;
    use std::time::Duration;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
    }

    /// Every holder of the phase keeps its channel open, so a supervising
    /// task that is dropped rather than run to its end -- here, by tearing
    /// its runtime down -- must still publish the terminal phase, or
    /// `wait_exited` never resolves.  One child's supervisor has been polled
    /// and is parked in its `select!`; the other's was never polled at all.
    #[test]
    fn waiters_resolve_when_the_supervising_task_is_dropped() {
        let workspace = tempfile::tempdir().expect("workspace");
        let counters = Arc::new(super::ChildCounters::default());
        let backend = crate::config::StdioBackend {
            command: "/bin/sh".into(),
            args: vec!["-c".to_owned(), "exec sleep 180".to_owned()],
            env: std::collections::BTreeMap::new(),
            inherit_env: Vec::new(),
            workspace: workspace.path().to_path_buf(),
            max_children: 1,
            session_idle: Duration::from_secs(60),
        };
        let start = || super::spawn(&backend, 1 << 20, &counters).expect("started");
        let first = runtime();
        let (polled, unpolled) = first.block_on(async {
            let polled = start();
            tokio::time::sleep(Duration::from_millis(50)).await;
            (polled, start())
        });
        assert!(!polled.0.phase().is_exited());
        assert!(!unpolled.0.phase().is_exited());
        drop(first);

        runtime().block_on(async {
            for (child, _events) in [&polled, &unpolled] {
                tokio::time::timeout(Duration::from_secs(10), child.wait_exited())
                    .await
                    .expect("a dropped supervisor still publishes the terminal phase");
                assert!(child.phase().is_exited());
            }
        });
    }
}
