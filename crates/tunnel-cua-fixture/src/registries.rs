//! The one owner of a device's input authority: its lease registry and its
//! capture registry, as a single piece of state held by a single task.
//!
//! **Why one task and not two shared registries.** The two are only correct
//! together: a lease dropped without its captures leaves a consumer able to
//! re-acquire and click at coordinates from an image a dead backend produced,
//! and captures dropped without the lease leave one session holding
//! exclusivity against a backend that never granted it. So nothing outside
//! this module can reach either registry. Every operation is a [`Command`],
//! the owner takes them one at a time in the order they were queued, and it
//! applies each one whole before it looks at the next. An invalidation and a
//! plan are therefore never interleaved, and no plan reads one registry from
//! before an invalidation and the other from after it.
//!
//! # The ordering an invalidation relies on
//!
//! A plan is only ever computed by the owner, from a queued
//! [`Command::Plan`]. Queue order alone would order a plan behind an
//! invalidation that was *queued* first, but not behind one that was
//! requested first and was still waiting for room in a full queue. So an
//! invalidation is requested in two steps: a count of requests is advanced
//! synchronously, before any waiting, and then the command is queued. The
//! owner reads that count before applying **every** command and, if a request
//! it has not yet honoured is outstanding, empties both registries first
//! ([`Owner::fence`]). An invalidation therefore takes effect no later than
//! the next command the owner applies, wherever its own command is in the
//! queue -- and even if it never arrives because its caller stopped waiting.
//! See [`Registries::invalidate`].
//!
//! The count is one independent monotonic word with one meaning ("this many
//! invalidations have been asked for"); it guards nothing and nobody waits on
//! it. The registries themselves are still touched by the owner alone.
//!
//! # Bound and backpressure
//!
//! The queue holds [`QUEUE`] commands. A caller that finds it full waits for
//! room; nothing is dropped and nothing is tried-and-abandoned. Every command
//! is pure and bounded -- the planner cannot block and nothing here does I/O
//! -- so the wait is the time the owner needs to work through at most
//! [`QUEUE`] such commands.
//!
//! # When the owner is gone
//!
//! The owner ends only when the last handle is dropped, so a caller holding a
//! handle normally always reaches it. The exception is the runtime it was
//! started on shutting down underneath a handle that outlives it. Every
//! accessor then **fails closed**: a plan is refused as not dispatched, a
//! lease is not granted, and no capture identity is issued. The registries
//! went with the owner, so nothing is still held either.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use tokio::sync::{mpsc, oneshot};

use tunnel_cua::capture::{CaptureIdentity, Captures};
use tunnel_cua::lease::{
    GrantRevision, InputLeases, LeaseGrant, LeaseRefusal, SessionId, TargetSession,
};
use tunnel_cua::operation::Operation;
use tunnel_cua::outcome::{Dispatch, NotDispatched};
use tunnel_cua::plan::{Planned, SessionContext, plan};
use tunnel_cua::supervision::{BackendGeneration, Invalidation, RESTART_RESIDUE};

/// Commands the owner may hold unread. See this module's header for what a
/// full queue does.
pub(crate) const QUEUE: usize = 64;

/// What one session's request is planned against, other than the registries.
pub(crate) struct PlanRequest {
    pub(crate) body: Vec<u8>,
    pub(crate) limit: u64,
    pub(crate) permitted: Arc<BTreeSet<Operation>>,
    pub(crate) session: SessionId,
    pub(crate) target: TargetSession,
    pub(crate) grant_revision: GrantRevision,
}

/// A successful capture to record.
pub(crate) struct CaptureRecord {
    pub(crate) target: TargetSession,
    pub(crate) display: u32,
    pub(crate) width: u32,
    pub(crate) height: u32,
    /// The declared scale, or `None` when nobody declared one.
    pub(crate) scale_percent: Option<u32>,
}

enum Command {
    Plan(Box<PlanRequest>, oneshot::Sender<Result<Planned, Dispatch>>),
    Acquire {
        target: TargetSession,
        session: SessionId,
        revision: GrantRevision,
        reply: oneshot::Sender<Result<LeaseGrant, LeaseRefusal>>,
    },
    Release(LeaseGrant, oneshot::Sender<Result<(), LeaseRefusal>>),
    ReconcileGrant {
        session: SessionId,
        revision: GrantRevision,
        reply: oneshot::Sender<Vec<TargetSession>>,
    },
    EndSession(SessionId, oneshot::Sender<Vec<TargetSession>>),
    Holder(TargetSession, oneshot::Sender<Option<SessionId>>),
    CaptureCount(oneshot::Sender<usize>),
    Record(CaptureRecord, oneshot::Sender<Option<CaptureIdentity>>),
    Invalidate(BackendGeneration, oneshot::Sender<Invalidation>),
}

/// Both registries, owned by value by the one task that runs [`Owner::run`].
struct Owner {
    leases: InputLeases,
    captures: Captures,
    /// How many invalidations have been asked for. Advanced by the handles.
    requested: Arc<AtomicU64>,
    /// The value of `requested` this owner has already honoured.
    honoured: u64,
    /// What [`Owner::fence`] freed ahead of the command that asked for it,
    /// kept so the next invalidation to arrive reports it rather than losing
    /// it. Bounded by what the registries can hold between two invalidations.
    freed_early: Vec<TargetSession>,
    forgotten_early: usize,
}

impl Owner {
    async fn run(mut self, mut commands: mpsc::Receiver<Command>) {
        while let Some(command) = commands.recv().await {
            self.apply(command);
        }
    }

    /// Honour every invalidation that has been asked for and not yet applied:
    /// empty both registries, together, before the command in hand is looked
    /// at.
    ///
    /// This is what closes the interval between an invalidation being
    /// requested and its command reaching the front of the queue. The request
    /// advanced `requested` before it waited for anything, and that happened
    /// before any command sent afterwards was sent, so by the time the owner
    /// applies such a command it reads the advanced count here.
    fn fence(&mut self) {
        let requested = self.requested.load(Ordering::SeqCst);
        if requested == self.honoured {
            return;
        }
        self.honoured = requested;
        self.freed_early.extend(self.leases.invalidate_all());
        self.forgotten_early += self.captures.invalidate_all();
    }

    /// Apply one command whole. Synchronous on purpose: there is no await
    /// between reading the registries and answering, so no other command can
    /// be applied part-way through this one.
    ///
    /// A reply nobody is waiting for is discarded; the command has still been
    /// applied.
    fn apply(&mut self, command: Command) {
        self.fence();
        match command {
            Command::Plan(request, reply) => {
                let context = SessionContext {
                    session: request.session,
                    target: &request.target,
                    grant_revision: request.grant_revision,
                    leases: &self.leases,
                    captures: &self.captures,
                };
                let planned = plan(&request.body, request.limit, &request.permitted, &context);
                let _ = reply.send(planned);
            }
            Command::Acquire {
                target,
                session,
                revision,
                reply,
            } => {
                let _ = reply.send(self.leases.acquire(&target, session, revision));
            }
            Command::Release(grant, reply) => {
                let _ = reply.send(self.leases.release(&grant));
            }
            Command::ReconcileGrant {
                session,
                revision,
                reply,
            } => {
                let _ = reply.send(self.leases.reconcile_grant(session, revision));
            }
            Command::EndSession(session, reply) => {
                let _ = reply.send(self.leases.release_all_for_session(session));
            }
            Command::Holder(target, reply) => {
                let _ = reply.send(self.leases.holder(&target));
            }
            Command::CaptureCount(reply) => {
                let _ = reply.send(self.captures.len());
            }
            Command::Record(capture, reply) => {
                let recorded = match capture.scale_percent {
                    Some(percent) => self.captures.record(
                        &capture.target,
                        capture.display,
                        capture.width,
                        capture.height,
                        percent,
                    ),
                    None => self.captures.record_undeclared_scale(
                        &capture.target,
                        capture.display,
                        capture.width,
                        capture.height,
                    ),
                };
                let _ = reply.send(recorded.ok());
            }
            Command::Invalidate(generation, reply) => {
                // The fence above has already honoured this request. This
                // call drops whatever was taken between that and now, which
                // keeps the queue-order meaning as well: nothing queued ahead
                // of an invalidation survives it.
                let mut invalidation = tunnel_cua::supervision::invalidate(
                    &mut self.leases,
                    &mut self.captures,
                    generation,
                );
                let mut released = core::mem::take(&mut self.freed_early);
                released.append(&mut invalidation.leases_released);
                invalidation.leases_released = released;
                invalidation.captures_forgotten += core::mem::take(&mut self.forgotten_early);
                let _ = reply.send(invalidation);
            }
        }
    }
}

/// The handle on a device's registries.
///
/// The owner is started on first use rather than at construction, so building
/// a device's state needs no runtime. Until then the registries are empty,
/// which is also what a freshly started owner holds.
#[derive(Debug, Default)]
pub(crate) struct Registries {
    owner: OnceLock<mpsc::Sender<Command>>,
    /// How many invalidations have been asked for; see [`Owner::fence`].
    requested: Arc<AtomicU64>,
}

impl Registries {
    fn owner(&self) -> &mpsc::Sender<Command> {
        self.owner.get_or_init(|| {
            let (commands, receiver) = mpsc::channel(QUEUE);
            let owner = Owner {
                leases: InputLeases::default(),
                captures: Captures::default(),
                requested: Arc::clone(&self.requested),
                honoured: 0,
                freed_early: Vec::new(),
                forgotten_early: 0,
            };
            tokio::spawn(owner.run(receiver));
            commands
        })
    }

    /// How many more commands the queue will take without a caller waiting.
    #[cfg(test)]
    pub(crate) fn room(&self) -> usize {
        self.owner().capacity()
    }

    /// Queue one command and wait for the owner's answer; `None` only if the
    /// owner is gone (see this module's header).
    async fn ask<T>(&self, command: impl FnOnce(oneshot::Sender<T>) -> Command) -> Option<T> {
        let (reply, answer) = oneshot::channel();
        self.owner().send(command(reply)).await.ok()?;
        answer.await.ok()
    }

    pub(crate) async fn plan(&self, request: PlanRequest) -> Result<Planned, Dispatch> {
        self.ask(|reply| Command::Plan(Box::new(request), reply))
            .await
            // Fail closed: with no owner there is no lease to have checked.
            .unwrap_or(Err(Dispatch::NotDispatched(NotDispatched::NotReached)))
    }

    pub(crate) async fn acquire(
        &self,
        target: &TargetSession,
        session: SessionId,
        revision: GrantRevision,
    ) -> Result<LeaseGrant, LeaseRefusal> {
        let target = target.clone();
        self.ask(|reply| Command::Acquire {
            target,
            session,
            revision,
            reply,
        })
        .await
        .unwrap_or(Err(LeaseRefusal::NotHeld))
    }

    pub(crate) async fn release(&self, grant: &LeaseGrant) -> Result<(), LeaseRefusal> {
        let grant = grant.clone();
        self.ask(|reply| Command::Release(grant, reply))
            .await
            .unwrap_or(Err(LeaseRefusal::NotHeld))
    }

    pub(crate) async fn reconcile_grant(
        &self,
        session: SessionId,
        revision: GrantRevision,
    ) -> Vec<TargetSession> {
        self.ask(|reply| Command::ReconcileGrant {
            session,
            revision,
            reply,
        })
        .await
        .unwrap_or_default()
    }

    /// [`Registries::reconcile_grant`], with a step of the caller's own made
    /// part of the same request.
    ///
    /// `commit` runs at the instant the reconcile is queued and not before:
    /// room in the queue is reserved first, and from there to the command
    /// being queued there is no await. So a caller cancelled while waiting
    /// has neither run `commit` nor queued anything, and a caller cancelled
    /// afterwards has done both -- the owner applies the reconcile whether or
    /// not anybody is left to hear the answer.
    pub(crate) async fn reconcile_grant_with(
        &self,
        session: SessionId,
        revision: GrantRevision,
        commit: impl FnOnce(),
    ) -> Vec<TargetSession> {
        let Ok(permit) = self.owner().reserve().await else {
            commit();
            return Vec::new();
        };
        let (reply, answer) = oneshot::channel();
        commit();
        permit.send(Command::ReconcileGrant {
            session,
            revision,
            reply,
        });
        answer.await.unwrap_or_default()
    }

    pub(crate) async fn end_session(&self, session: SessionId) -> Vec<TargetSession> {
        self.ask(|reply| Command::EndSession(session, reply))
            .await
            .unwrap_or_default()
    }

    pub(crate) async fn holder(&self, target: &TargetSession) -> Option<SessionId> {
        let target = target.clone();
        self.ask(|reply| Command::Holder(target, reply))
            .await
            .flatten()
    }

    pub(crate) async fn capture_count(&self) -> usize {
        self.ask(Command::CaptureCount).await.unwrap_or_default()
    }

    pub(crate) async fn record(&self, capture: CaptureRecord) -> Option<CaptureIdentity> {
        self.ask(|reply| Command::Record(capture, reply))
            .await
            .flatten()
    }

    /// Drop every lease and forget every capture identity, together.
    ///
    /// **No input can be planned between this being requested and applied.**
    /// The request is made by the first poll of this future, synchronously
    /// and before it waits for anything: it advances the count the owner
    /// reads before applying every command. The owner is the only thing that
    /// plans, so any plan it computes from then on -- one already queued, one
    /// queued while this caller is still waiting for room, or one asked for
    /// later -- is computed after [`Owner::fence`] has emptied both
    /// registries, and is refused for want of a lease. A plan the owner had
    /// already computed was planned before the invalidation was requested.
    ///
    /// **A request made is never lost.** If this future is dropped after its
    /// first poll, at any point, the invalidation is still applied before the
    /// owner's next command; only the report goes to a later invalidation
    /// instead. The future resolves after the owner has applied this
    /// invalidation's own command, so a caller that awaits it knows it has
    /// taken effect.
    pub(crate) async fn invalidate(&self, generation: BackendGeneration) -> Invalidation {
        self.requested.fetch_add(1, Ordering::SeqCst);
        self.ask(|reply| Command::Invalidate(generation, reply))
            .await
            // The registries went with the owner: nothing is held, and every
            // later plan is refused. The residue declaration is unconditional
            // here for the reason it is in `tunnel_cua::supervision`.
            .unwrap_or(Invalidation {
                generation,
                leases_released: Vec::new(),
                captures_forgotten: 0,
                residue: RESTART_RESIDUE,
            })
    }
}
