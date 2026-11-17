//! The session as a pure state machine.
//!
//! No socket, no clock, no filesystem and no resolver.  [`Session`] is fed
//! decoded [`Frame`]s and answers, for each request, either a [`SessionError`]
//! or an [`Accepted`] saying which gate-1 [`Primitive`]s it needs and which
//! validated [`VirtualPath`]s it names.  That pair is the whole interface gate 4
//! needs: authorize the primitives against the live grant, hand the paths to
//! gate 2's resolver, then report the outcome through [`Session::complete`] or
//! [`Session::fail`].
//!
//! # State is applied on the reply, never on the request
//!
//! The single most important rule in the file.  A `Twalk` does not bind
//! `newfid`; the `Rwalk` does, and only when the walk arrived — a **partial**
//! walk binds nothing.  A `Tlopen` does not mark a fid open; the `Rlopen` does.
//! Mutating on the request and rolling back on failure would mean a failed walk
//! had briefly bound a fid that a concurrent request could have used.
//!
//! Two deliberate exceptions, both from 9P itself and both recorded here rather
//! than discovered later: `Tclunk` and `Tremove` release their fid on **either**
//! answer, because the fid is unusable after either.  A client that had to
//! guess whether a failed clunk left a fid behind would leak fids against its
//! own quota.
//!
//! # What this machine authorizes, and what it cannot
//!
//! It checks its grant on every request, before anything else about the request
//! is acted on.  It **cannot** check freshness: `docs/filesystem-api.md` and
//! `docs/cluster.md` require the grant to be rechecked after each asynchronous
//! queue wait and immediately before each primitive side effect, and a machine
//! with no clock and no queue has neither event to hook.  Gate 4 owns that
//! recheck; this is the static half of it.

use std::collections::{BTreeMap, BTreeSet};

use tunnel_fs_core::{
    CapabilitySet, FeatureSet, Limits, PathBounds, Primitive, VirtualPath, admits_session,
};

use crate::codec::{DIALECT, Frame, negotiate};
use crate::error::SessionError;
use crate::flags::{
    O_ACCMODE, O_APPEND, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY, Primitives, create_primitives,
    getattr_primitives, open_primitives, setattr_primitives, unlinkat_primitives,
};
use crate::message::{Message, MessageType};
use crate::wire::{NOFID, NONUNAME, NOTAG, Qid, QidKind};

/// Where the session is in its lifecycle.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Phase {
    /// Nothing but `Tversion` is accepted.
    AwaitingVersion,
    /// `Tversion` answered; only `Tattach` and `Tflush` are accepted.
    Versioned,
    /// The root fid is bound; the profile's full request set is accepted.
    Attached,
    /// Ended.  Nothing is accepted.
    Closed,
}

/// How a fid is open, if it is.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct OpenMode {
    /// The fid may be read from.
    pub read: bool,
    /// The fid may be written to.
    pub write: bool,
    /// The fid names a directory and is enumerated rather than read.
    pub directory: bool,
}

/// What the session knows about one live fid.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FidState {
    path: VirtualPath,
    qid: Qid,
    open: Option<OpenMode>,
    generation: u64,
}

impl FidState {
    /// The virtual path this fid names.
    #[must_use]
    pub const fn path(&self) -> &VirtualPath {
        &self.path
    }

    /// The qid the provider reported for it.
    #[must_use]
    pub const fn qid(&self) -> Qid {
        self.qid
    }

    /// How the fid is open, or `None` if it is not.
    #[must_use]
    pub const fn open(&self) -> Option<OpenMode> {
        self.open
    }

    /// Whether the fid names a directory.
    #[must_use]
    pub fn is_directory(&self) -> bool {
        self.qid.kind == QidKind::Directory
    }

    /// Which **binding** of this fid number this is.
    ///
    /// A fid number says nothing on its own: a client may clunk one and walk a
    /// new file to the same number while a request naming the old binding is
    /// still outstanding.  The generation distinguishes the two, and it is what
    /// this machine checks before a late reply is allowed to touch a fid.  It
    /// is exported because gate 4 holds a resolved descriptor per fid and needs
    /// the same distinction: a descriptor cached against generation *n* must
    /// not be reused once the number carries generation *n + 1*.
    ///
    /// Monotonic within a session, never reused, and never zero for a live fid.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

/// What one fid number holds in a session.
///
/// A number that holds nothing is absent from the session's fid table, and a
/// released one leaves it; a number is therefore reserved **or** bound, never
/// both.
#[derive(Clone, Debug, Eq, PartialEq)]
enum FidSlot {
    /// A request has claimed the number and no reply has bound it yet.
    ///
    /// Reserved at request time so two concurrent `Twalk`s cannot both claim
    /// one `newfid`, and so the fid quota counts work already in flight.
    Reserved(VirtualPath),
    /// A reply bound the number.  Whether it is open is
    /// [`FidState::open`].
    Bound(FidState),
}

/// Everything that can change what a fid number holds.
#[derive(Clone, Debug, Eq, PartialEq)]
enum FidEvent {
    /// A request claims the number for the path it would bind.
    Reserve(VirtualPath),
    /// The claiming request is over without binding.
    Unreserve,
    /// The claiming request's reply binds the number.
    Bind {
        path: VirtualPath,
        qid: Qid,
        generation: u64,
    },
    /// A walk in place moves the binding it was admitted against.
    Rebind {
        admitted: u64,
        path: VirtualPath,
        qid: Qid,
        generation: u64,
    },
    /// An `Rlopen` for the binding the open was admitted against.
    Open {
        admitted: u64,
        qid: Qid,
        mode: OpenMode,
    },
    /// An `Rlcreate` rebinds the number to the child it made, open.
    Create {
        admitted: u64,
        child: VirtualPath,
        qid: Qid,
        mode: OpenMode,
        generation: u64,
    },
    /// A clunk or remove of the binding it was admitted against.
    Release { admitted: u64 },
}

impl FidSlot {
    /// The only place a fid number's contents change.  The first value is
    /// what the number holds afterwards (`None` is nothing); the second is
    /// whether the event applied.  A refused event changes nothing: it found
    /// the number absent, or held by something other than what the event
    /// was admitted against.
    fn on_event(slot: Option<Self>, event: FidEvent) -> (Option<Self>, bool) {
        match (slot, event) {
            (None, FidEvent::Reserve(path)) => (Some(Self::Reserved(path)), true),
            (Some(Self::Reserved(_)), FidEvent::Unreserve) => (None, true),
            (
                Some(Self::Reserved(_)),
                FidEvent::Bind {
                    path,
                    qid,
                    generation,
                },
            ) => (
                Some(Self::Bound(FidState {
                    path,
                    qid,
                    open: None,
                    generation,
                })),
                true,
            ),
            (
                Some(Self::Bound(state)),
                FidEvent::Rebind {
                    admitted,
                    path,
                    qid,
                    generation,
                },
            ) if state.generation == admitted => (
                Some(Self::Bound(FidState {
                    path,
                    qid,
                    open: None,
                    generation,
                })),
                true,
            ),
            (
                Some(Self::Bound(state)),
                FidEvent::Open {
                    admitted,
                    qid,
                    mode,
                },
            ) if state.generation == admitted => (
                Some(Self::Bound(FidState {
                    qid,
                    open: Some(mode),
                    ..state
                })),
                true,
            ),
            (
                Some(Self::Bound(state)),
                FidEvent::Create {
                    admitted,
                    child,
                    qid,
                    mode,
                    generation,
                },
            ) if state.generation == admitted => (
                Some(Self::Bound(FidState {
                    path: child,
                    qid,
                    open: Some(mode),
                    generation,
                })),
                true,
            ),
            (Some(Self::Bound(state)), FidEvent::Release { admitted })
                if state.generation == admitted =>
            {
                (None, true)
            }
            (slot, _) => (slot, false),
        }
    }
}

/// The virtual paths a request names.
///
/// Every variant carries only already-validated [`VirtualPath`]s, so gate 4
/// never re-derives a path from wire bytes and gate 2's resolver is the only
/// thing that turns one into a descriptor.  Both endpoints of a rename and both
/// of a link are separate paths, because the contract confines them
/// independently and there is no implicit cross-export move.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequestPaths {
    /// The request names no node: `Tversion`, `Tflush`.
    Session,
    /// One existing node.
    Node(VirtualPath),
    /// A walk: where it starts and where a complete walk would end.
    ///
    /// A partial walk stops short of `destination`; the `Rwalk`'s qid count
    /// says how far it got, and `newfid` is bound only for a walk that arrived.
    Walk {
        /// Where the walk starts.
        origin: VirtualPath,
        /// Where a complete walk ends.
        destination: VirtualPath,
    },
    /// A name inside a parent directory, created or removed.
    Child {
        /// The parent directory.
        parent: VirtualPath,
        /// The child the request names.
        child: VirtualPath,
    },
    /// Two independently confined endpoints.
    Pair {
        /// The source.
        source: VirtualPath,
        /// The destination.
        destination: VirtualPath,
    },
}

/// An admitted request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Accepted {
    /// Every primitive the request requires, as a conjunction.
    ///
    /// Already checked against this session's grant.  Gate 4 rechecks them
    /// against the **live** grant after any queue wait.
    pub primitives: Primitives,
    /// The paths the request names.
    pub paths: RequestPaths,
    /// The `msize` a `Tversion` settled on, and `None` for everything else.
    pub negotiated_msize: Option<u32>,
}

/// What a successful reply does to the fid table.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Effect {
    /// Nothing.
    None,
    /// Bind the reserved root fid.
    Attach { fid: u32 },
    /// Bind `newfid` to `destination`, but only for a complete walk.
    Walk {
        origin: u32,
        /// The binding `origin` carried when the walk was admitted.
        origin_generation: u64,
        newfid: u32,
        destination: VirtualPath,
        names: usize,
        reserved: bool,
    },
    /// Mark `fid` open.
    Open {
        fid: u32,
        /// The binding `fid` carried when the open was admitted.
        generation: u64,
        mode: OpenMode,
    },
    /// Rebind `fid` to the created child and mark it open.
    Create {
        fid: u32,
        /// The binding `fid` carried when the create was admitted.
        generation: u64,
        child: VirtualPath,
        mode: OpenMode,
    },
    /// Release `fid` whatever the answer is.
    Release {
        fid: u32,
        /// The binding `fid` carried when the clunk or remove was admitted.
        ///
        /// Two `Tclunk`s of one fid can be outstanding at once, and the first
        /// reply frees the number for a fresh walk.  Without this stamp the
        /// second reply deleted whatever now held that number: the client's
        /// live fid vanished while gate 4 still held a descriptor for it.
        generation: u64,
    },
    /// The reply carries a byte count the request bounded.
    ///
    /// `Tread` and `Treaddir` bound their reply's `data`; `Twrite` bounds the
    /// `count` an `Rwrite` may acknowledge, because a provider cannot have
    /// written more bytes than the request carried.  Without this the session
    /// would accept an `Rread` of a hundred bytes for a two-byte `Tread`, which
    /// is the same class of unchecked reply as an `Rwalk` longer than its
    /// `Twalk`.
    CountedReply { limit: u32 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TagState {
    message_type: MessageType,
    /// This tag belongs to a `Tflush`, and this is the tag it flushes.  Fixed
    /// when the tag is admitted.
    flushing: Option<u16>,
    phase: TagPhase,
}

/// Where one outstanding tag is between its request and its release.
///
/// A released tag has no phase: it leaves the session's tag table, which is
/// the only place a tag can be found.
#[derive(Clone, Debug, Eq, PartialEq)]
enum TagPhase {
    /// The request is outstanding and no `Tflush` names it.
    Pending { effect: Effect },
    /// The request is outstanding and at least one `Tflush` names it.
    ///
    /// `by` is every `Tflush` currently outstanding against this tag, and is
    /// never empty.  A **set**, not one tag: 9P allows several flushes of one
    /// request, and a single slot meant the second flush overwrote the first.
    /// Releasing then keyed on the flush's own `flushing` field alone, so the
    /// first `Rflush` freed the tag, the client could re-issue on it — and
    /// the second `Rflush` then cancelled that new request and undid its
    /// reservation.  Membership is what makes a re-issued request safe: it is
    /// `Pending`, with no set at all, so no stale `Rflush` can ever match it.
    FlushRequested { effect: Effect, by: BTreeSet<u16> },
    /// The original reply arrived while a flush was still pending.
    ///
    /// `docs/filesystem-api.md`: "Respect a normal reply arriving before
    /// `Rflush`, and reserve the flushed tag until the flush response."  The
    /// reply's effect was applied, so none is carried; the tag is held, and
    /// unusable, for the flushes in `by`, which is never empty.
    Answered { by: BTreeSet<u16> },
}

/// Everything that can change a [`TagPhase`].
#[derive(Clone, Debug, Eq, PartialEq)]
enum TagEvent {
    /// A `Tflush` carrying this tag was admitted against the request.
    FlushAdmitted(u16),
    /// The request's own reply or `Rlerror` arrived.  `flush_live` says
    /// whether a live `Tflush` still names the tag.
    Replied { flush_live: bool },
    /// The `Tflush` `flush` against this tag was answered with `Rflush`;
    /// `remaining` is every other live flush still outstanding against it.
    FlushAnswered {
        flush: u16,
        remaining: BTreeSet<u16>,
    },
    /// The `Tflush` `flush` against this tag ended without happening;
    /// `remaining` is every other live flush still outstanding against it.
    FlushCancelled {
        flush: u16,
        remaining: BTreeSet<u16>,
    },
}

/// What a tag transition decided.
#[derive(Clone, Debug, Eq, PartialEq)]
enum TagOutcome {
    /// The tag stays in the table.
    Held,
    /// The tag is released with nothing left to undo.
    Released,
    /// The tag is released by a flush before its own reply arrived: the
    /// request is cancelled, and the reservation its effect made goes with
    /// it.
    Cancelled(Effect),
    /// The event does not apply in this phase; nothing changed.
    Refused,
}

impl TagPhase {
    /// The effect a reply would apply, while the request is unanswered.
    const fn effect(&self) -> Option<&Effect> {
        match self {
            Self::Pending { effect } | Self::FlushRequested { effect, .. } => Some(effect),
            Self::Answered { .. } => None,
        }
    }

    /// The flushes recorded against this tag.
    const fn flushed_by(&self) -> Option<&BTreeSet<u16>> {
        match self {
            Self::Pending { .. } => None,
            Self::FlushRequested { by, .. } | Self::Answered { by } => Some(by),
        }
    }

    fn is_flushed_by(&self, flush: u16) -> bool {
        self.flushed_by().is_some_and(|by| by.contains(&flush))
    }

    /// The only place a tag's phase changes.  `None` is a released tag.
    fn on_event(self, event: TagEvent) -> (Option<Self>, TagOutcome) {
        match (self, event) {
            (Self::Pending { effect }, TagEvent::FlushAdmitted(flush)) => (
                Some(Self::FlushRequested {
                    effect,
                    by: BTreeSet::from([flush]),
                }),
                TagOutcome::Held,
            ),
            (Self::FlushRequested { effect, mut by }, TagEvent::FlushAdmitted(flush)) => {
                by.insert(flush);
                (Some(Self::FlushRequested { effect, by }), TagOutcome::Held)
            }
            (Self::Answered { mut by }, TagEvent::FlushAdmitted(flush)) => {
                by.insert(flush);
                (Some(Self::Answered { by }), TagOutcome::Held)
            }
            // The original reply arrived before its `Rflush`.  It is honoured
            // — its effect has already been applied — but the tag stays
            // reserved, and unusable, until **every** flush outstanding
            // against it has been answered.
            (Self::FlushRequested { by, .. }, TagEvent::Replied { flush_live: true }) => {
                (Some(Self::Answered { by }), TagOutcome::Held)
            }
            (Self::Pending { .. } | Self::FlushRequested { .. }, TagEvent::Replied { .. }) => {
                (None, TagOutcome::Released)
            }
            // A second reply on a tag whose original answer already arrived.
            (phase @ Self::Answered { .. }, TagEvent::Replied { .. }) => {
                (Some(phase), TagOutcome::Refused)
            }
            (
                phase,
                TagEvent::FlushAnswered { flush, .. } | TagEvent::FlushCancelled { flush, .. },
            ) if !phase.is_flushed_by(flush) => (Some(phase), TagOutcome::Refused),
            // The contract's "reserve the flushed tag until the flush
            // response" means the **last** response when there are several.
            (
                Self::FlushRequested { effect, .. },
                TagEvent::FlushAnswered { remaining, .. }
                | TagEvent::FlushCancelled { remaining, .. },
            ) if !remaining.is_empty() => (
                Some(Self::FlushRequested {
                    effect,
                    by: remaining,
                }),
                TagOutcome::Held,
            ),
            (
                Self::Answered { .. },
                TagEvent::FlushAnswered { remaining, .. }
                | TagEvent::FlushCancelled { remaining, .. },
            ) if !remaining.is_empty() => {
                (Some(Self::Answered { by: remaining }), TagOutcome::Held)
            }
            // An `Rflush` releases the tag it flushed, whether or not the
            // original reply ever arrived.
            (Self::FlushRequested { effect, .. }, TagEvent::FlushAnswered { .. }) => {
                (None, TagOutcome::Cancelled(effect))
            }
            // A cancelled flush is not an answered one: the request it named
            // is still outstanding, now with no flush against it.
            (Self::FlushRequested { effect, .. }, TagEvent::FlushCancelled { .. }) => {
                (Some(Self::Pending { effect }), TagOutcome::Held)
            }
            // Held only for flushes, and the last of them is gone.
            (
                Self::Answered { .. },
                TagEvent::FlushAnswered { .. } | TagEvent::FlushCancelled { .. },
            ) => (None, TagOutcome::Released),
            // Unreachable: a pending tag is flushed by nothing, so the
            // membership guard above already refused these.
            (
                phase @ Self::Pending { .. },
                TagEvent::FlushAnswered { .. } | TagEvent::FlushCancelled { .. },
            ) => (Some(phase), TagOutcome::Refused),
        }
    }
}

/// How a retiring `Tflush` ended, which decides what happens to its victim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FlushOutcome {
    /// An `Rflush` arrived: the flush happened, so its victim is released.
    Answered,
    /// The flush ended without happening — an `Rlerror`, or the flush was
    /// itself flushed — so its victim is **not** released.
    Cancelled,
}

/// The pure 9P session state machine.
#[derive(Clone, Debug)]
pub struct Session {
    phase: Phase,
    grant: CapabilitySet,
    features: FeatureSet,
    limits: Limits,
    bounds: PathBounds,
    msize: u32,
    pending_msize: Option<u32>,
    tags: BTreeMap<u16, TagState>,
    /// Every fid number that holds something: reserved by a request no
    /// reply has bound yet, or bound.
    fids: BTreeMap<u32, FidSlot>,
    /// Hands out the stamp on [`FidState::generation`].  Monotonic, never
    /// reused, and never zero, so a stale effect can be told from a live one.
    next_generation: u64,
}

impl Session {
    /// Build a session for a grant.
    ///
    /// Returns `None` for an empty grant: gate 1's `admits_session` says an
    /// export granting nothing admits no session at all, rather than admitting
    /// one that can do nothing.
    #[must_use]
    pub fn new(grant: CapabilitySet, features: FeatureSet, limits: Limits) -> Option<Self> {
        if !admits_session(grant) {
            return None;
        }
        let msize = u32::try_from(limits.max_message_bytes()).unwrap_or(u32::MAX);
        Some(Self {
            phase: Phase::AwaitingVersion,
            grant,
            features,
            limits,
            bounds: limits.path_bounds(),
            msize,
            pending_msize: None,
            tags: BTreeMap::new(),
            fids: BTreeMap::new(),
            next_generation: 0,
        })
    }

    /// The current phase.
    #[must_use]
    pub const fn phase(&self) -> Phase {
        self.phase
    }

    /// The `msize` in force.  This side's ceiling until `Rversion` commits one.
    #[must_use]
    pub const fn msize(&self) -> u32 {
        self.msize
    }

    /// The grant this session was admitted for.
    #[must_use]
    pub const fn grant(&self) -> CapabilitySet {
        self.grant
    }

    /// The features the provider implements.
    #[must_use]
    pub const fn features(&self) -> FeatureSet {
        self.features
    }

    /// How many tags are outstanding, including tags a flush still reserves.
    #[must_use]
    pub fn outstanding_tags(&self) -> usize {
        self.tags.len()
    }

    /// How many fids are live, counting those no reply has bound yet.
    #[must_use]
    pub fn live_fids(&self) -> usize {
        self.fids.len()
    }

    /// The state of one bound fid.
    #[must_use]
    pub fn fid(&self, fid: u32) -> Option<&FidState> {
        match self.fids.get(&fid) {
            Some(FidSlot::Bound(state)) => Some(state),
            Some(FidSlot::Reserved(_)) | None => None,
        }
    }

    /// Apply one event to what `fid` holds.  False if it was refused.
    fn fid_event(&mut self, fid: u32, event: FidEvent) -> bool {
        let (slot, applied) = FidSlot::on_event(self.fids.remove(&fid), event);
        if let Some(slot) = slot {
            self.fids.insert(fid, slot);
        }
        applied
    }

    /// Whether `fid` is reserved by a request no reply has bound yet.
    fn is_reserved(&self, fid: u32) -> bool {
        matches!(self.fids.get(&fid), Some(FidSlot::Reserved(_)))
    }

    /// The binding of `fid` a request was admitted against, if the number
    /// still carries it.
    fn admitted_fid(&self, fid: u32, admitted: u64) -> Option<&FidState> {
        self.fid(fid).filter(|state| state.generation == admitted)
    }

    /// Whether `tag` is outstanding.
    #[must_use]
    pub fn has_tag(&self, tag: u16) -> bool {
        self.tags.contains_key(&tag)
    }

    /// End the session, forgetting every tag and fid.
    ///
    /// Cancelling pending operations and clunking remaining fids within a
    /// deadline is gate 4's; this only forgets them, which is what makes a fid
    /// from a closed session unusable when the same numbers appear again.
    pub fn close(&mut self) {
        self.phase = Phase::Closed;
        self.tags.clear();
        self.fids.clear();
    }

    /// The primitives a frame decodes to, without admitting it.
    ///
    /// [`Session::request`] classifies a frame and then throws the
    /// classification away when it refuses one, so a caller that wants to know
    /// **what** it refused has nothing to ask.  This is that question, and it
    /// is deliberately the *same* computation rather than a second one: a
    /// caller re-deriving a request's primitives from its opcode would get
    /// `Tlopen` wrong, because whether an open is a mutation is decided by its
    /// flag word — `O_TRUNC` discards content and `O_WRONLY` alone does not.
    ///
    /// `None` for a frame this session could not classify at all, which is a
    /// narrower answer than it looks: a request refused for its *fid state* —
    /// a `Twrite` to a fid that is not open for writing — is refused before
    /// any primitive is decided, so the session never formed an opinion about
    /// whether it was a mutation and this does not invent one.
    ///
    /// Pure: it reads the session and changes nothing. That does **not** make
    /// it insensitive to when it is asked — a refusal may close the session,
    /// and a closed session classifies to `Err(Closed)` and so answers `None`.
    /// Ask it before the refusal is delivered, which is what the call site in
    /// `Provider::accept` does and why it does it there.
    #[must_use]
    pub fn required_primitives(&self, frame: &Frame) -> Option<Primitives> {
        self.classify(frame)
            .ok()
            .map(|(accepted, _)| accepted.primitives)
    }

    /// Admit one request.
    ///
    /// # Errors
    ///
    /// Every [`SessionError`].  [`SessionError::answer`] says whether the
    /// caller replies `Rlerror` or closes the socket.
    pub fn request(&mut self, frame: &Frame) -> Result<Accepted, SessionError> {
        if self.phase == Phase::Closed {
            return Err(SessionError::Closed);
        }
        if !frame.message.is_request() {
            return Err(SessionError::UnexpectedReply);
        }
        let (accepted, effect) = self.classify(frame)?;
        // The grant is checked before a tag is taken or a fid reserved, so a
        // refused request costs the session nothing.
        for primitive in accepted.primitives.iter() {
            if !primitive.is_permitted(self.grant, self.features) {
                return Err(SessionError::NotPermitted);
            }
        }
        let effect = self.reserve_for(effect)?;
        if let Err(error) = self.reserve_tag(frame, effect.clone()) {
            self.undo_reservation(&effect);
            return Err(error);
        }
        if let Some(msize) = accepted.negotiated_msize {
            self.pending_msize = Some(msize);
        }
        Ok(accepted)
    }

    /// Apply a successful reply and release its tag.
    ///
    /// # Errors
    ///
    /// [`SessionError::TagNotInUse`] for a tag nothing is waiting on,
    /// [`SessionError::UnexpectedReply`] for a reply of the wrong type, and
    /// [`SessionError::MalformedReply`] for one whose fields contradict the
    /// request it answers.
    ///
    /// # Gate 4 must not feed a late reply to this
    ///
    /// A provider reply that arrives **after** its `Rflush` names a tag this
    /// machine has already released, so it answers [`SessionError::TagNotInUse`]
    /// — which is a 1002 close.  That is the right answer for a peer inventing
    /// a tag and the wrong one for an ordinary flush race, and the machine
    /// cannot tell them apart: both look like a reply on a released tag.  **The
    /// dispatcher owns the distinction and must drop a reply whose tag it
    /// flushed rather than passing it here.** The contract already says a
    /// normal reply arriving before `Rflush` is honoured and the tag stays
    /// reserved until the flush response; this is the other side of that
    /// window.
    pub fn complete(&mut self, frame: &Frame) -> Result<(), SessionError> {
        if self.phase == Phase::Closed {
            return Err(SessionError::Closed);
        }
        if frame.message.is_request() {
            return Err(SessionError::UnexpectedReply);
        }
        if frame.message_type() == MessageType::Rversion {
            return self.complete_version(frame);
        }
        let state = self.tags.get(&frame.tag).ok_or(SessionError::TagNotInUse)?;
        let Some(effect) = state.phase.effect().cloned() else {
            // A second reply on a tag whose original answer already arrived.
            return Err(SessionError::TagNotInUse);
        };
        if reply_for(state.message_type) != frame.message_type() {
            return Err(SessionError::UnexpectedReply);
        }
        let applied = self.apply_effect(&effect, &frame.message);
        // Whatever the effect did or refused to do, the request is over: its
        // tag is released and any fid it had reserved but not bound goes with
        // it.  A reservation exists only for an outstanding request, so
        // leaving one behind on an error path would strand a fid number that
        // is neither bound (so it cannot be clunked) nor free (so it cannot be
        // walked to).  After a successful bind this is a no-op, because
        // `apply_effect` consumed the reservation itself.
        self.undo_reservation(&effect);
        self.retire_tag(frame.tag, FlushOutcome::Answered);
        applied
    }

    /// Apply an `Rlerror` and release its tag.
    ///
    /// The request's state changes are **not** applied, except the `Tclunk` and
    /// `Tremove` fid release, which happens either way.
    ///
    /// # A failed `Tflush` is a cancelled flush, not an answered one
    ///
    /// 9P answers `Tflush` only with `Rflush`, so gate 4 will never reach this
    /// with a flush's tag and the case is unreachable in practice.  It is
    /// still worth getting right rather than documenting as impossible: the
    /// two answers differ in what they do to the **victim**, and an `Rlerror`
    /// says the flush did not happen.  Treating it as answered would release
    /// the victim and undo its reservation — cancelling a request on the
    /// strength of a cancellation that failed.  So a failed flush takes the
    /// same path as one that was itself flushed: it leaves its victim's set
    /// without releasing it.
    ///
    /// # Errors
    /// [`SessionError::TagNotInUse`].
    pub fn fail(&mut self, tag: u16) -> Result<(), SessionError> {
        if self.phase == Phase::Closed {
            return Err(SessionError::Closed);
        }
        let state = self.tags.get(&tag).ok_or(SessionError::TagNotInUse)?;
        let Some(effect) = state.phase.effect().cloned() else {
            return Err(SessionError::TagNotInUse);
        };
        match &effect {
            Effect::Release { fid, generation } => self.release_fid(*fid, *generation),
            other => self.undo_reservation(other),
        }
        // An `Rlerror` means the request did not happen, so a failed `Tflush`
        // is a **cancelled** flush rather than an answered one.
        self.retire_tag(tag, FlushOutcome::Cancelled);
        Ok(())
    }

    /// The `Rversion` this session's pending `Tversion` must be answered with.
    ///
    /// Provided so a caller cannot accidentally reply with an `msize` other
    /// than the one negotiation settled on; [`Session::complete`] refuses any
    /// other value.
    #[must_use]
    pub fn version_reply(&self) -> Option<Frame> {
        self.pending_msize.map(|msize| {
            Frame::new(
                NOTAG,
                Message::Rversion {
                    msize,
                    version: DIALECT.to_owned(),
                },
            )
        })
    }

    // ---------------------------------------------------------------- tags

    fn reserve_tag(&mut self, frame: &Frame, effect: Effect) -> Result<(), SessionError> {
        if frame.tag == NOTAG {
            // Only `Tversion` reaches here with NOTAG; the codec guaranteed it.
            // It occupies no tag slot, because nothing may be outstanding
            // alongside the handshake.
            return Ok(());
        }
        if let Some(existing) = self.tags.get(&frame.tag) {
            return Err(match existing.phase {
                TagPhase::Pending { .. } => SessionError::TagInUse,
                TagPhase::FlushRequested { .. } | TagPhase::Answered { .. } => {
                    SessionError::TagReservedByFlush
                }
            });
        }
        let quota = usize::try_from(self.limits.max_inflight_requests()).unwrap_or(usize::MAX);
        if self.tags.len() >= quota {
            return Err(SessionError::TagQuotaExhausted);
        }
        let flushing = match &frame.message {
            Message::Tflush { oldtag } => Some(*oldtag),
            _ => None,
        };
        if let Some(oldtag) = flushing {
            self.transition_tag(oldtag, TagEvent::FlushAdmitted(frame.tag));
        }
        self.tags.insert(
            frame.tag,
            TagState {
                message_type: frame.message_type(),
                flushing,
                phase: TagPhase::Pending { effect },
            },
        );
        Ok(())
    }

    /// Apply one event to an outstanding tag, releasing it from the table if
    /// the transition says so.  `None` for a tag that is not outstanding;
    /// otherwise what the transition decided and the flush target the tag
    /// carried.
    fn transition_tag(&mut self, tag: u16, event: TagEvent) -> Option<(TagOutcome, Option<u16>)> {
        let TagState {
            message_type,
            flushing,
            phase,
        } = self.tags.remove(&tag)?;
        let (next, outcome) = phase.on_event(event);
        if let Some(phase) = next {
            self.tags.insert(
                tag,
                TagState {
                    message_type,
                    flushing,
                    phase,
                },
            );
        }
        Some((outcome, flushing))
    }

    /// Release a tag, honouring the flush reservation.
    fn retire_tag(&mut self, tag: u16, outcome: FlushOutcome) {
        let flush_live = self.tags.get(&tag).is_some_and(|state| {
            state.phase.flushed_by().is_some_and(|by| {
                by.iter()
                    .any(|flush_tag| self.is_live_flush_of(*flush_tag, tag))
            })
        });
        let Some((TagOutcome::Released, flushing)) =
            self.transition_tag(tag, TagEvent::Replied { flush_live })
        else {
            // Still reserved for a live flush (or not outstanding at all).
            return;
        };
        if let Some(flushed) = flushing {
            match outcome {
                FlushOutcome::Answered => self.release_flushed(flushed, tag),
                // A flush that ended without happening leaves its victim's set
                // but does not release it — see `Session::fail`.
                FlushOutcome::Cancelled => self.cancel_flush(flushed, tag),
            }
        }
    }

    /// Whether `flush_tag` is a **live** tag that is a `Tflush` of `victim`.
    ///
    /// The identity of a flush is that pair, not the number.  Testing only
    /// whether the number is outstanding let a *reused* tag count as a flush of
    /// something it had nothing to do with: with a stale entry left in a
    /// target's set and the client re-issuing that number as a flush of some
    /// other tag, the target read as "still flushed" forever — reserved,
    /// un-reissuable, and releasable by nothing. Repeated, that pins the
    /// session's own `maxInflightRequests` one slot at a time.
    fn is_live_flush_of(&self, flush_tag: u16, victim: u16) -> bool {
        self.tags
            .get(&flush_tag)
            .is_some_and(|state| state.flushing == Some(victim))
    }

    /// The flushes still outstanding against `victim`, `excluded` aside.
    fn live_flushes_of(&self, victim: u16, excluded: u16) -> BTreeSet<u16> {
        self.tags
            .get(&victim)
            .and_then(|target| target.phase.flushed_by())
            .map_or_else(BTreeSet::new, |by| {
                by.iter()
                    .copied()
                    .filter(|candidate| {
                        *candidate != excluded && self.is_live_flush_of(*candidate, victim)
                    })
                    .collect()
            })
    }

    /// Answer one `Tflush`: drop it from its target's set, and release the
    /// target once it is the **last** flush outstanding against it.
    ///
    /// Keyed on membership rather than on the flush's own `flushing` field.
    /// That is what makes a re-issued request safe: with two flushes for one
    /// tag, the first `Rflush` must not free the tag — and if it did, the
    /// client could re-issue on it and the second `Rflush` would silently
    /// cancel that new request and undo its reservation, leaving its eventual
    /// reply to close the session with a fatal unknown tag.  A re-issued
    /// request carries an empty set, so no stale `Rflush` can match it.
    fn release_flushed(&mut self, flushed: u16, flush_tag: u16) {
        let event = TagEvent::FlushAnswered {
            flush: flush_tag,
            remaining: self.live_flushes_of(flushed, flush_tag),
        };
        let Some((outcome, flushing)) = self.transition_tag(flushed, event) else {
            return;
        };
        match outcome {
            // Not a flush of this tag, or other flushes still hold it.
            TagOutcome::Refused | TagOutcome::Held => return,
            // An `Rflush` releases the tag it flushed, whether or not the
            // original reply ever arrived — and the flushed request's
            // **reservation** goes with it.  Without that, a flushed `Twalk`
            // or `Tattach` strands its target fid for the life of the
            // session: no reply will ever bind it and no `Tclunk` can release
            // it, because it is not bound, and a client that flushes walks
            // exhausts its own fid quota with nothing to clunk.
            TagOutcome::Cancelled(effect) => self.undo_reservation(&effect),
            // A tag already answered bound its fid and carried no effect, so
            // it has nothing left to undo.
            TagOutcome::Released => {}
        }
        if let Some(victim) = flushing {
            // The tag just removed was itself a `Tflush`, so removing it
            // **cancels** that flush and it must leave its own victim's set —
            // otherwise the victim keeps a member no reply will ever answer.
            self.cancel_flush(victim, flushed);
        }
    }

    /// Remove a cancelled flush from its victim's set.
    ///
    /// A cancelled flush is not an answered one, so this does **not** release
    /// the victim the way [`Session::release_flushed`] does: the victim's own
    /// request may still be outstanding, and undoing its reservation would
    /// cancel a request nobody asked to cancel.  The one case that must still
    /// be collected is a victim held *only* for this flush whose own reply has
    /// already arrived: with the flush gone there is nothing left for it to
    /// wait on, and leaving it would be the same permanent reservation this
    /// method exists to prevent.
    fn cancel_flush(&mut self, victim: u16, flush_tag: u16) {
        let event = TagEvent::FlushCancelled {
            flush: flush_tag,
            remaining: self.live_flushes_of(victim, flush_tag),
        };
        // Held only for a flush that has now been cancelled, and already
        // answered, so it carried no effect and there is nothing to undo.
        if let Some((TagOutcome::Released, Some(next))) = self.transition_tag(victim, event) {
            // It was a flush itself, so cancel it against its own victim too.
            // The chain is finite: every step removes one tag.
            self.cancel_flush(next, victim);
        }
    }

    // ---------------------------------------------------------------- fids

    fn reserve_for(&mut self, effect: Effect) -> Result<Effect, SessionError> {
        match effect {
            Effect::Attach { fid } => {
                self.reserve_fid(fid, VirtualPath::root())?;
                Ok(Effect::Attach { fid })
            }
            Effect::Walk {
                origin,
                origin_generation,
                newfid,
                destination,
                names,
                ..
            } => {
                let reserved = newfid != origin;
                if reserved {
                    self.reserve_fid(newfid, destination.clone())?;
                }
                Ok(Effect::Walk {
                    origin,
                    origin_generation,
                    newfid,
                    destination,
                    names,
                    reserved,
                })
            }
            other => Ok(other),
        }
    }

    fn undo_reservation(&mut self, effect: &Effect) {
        match effect {
            Effect::Attach { fid }
            | Effect::Walk {
                newfid: fid,
                reserved: true,
                ..
            } => {
                // Refused, and harmless, once the reply has bound the fid.
                self.fid_event(*fid, FidEvent::Unreserve);
            }
            _ => {}
        }
    }

    fn reserve_fid(&mut self, fid: u32, path: VirtualPath) -> Result<(), SessionError> {
        if fid == NOFID {
            return Err(SessionError::UnknownFid);
        }
        if self.fids.contains_key(&fid) {
            return Err(SessionError::FidInUse);
        }
        let quota = usize::try_from(self.limits.max_fids()).unwrap_or(usize::MAX);
        if self.live_fids() >= quota {
            return Err(SessionError::FidQuotaExhausted);
        }
        self.fid_event(fid, FidEvent::Reserve(path));
        Ok(())
    }

    /// Hand out the next fid binding stamp.
    ///
    /// `checked_add` rather than `wrapping_add`, so "monotonic, never reused,
    /// never zero" is true without qualification.  Wrapping would have made it
    /// true only up to 2^64 bindings, which is unreachable — a session would
    /// have to bind a fid every nanosecond for five centuries — but a stated
    /// invariant that quietly stops holding at some ceiling is worse than one
    /// that says where it ends.
    fn fresh_generation(&mut self) -> u64 {
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .expect("a session cannot bind 2^64 fids");
        self.next_generation
    }

    /// Whether a `Tattach` is outstanding with no reply yet.
    fn attach_outstanding(&self) -> bool {
        self.tags
            .values()
            .any(|tag| matches!(tag.phase.effect(), Some(Effect::Attach { .. })))
    }

    /// Release `fid`, but only if it still carries the binding the request
    /// was admitted against.
    ///
    /// `Tclunk` and `Tremove` release their fid on **either** answer, so this
    /// is reached from both [`Session::complete`] and [`Session::fail`]; it is
    /// the one apply path that deletes rather than writes, and it needs the
    /// generation for exactly the same reason the others do.
    fn release_fid(&mut self, fid: u32, generation: u64) {
        self.fid_event(
            fid,
            FidEvent::Release {
                admitted: generation,
            },
        );
    }

    fn require_fid(&self, fid: u32) -> Result<&FidState, SessionError> {
        if fid == NOFID {
            return Err(SessionError::UnknownFid);
        }
        self.fid(fid).ok_or(SessionError::UnknownFid)
    }

    // ------------------------------------------------------- classification

    fn classify(&self, frame: &Frame) -> Result<(Accepted, Effect), SessionError> {
        match &frame.message {
            Message::Tversion { msize, version } => {
                // `pending_msize` is the second half of "one `Tversion` per
                // session": the phase alone only moves when the `Rversion`
                // arrives, so a **pipelined** client could otherwise land two
                // `Tversion`s before either was answered, and the second would
                // silently overwrite what the first negotiated.
                if self.phase != Phase::AwaitingVersion || self.pending_msize.is_some() {
                    return Err(SessionError::RepeatedVersion);
                }
                let negotiated = negotiate(*msize, version, self.msize)?;
                Ok((
                    Accepted {
                        primitives: Primitives::one(Primitive::Version),
                        paths: RequestPaths::Session,
                        negotiated_msize: Some(negotiated),
                    },
                    Effect::None,
                ))
            }
            Message::Tattach {
                fid,
                afid,
                uname,
                aname,
                n_uname,
            } => {
                match self.phase {
                    Phase::AwaitingVersion => return Err(SessionError::BeforeVersion),
                    Phase::Attached => return Err(SessionError::RepeatedAttach),
                    Phase::Versioned | Phase::Closed => {}
                }
                // The phase moves only when the `Rattach` arrives, so the
                // outstanding-attach check is what stops a pipelined client
                // binding two root fids before either was answered.
                if self.attach_outstanding() {
                    return Err(SessionError::RepeatedAttach);
                }
                if *afid != NOFID || !uname.is_empty() || !aname.is_empty() || *n_uname != NONUNAME
                {
                    return Err(SessionError::AttachFieldNotPermitted);
                }
                if *fid == NOFID {
                    return Err(SessionError::UnknownFid);
                }
                Ok((
                    Accepted {
                        primitives: Primitives::one(Primitive::Attach),
                        paths: RequestPaths::Node(VirtualPath::root()),
                        negotiated_msize: None,
                    },
                    Effect::Attach { fid: *fid },
                ))
            }
            Message::Tflush { .. } => {
                if self.phase == Phase::AwaitingVersion {
                    return Err(SessionError::BeforeVersion);
                }
                Ok((
                    Accepted {
                        primitives: Primitives::one(Primitive::Flush),
                        paths: RequestPaths::Session,
                        negotiated_msize: None,
                    },
                    Effect::None,
                ))
            }
            _ => self.classify_attached(frame),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn classify_attached(&self, frame: &Frame) -> Result<(Accepted, Effect), SessionError> {
        match self.phase {
            Phase::AwaitingVersion => return Err(SessionError::BeforeVersion),
            Phase::Versioned => return Err(SessionError::BeforeAttach),
            Phase::Attached => {}
            Phase::Closed => return Err(SessionError::Closed),
        }
        let node = |primitives: Primitives, path: &VirtualPath| Accepted {
            primitives,
            paths: RequestPaths::Node(path.clone()),
            negotiated_msize: None,
        };
        let child = |primitives: Primitives, parent: &VirtualPath, child: VirtualPath| Accepted {
            primitives,
            paths: RequestPaths::Child {
                parent: parent.clone(),
                child,
            },
            negotiated_msize: None,
        };
        let pair =
            |primitives: Primitives, source: VirtualPath, destination: VirtualPath| Accepted {
                primitives,
                paths: RequestPaths::Pair {
                    source,
                    destination,
                },
                negotiated_msize: None,
            };
        match &frame.message {
            Message::Twalk { fid, newfid, names } => {
                let origin = self.require_fid(*fid)?;
                if origin.open.is_some() {
                    // 9P: a walk from an open fid is illegal.  The fid's
                    // position and its open mode would otherwise disagree.
                    return Err(SessionError::FidIsOpen);
                }
                if *newfid == NOFID {
                    return Err(SessionError::UnknownFid);
                }
                let mut destination = origin.path.clone();
                for name in names {
                    destination = destination.join(name, self.bounds)?;
                }
                Ok((
                    Accepted {
                        primitives: Primitives::one(Primitive::Walk),
                        paths: RequestPaths::Walk {
                            origin: origin.path.clone(),
                            destination: destination.clone(),
                        },
                        negotiated_msize: None,
                    },
                    Effect::Walk {
                        origin: *fid,
                        origin_generation: origin.generation,
                        newfid: *newfid,
                        destination,
                        names: names.len(),
                        reserved: false,
                    },
                ))
            }
            Message::Tlopen { fid, flags } => {
                let state = self.require_fid(*fid)?;
                if state.open.is_some() {
                    return Err(SessionError::FidIsOpen);
                }
                let directory = state.is_directory();
                let primitives = open_primitives(*flags, directory)?;
                Ok((
                    node(primitives, &state.path),
                    Effect::Open {
                        fid: *fid,
                        generation: state.generation,
                        mode: open_mode(*flags, directory),
                    },
                ))
            }
            Message::Tlcreate {
                fid, name, flags, ..
            } => {
                let parent = self.require_fid(*fid)?;
                if parent.open.is_some() {
                    return Err(SessionError::FidIsOpen);
                }
                if !parent.is_directory() {
                    return Err(SessionError::FidWrongKind);
                }
                let created = parent.path.join(name, self.bounds)?;
                Ok((
                    child(create_primitives(*flags)?, &parent.path, created.clone()),
                    Effect::Create {
                        fid: *fid,
                        generation: parent.generation,
                        child: created,
                        mode: open_mode(*flags, false),
                    },
                ))
            }
            Message::Tmkdir { dfid, name, .. } => {
                let parent = self.require_fid(*dfid)?;
                let made = parent.path.join(name, self.bounds)?;
                Ok((
                    child(Primitives::one(Primitive::Mkdir), &parent.path, made),
                    Effect::None,
                ))
            }
            Message::Tsymlink { fid, name, .. } => {
                let parent = self.require_fid(*fid)?;
                let link = parent.path.join(name, self.bounds)?;
                Ok((
                    child(Primitives::one(Primitive::Symlink), &parent.path, link),
                    Effect::None,
                ))
            }
            Message::Tunlinkat {
                dirfid,
                name,
                flags,
            } => {
                let parent = self.require_fid(*dirfid)?;
                let target = parent.path.join(name, self.bounds)?;
                Ok((
                    child(unlinkat_primitives(*flags)?, &parent.path, target),
                    Effect::None,
                ))
            }
            Message::Tlink { dfid, fid, name } => {
                let source = self.require_fid(*fid)?;
                let parent = self.require_fid(*dfid)?;
                let destination = parent.path.join(name, self.bounds)?;
                Ok((
                    pair(
                        Primitives::one(Primitive::Link),
                        source.path.clone(),
                        destination,
                    ),
                    Effect::None,
                ))
            }
            Message::Trename { fid, dfid, name } => {
                let source = self.require_fid(*fid)?;
                let parent = self.require_fid(*dfid)?;
                let destination = parent.path.join(name, self.bounds)?;
                Ok((
                    pair(
                        Primitives::one(Primitive::Rename),
                        source.path.clone(),
                        destination,
                    ),
                    Effect::None,
                ))
            }
            Message::Trenameat {
                olddirfid,
                oldname,
                newdirfid,
                newname,
            } => {
                let old_parent = self.require_fid(*olddirfid)?;
                let new_parent = self.require_fid(*newdirfid)?;
                let source = old_parent.path.join(oldname, self.bounds)?;
                let destination = new_parent.path.join(newname, self.bounds)?;
                Ok((
                    pair(Primitives::one(Primitive::Rename), source, destination),
                    Effect::None,
                ))
            }
            Message::Tgetattr { fid, request_mask } => {
                let state = self.require_fid(*fid)?;
                Ok((
                    node(getattr_primitives(*request_mask)?, &state.path),
                    Effect::None,
                ))
            }
            Message::Tsetattr { fid, valid, .. } => {
                let state = self.require_fid(*fid)?;
                Ok((node(setattr_primitives(*valid)?, &state.path), Effect::None))
            }
            Message::Treadlink { fid } => {
                let state = self.require_fid(*fid)?;
                Ok((
                    node(Primitives::one(Primitive::Readlink), &state.path),
                    Effect::None,
                ))
            }
            Message::Tread { fid, count, .. } => {
                let state = self.require_fid(*fid)?;
                let open = state.open.ok_or(SessionError::FidNotOpen)?;
                if open.directory {
                    // A directory is enumerated with `Treaddir`, which returns
                    // records.  A byte read of one would hand the caller the
                    // host's own directory layout.
                    return Err(SessionError::FidWrongKind);
                }
                if !open.read {
                    return Err(SessionError::FidNotOpen);
                }
                Ok((
                    node(Primitives::one(Primitive::Read), &state.path),
                    Effect::CountedReply { limit: *count },
                ))
            }
            Message::Twrite { fid, data, .. } => {
                let state = self.require_fid(*fid)?;
                let open = state.open.ok_or(SessionError::FidNotOpen)?;
                if open.directory {
                    return Err(SessionError::FidWrongKind);
                }
                if !open.write {
                    return Err(SessionError::FidNotOpen);
                }
                Ok((
                    node(Primitives::one(Primitive::Write), &state.path),
                    Effect::CountedReply {
                        limit: u32::try_from(data.len()).unwrap_or(u32::MAX),
                    },
                ))
            }
            Message::Treaddir { fid, count, .. } => {
                let state = self.require_fid(*fid)?;
                let open = state.open.ok_or(SessionError::FidNotOpen)?;
                if !open.directory {
                    return Err(SessionError::FidWrongKind);
                }
                Ok((
                    node(Primitives::one(Primitive::Readdir), &state.path),
                    Effect::CountedReply { limit: *count },
                ))
            }
            Message::Tclunk { fid } => {
                let state = self.require_fid(*fid)?;
                Ok((
                    node(Primitives::one(Primitive::Clunk), &state.path),
                    Effect::Release {
                        fid: *fid,
                        generation: state.generation,
                    },
                ))
            }
            Message::Tremove { fid } => {
                let state = self.require_fid(*fid)?;
                // The kind decides the primitive: `Tremove` on a directory is
                // the same authority as `Tunlinkat` with `AT_REMOVEDIR`.
                let primitive = if state.is_directory() {
                    Primitive::RemoveDir
                } else {
                    Primitive::Unlink
                };
                Ok((
                    node(Primitives::one(primitive), &state.path),
                    Effect::Release {
                        fid: *fid,
                        generation: state.generation,
                    },
                ))
            }
            // `Tversion`, `Tattach` and `Tflush` are handled by `classify`, and
            // a reply was refused before classification began.
            _ => Err(SessionError::UnexpectedReply),
        }
    }

    // ------------------------------------------------------------- effects

    fn complete_version(&mut self, frame: &Frame) -> Result<(), SessionError> {
        let Message::Rversion { msize, version } = &frame.message else {
            return Err(SessionError::UnexpectedReply);
        };
        if self.phase != Phase::AwaitingVersion {
            return Err(SessionError::RepeatedVersion);
        }
        let expected = self.pending_msize.ok_or(SessionError::TagNotInUse)?;
        if *msize != expected || version != DIALECT {
            return Err(SessionError::MalformedReply);
        }
        self.msize = expected;
        self.pending_msize = None;
        self.phase = Phase::Versioned;
        Ok(())
    }

    fn apply_effect(&mut self, effect: &Effect, reply: &Message) -> Result<(), SessionError> {
        match (effect, reply) {
            (Effect::Attach { fid }, Message::Rattach { qid }) => {
                // A flushed attach released its reservation, so a late
                // `Rattach` binds nothing and leaves the session unattached.
                let Some(FidSlot::Reserved(path)) = self.fids.get(fid).cloned() else {
                    return Ok(());
                };
                if qid.kind != QidKind::Directory {
                    // The export root is a directory.  A provider claiming
                    // otherwise has bound the session to something this profile
                    // cannot serve.
                    self.fid_event(*fid, FidEvent::Unreserve);
                    return Err(SessionError::MalformedReply);
                }
                let generation = self.fresh_generation();
                self.fid_event(
                    *fid,
                    FidEvent::Bind {
                        path,
                        qid: *qid,
                        generation,
                    },
                );
                self.phase = Phase::Attached;
                Ok(())
            }
            (Effect::CountedReply { limit }, Message::Rread { data })
            | (Effect::CountedReply { limit }, Message::Rreaddir { data }) => {
                // A short read is normal; a reply longer than the request asked
                // for is not, and accepting it would let a provider return
                // bytes the caller never made room for.
                if data.len() > *limit as usize {
                    return Err(SessionError::MalformedReply);
                }
                Ok(())
            }
            (Effect::CountedReply { limit }, Message::Rwrite { count }) => {
                // A short write is normal; acknowledging more bytes than the
                // `Twrite` carried is not, and `bytesAcknowledged` is built
                // from these.
                if count > limit {
                    return Err(SessionError::MalformedReply);
                }
                Ok(())
            }
            (
                Effect::Walk {
                    origin,
                    origin_generation,
                    newfid,
                    destination,
                    names,
                    reserved,
                },
                Message::Rwalk { qids },
            ) => {
                if qids.len() > *names {
                    return Err(SessionError::MalformedReply);
                }
                if qids.is_empty() && *names > 0 {
                    // 9P: when the **first** element cannot be walked the
                    // server answers an error reply, not an `Rwalk` carrying
                    // no qids.  Accepting the latter would let a provider
                    // report "nothing found" in a shape the client is supposed
                    // to read as a successful zero-element clone.
                    return Err(SessionError::MalformedReply);
                }
                if qids.len() < *names {
                    // A partial walk binds nothing.  The reservation is
                    // released, and `newfid` is as unused as before.
                    if *reserved {
                        self.fid_event(*newfid, FidEvent::Unreserve);
                    }
                    return Ok(());
                }
                let qid = if let Some(qid) = qids.last() {
                    *qid
                } else {
                    // A zero-element walk clones the fid, so the destination's
                    // qid is the origin's — and if the origin was clunked
                    // while this walk was outstanding there is nothing left to
                    // clone, so the reply applies nothing.
                    match self.fid(*origin) {
                        Some(state) if state.generation == *origin_generation => state.qid,
                        // Gone, or the number carries a different binding now:
                        // either way there is nothing left to clone.
                        _ => return Ok(()),
                    }
                };
                if *reserved {
                    if !self.is_reserved(*newfid) {
                        // The reservation was released — flushed, or the
                        // request already failed — so there is nothing to bind.
                        return Ok(());
                    }
                    let generation = self.fresh_generation();
                    self.fid_event(
                        *newfid,
                        FidEvent::Bind {
                            path: destination.clone(),
                            qid,
                            generation,
                        },
                    );
                } else {
                    if self.admitted_fid(*newfid, *origin_generation).is_none() {
                        // A walk in place reserves nothing, so it may bind only
                        // the **binding** it was admitted against.  Re-creating
                        // a fid clunked while the walk was outstanding would
                        // put a number back into the table that the quota had
                        // already released, and `live_fids()` could then exceed
                        // `maxFids`; moving a number the client has since
                        // re-bound to something else would leave this session's
                        // path and gate 4's descriptor for that fid
                        // disagreeing.
                        return Ok(());
                    }
                    let generation = self.fresh_generation();
                    self.fid_event(
                        *newfid,
                        FidEvent::Rebind {
                            admitted: *origin_generation,
                            path: destination.clone(),
                            qid,
                            generation,
                        },
                    );
                }
                Ok(())
            }
            (
                Effect::Open {
                    fid,
                    generation,
                    mode,
                },
                Message::Rlopen { qid, .. },
            ) => {
                // A fid clunked while its open was outstanding is gone, and a
                // number the client has since re-bound carries a different
                // generation; either way the reply applies nothing rather than
                // failing, because a reply is not a request and gate 4 has no
                // `Rlerror` to send for it.
                if self.admitted_fid(*fid, *generation).is_none() {
                    return Ok(());
                }
                let mut mode = *mode;
                // The provider's qid is the authority on the node's kind, so an
                // open that the flags called a file and the host calls a
                // directory is recorded as a directory rather than as whichever
                // the client claimed.
                mode.directory = qid.kind == QidKind::Directory;
                if mode.directory && (mode.write || !mode.read) {
                    return Err(SessionError::MalformedReply);
                }
                self.fid_event(
                    *fid,
                    FidEvent::Open {
                        admitted: *generation,
                        qid: *qid,
                        mode,
                    },
                );
                Ok(())
            }
            (
                Effect::Create {
                    fid,
                    generation,
                    child,
                    mode,
                },
                Message::Rlcreate { qid, .. },
            ) => {
                if qid.kind != QidKind::File {
                    return Err(SessionError::MalformedReply);
                }
                let fresh = self.fresh_generation();
                // A create rebinds the fid to the child it made, so the number
                // now carries a new binding.  Refused, applying nothing, if the
                // number no longer carries the binding the create was admitted
                // against.
                self.fid_event(
                    *fid,
                    FidEvent::Create {
                        admitted: *generation,
                        child: child.clone(),
                        qid: *qid,
                        mode: *mode,
                        generation: fresh,
                    },
                );
                Ok(())
            }
            (Effect::Release { fid, generation }, _) => {
                self.release_fid(*fid, *generation);
                Ok(())
            }
            (Effect::None, _) => Ok(()),
            // Every other pairing means the reply's type did not match its
            // request's, which `complete` already refused.
            _ => Err(SessionError::UnexpectedReply),
        }
    }
}

/// The open mode a validated flag word produces.
///
/// Only reached after [`open_primitives`] or [`create_primitives`] accepted the
/// flags, so the impossible combinations are already gone.
fn open_mode(flags: u32, is_directory: bool) -> OpenMode {
    let access = flags & O_ACCMODE;
    OpenMode {
        read: access == O_RDONLY || access == O_RDWR,
        write: access == O_WRONLY || access == O_RDWR || flags & (O_TRUNC | O_APPEND) != 0,
        directory: is_directory,
    }
}

/// The reply type that answers a request type.
const fn reply_for(request: MessageType) -> MessageType {
    match request {
        MessageType::Tversion => MessageType::Rversion,
        MessageType::Tattach => MessageType::Rattach,
        MessageType::Tflush => MessageType::Rflush,
        MessageType::Twalk => MessageType::Rwalk,
        MessageType::Tlopen => MessageType::Rlopen,
        MessageType::Tlcreate => MessageType::Rlcreate,
        MessageType::Tsymlink => MessageType::Rsymlink,
        MessageType::Treadlink => MessageType::Rreadlink,
        MessageType::Tgetattr => MessageType::Rgetattr,
        MessageType::Tsetattr => MessageType::Rsetattr,
        MessageType::Treaddir => MessageType::Rreaddir,
        MessageType::Tlink => MessageType::Rlink,
        MessageType::Tmkdir => MessageType::Rmkdir,
        MessageType::Trename => MessageType::Rrename,
        MessageType::Trenameat => MessageType::Rrenameat,
        MessageType::Tunlinkat => MessageType::Runlinkat,
        MessageType::Tread => MessageType::Rread,
        MessageType::Twrite => MessageType::Rwrite,
        MessageType::Tclunk => MessageType::Rclunk,
        MessageType::Tremove => MessageType::Rremove,
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn walk_effect() -> Effect {
        Effect::Attach { fid: 7 }
    }

    fn set(tags: &[u16]) -> BTreeSet<u16> {
        tags.iter().copied().collect()
    }

    fn pending() -> TagPhase {
        TagPhase::Pending {
            effect: walk_effect(),
        }
    }

    fn flush_requested(by: &[u16]) -> TagPhase {
        TagPhase::FlushRequested {
            effect: walk_effect(),
            by: set(by),
        }
    }

    fn answered(by: &[u16]) -> TagPhase {
        TagPhase::Answered { by: set(by) }
    }

    fn flush_answered(flush: u16, remaining: &[u16]) -> TagEvent {
        TagEvent::FlushAnswered {
            flush,
            remaining: set(remaining),
        }
    }

    fn flush_cancelled(flush: u16, remaining: &[u16]) -> TagEvent {
        TagEvent::FlushCancelled {
            flush,
            remaining: set(remaining),
        }
    }

    #[test]
    fn a_flush_is_recorded_against_every_phase() {
        assert_eq!(
            pending().on_event(TagEvent::FlushAdmitted(2)),
            (Some(flush_requested(&[2])), TagOutcome::Held)
        );
        assert_eq!(
            flush_requested(&[2]).on_event(TagEvent::FlushAdmitted(3)),
            (Some(flush_requested(&[2, 3])), TagOutcome::Held)
        );
        assert_eq!(
            answered(&[2]).on_event(TagEvent::FlushAdmitted(3)),
            (Some(answered(&[2, 3])), TagOutcome::Held)
        );
    }

    #[test]
    fn a_reply_releases_the_tag_unless_a_live_flush_still_names_it() {
        for flush_live in [false, true] {
            assert_eq!(
                pending().on_event(TagEvent::Replied { flush_live }),
                (None, TagOutcome::Released)
            );
        }
        // Only stale flushes are recorded: nothing holds the tag.
        assert_eq!(
            flush_requested(&[2]).on_event(TagEvent::Replied { flush_live: false }),
            (None, TagOutcome::Released)
        );
        // The reply is honoured and the tag stays reserved for the flush,
        // carrying no effect any more.
        let (next, outcome) =
            flush_requested(&[2, 3]).on_event(TagEvent::Replied { flush_live: true });
        assert_eq!(
            (next.clone(), outcome),
            (Some(answered(&[2, 3])), TagOutcome::Held)
        );
        assert_eq!(next.and_then(|phase| phase.effect().cloned()), None);
        // A second reply is refused.
        for flush_live in [false, true] {
            assert_eq!(
                answered(&[2]).on_event(TagEvent::Replied { flush_live }),
                (Some(answered(&[2])), TagOutcome::Refused)
            );
        }
    }

    #[test]
    fn the_last_rflush_releases_the_tag_and_cancels_an_unanswered_request() {
        // Another live flush remains: the tag is held for it.
        assert_eq!(
            flush_requested(&[2, 3]).on_event(flush_answered(2, &[3])),
            (Some(flush_requested(&[3])), TagOutcome::Held)
        );
        assert_eq!(
            answered(&[2, 3]).on_event(flush_answered(2, &[3])),
            (Some(answered(&[3])), TagOutcome::Held)
        );
        // The last one: an unanswered request is cancelled and hands back its
        // effect so its reservation is undone; an answered one has nothing
        // left to undo.
        assert_eq!(
            flush_requested(&[2]).on_event(flush_answered(2, &[])),
            (None, TagOutcome::Cancelled(walk_effect()))
        );
        assert_eq!(
            answered(&[2]).on_event(flush_answered(2, &[])),
            (None, TagOutcome::Released)
        );
    }

    #[test]
    fn a_cancelled_flush_never_cancels_the_request_it_named() {
        assert_eq!(
            flush_requested(&[2, 3]).on_event(flush_cancelled(2, &[3])),
            (Some(flush_requested(&[3])), TagOutcome::Held)
        );
        // The request is still outstanding, with no flush against it.
        assert_eq!(
            flush_requested(&[2]).on_event(flush_cancelled(2, &[])),
            (Some(pending()), TagOutcome::Held)
        );
        assert_eq!(
            answered(&[2, 3]).on_event(flush_cancelled(2, &[3])),
            (Some(answered(&[3])), TagOutcome::Held)
        );
        // Held only for that flush and already answered: collected.
        assert_eq!(
            answered(&[2]).on_event(flush_cancelled(2, &[])),
            (None, TagOutcome::Released)
        );
    }

    /// Membership is what makes a re-issued request safe: an `Rflush` (or a
    /// cancelled flush) that is not recorded against the tag changes nothing.
    #[test]
    fn a_flush_that_does_not_name_the_tag_is_refused() {
        for phase in [pending(), flush_requested(&[2]), answered(&[2])] {
            for event in [
                flush_answered(9, &[]),
                flush_answered(9, &[2]),
                flush_cancelled(9, &[]),
                flush_cancelled(9, &[2]),
            ] {
                assert_eq!(
                    phase.clone().on_event(event),
                    (Some(phase.clone()), TagOutcome::Refused)
                );
            }
        }
    }

    fn path() -> VirtualPath {
        VirtualPath::root()
    }

    fn qid(kind: QidKind) -> Qid {
        Qid {
            kind,
            version: 0,
            path: 1,
        }
    }

    fn bound(generation: u64, open: Option<OpenMode>) -> FidSlot {
        FidSlot::Bound(FidState {
            path: path(),
            qid: qid(QidKind::Directory),
            open,
            generation,
        })
    }

    fn fid_events(admitted: u64) -> Vec<FidEvent> {
        vec![
            FidEvent::Reserve(path()),
            FidEvent::Unreserve,
            FidEvent::Bind {
                path: path(),
                qid: qid(QidKind::Directory),
                generation: 9,
            },
            FidEvent::Rebind {
                admitted,
                path: path(),
                qid: qid(QidKind::File),
                generation: 9,
            },
            FidEvent::Open {
                admitted,
                qid: qid(QidKind::File),
                mode: OpenMode {
                    read: true,
                    ..OpenMode::default()
                },
            },
            FidEvent::Create {
                admitted,
                child: path(),
                qid: qid(QidKind::File),
                mode: OpenMode {
                    write: true,
                    ..OpenMode::default()
                },
                generation: 9,
            },
            FidEvent::Release { admitted },
        ]
    }

    #[test]
    fn an_absent_fid_can_only_be_reserved() {
        for event in fid_events(1) {
            let reserve = matches!(event, FidEvent::Reserve(_));
            let (slot, applied) = FidSlot::on_event(None, event);
            assert_eq!(applied, reserve);
            assert_eq!(slot, reserve.then(|| FidSlot::Reserved(path())));
        }
    }

    #[test]
    fn a_reserved_fid_is_bound_or_released_and_nothing_else() {
        for event in fid_events(1) {
            let reserved = Some(FidSlot::Reserved(path()));
            let (slot, applied) = FidSlot::on_event(reserved.clone(), event.clone());
            match event {
                FidEvent::Unreserve => assert_eq!((slot, applied), (None, true)),
                FidEvent::Bind { .. } => assert_eq!((slot, applied), (Some(bound(9, None)), true)),
                // In particular a second reservation of the number is refused.
                _ => assert_eq!((slot, applied), (reserved, false)),
            }
        }
    }

    #[test]
    fn a_bound_fid_changes_only_for_the_binding_a_request_was_admitted_against() {
        let open = Some(OpenMode {
            read: true,
            ..OpenMode::default()
        });
        for start in [bound(1, None), bound(1, open)] {
            // A stale request (admitted against another binding) applies
            // nothing, whatever it is.
            for event in fid_events(2) {
                assert_eq!(
                    FidSlot::on_event(Some(start.clone()), event),
                    (Some(start.clone()), false)
                );
            }
            for event in fid_events(1) {
                let (slot, applied) = FidSlot::on_event(Some(start.clone()), event.clone());
                let state = |slot: Option<FidSlot>| match slot {
                    Some(FidSlot::Bound(state)) => state,
                    other => panic!("not bound: {other:?}"),
                };
                match event {
                    // A bound number cannot be reserved, unreserved or bound
                    // again by a claim.
                    FidEvent::Reserve(_) | FidEvent::Unreserve | FidEvent::Bind { .. } => {
                        assert_eq!((slot, applied), (Some(start.clone()), false));
                    }
                    FidEvent::Rebind { .. } => {
                        assert!(applied);
                        let state = state(slot);
                        assert_eq!((state.generation, state.open), (9, None));
                        assert_eq!(state.qid.kind, QidKind::File);
                    }
                    FidEvent::Open { mode, .. } => {
                        assert!(applied);
                        let state = state(slot);
                        // Opening keeps the binding.
                        assert_eq!((state.generation, state.open), (1, Some(mode)));
                    }
                    FidEvent::Create { mode, .. } => {
                        assert!(applied);
                        let state = state(slot);
                        assert_eq!((state.generation, state.open), (9, Some(mode)));
                    }
                    FidEvent::Release { .. } => assert_eq!((slot, applied), (None, true)),
                }
            }
        }
    }
}
