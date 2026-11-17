//! The explicit shared terminal state of one exchange at one endpoint.
//!
//! The whole state is one [`State`] value held in a single atomic word.
//! Every change goes through [`State::on_event`], applied by compare and
//! swap, so a change is decided from one consistent value and is seen whole
//! or not at all.  Waiters are woken after each change and read that same
//! word: there is no second copy (a separate "terminal" flag per direction)
//! that could disagree with the recorded outcome.

use std::sync::atomic::{AtomicU32, Ordering};

use tokio::sync::Notify;
use tunnel_http_forward::HttpErrorCode;

use crate::progress::{PauseSignal, ProgressBudgets, ProgressKind};
use crate::status::{ExchangeReport, Execution, Outcome, ResetDetail};
use crate::stream::FrameSender;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Dir {
    Request,
    Response,
}

/// One direction of an exchange that has not failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Flow {
    /// Reported as [`Outcome::Pending`].
    Open,
    /// HEAD, BODY*, END and FIN all passed.
    Complete,
}

/// How the request direction ended in a failed exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RequestEnd {
    Complete,
    Aborted,
}

/// How the response direction ended in a failed exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResponseEnd {
    Complete,
    Aborted,
    /// The consumer released the response body after its head (M3-32).
    Released,
}

/// Whether the exchange has failed.  A direction is unfinished only while
/// the exchange is `Running`, and is aborted or released only once it has
/// `Failed`: an error with a pending direction, or an aborted direction with
/// no error, cannot be written down.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Lifecycle {
    Running {
        request: Flow,
        response: Flow,
    },
    /// The first failure was recorded and both directions are terminal.
    Failed {
        code: HttpErrorCode,
        request: RequestEnd,
        response: ResponseEnd,
    },
}

/// The complete state of one exchange at one endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct State {
    lifecycle: Lifecycle,
    execution: Execution,
    /// The progress budget whose expiry is about to fail (or failed) the
    /// exchange.  Only recorded while running.
    progress_expired: Option<ProgressKind>,
    /// A response head exists at this endpoint: the device's handler
    /// returned its response, or the owner decoded the device's
    /// `RESPONSE_HEAD`.  It ends the response-head bound (M4-71).
    response_head: bool,
}

/// Everything that can change a [`State`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Event {
    /// A direction passed its FIN.
    Complete(Dir),
    /// A failure: `response` is how an unfinished response is recorded if
    /// this is the first failure ([`ResponseEnd::Aborted`] or
    /// [`ResponseEnd::Released`]).
    Fail {
        code: HttpErrorCode,
        response: ResponseEnd,
    },
    /// The device is about to invoke the handler.
    BeginDispatch,
    /// This endpoint learned more (or less) about handler invocation.
    SetExecution(Execution),
    /// A progress budget expired; a `Fail` follows.
    ProgressExpired(ProgressKind),
    /// A response head exists at this endpoint.
    ResponseHead,
}

/// What a transition asks its caller to do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Effect {
    /// The state changed (or already held the requested value).
    Applied,
    /// The event is not legal in this state; nothing changed.
    Refused,
    /// The exchange is failed: emit RESET with `detail`.  `first` is true
    /// for the transition that recorded the failure.
    Reset { detail: ResetDetail, first: bool },
}

impl State {
    const fn new(execution: Execution) -> Self {
        Self {
            lifecycle: Lifecycle::Running {
                request: Flow::Open,
                response: Flow::Open,
            },
            execution,
            progress_expired: None,
            response_head: false,
        }
    }

    /// The only place an exchange's state changes.
    pub(crate) fn on_event(self, event: Event) -> (Self, Effect) {
        match (event, self.lifecycle) {
            (Event::Complete(dir), Lifecycle::Running { request, response }) => {
                let (request, response, was) = match dir {
                    Dir::Request => (Flow::Complete, response, request),
                    Dir::Response => (request, Flow::Complete, response),
                };
                let effect = match was {
                    Flow::Open => Effect::Applied,
                    Flow::Complete => Effect::Refused,
                };
                let lifecycle = Lifecycle::Running { request, response };
                (Self { lifecycle, ..self }, effect)
            }
            // An aborted direction stays aborted; a completed one stays
            // complete.
            (Event::Complete(_), Lifecycle::Failed { .. }) => (self, Effect::Refused),
            // Both directions completed: there is nothing left to fail.
            (
                Event::Fail { .. },
                Lifecycle::Running {
                    request: Flow::Complete,
                    response: Flow::Complete,
                },
            ) => (self, Effect::Refused),
            (
                Event::Fail {
                    code,
                    response: unfinished,
                },
                Lifecycle::Running { request, response },
            ) => {
                let lifecycle = Lifecycle::Failed {
                    code,
                    request: match request {
                        Flow::Open => RequestEnd::Aborted,
                        Flow::Complete => RequestEnd::Complete,
                    },
                    response: match response {
                        Flow::Open => unfinished,
                        Flow::Complete => ResponseEnd::Complete,
                    },
                };
                let detail = ResetDetail {
                    code,
                    execution: self.execution,
                };
                (
                    Self { lifecycle, ..self },
                    Effect::Reset {
                        detail,
                        first: true,
                    },
                )
            }
            // A later failure keeps the first code and both outcomes.
            (Event::Fail { .. }, Lifecycle::Failed { code, .. }) => {
                let detail = ResetDetail {
                    code,
                    execution: self.execution,
                };
                (
                    self,
                    Effect::Reset {
                        detail,
                        first: false,
                    },
                )
            }
            // A RESET can never claim `not_dispatched` for a handler that is
            // then started: once failed, dispatch is refused.
            (Event::BeginDispatch, Lifecycle::Failed { .. })
            | (Event::ProgressExpired(_), Lifecycle::Failed { .. }) => (self, Effect::Refused),
            (Event::BeginDispatch, Lifecycle::Running { .. }) => (
                Self {
                    execution: Execution::Dispatched,
                    ..self
                },
                Effect::Applied,
            ),
            (Event::SetExecution(execution), _) => (Self { execution, ..self }, Effect::Applied),
            (Event::ProgressExpired(kind), Lifecycle::Running { .. }) => {
                if self.progress_expired.is_some() {
                    // The first expiry is the one reported.
                    return (self, Effect::Refused);
                }
                (
                    Self {
                        progress_expired: Some(kind),
                        ..self
                    },
                    Effect::Applied,
                )
            }
            (Event::ResponseHead, _) => (
                Self {
                    response_head: true,
                    ..self
                },
                Effect::Applied,
            ),
        }
    }

    const fn outcome(self, dir: Dir) -> Outcome {
        match (self.lifecycle, dir) {
            (
                Lifecycle::Running {
                    request: Flow::Open,
                    ..
                },
                Dir::Request,
            )
            | (
                Lifecycle::Running {
                    response: Flow::Open,
                    ..
                },
                Dir::Response,
            ) => Outcome::Pending,
            (
                Lifecycle::Running {
                    request: Flow::Complete,
                    ..
                }
                | Lifecycle::Failed {
                    request: RequestEnd::Complete,
                    ..
                },
                Dir::Request,
            )
            | (
                Lifecycle::Running {
                    response: Flow::Complete,
                    ..
                }
                | Lifecycle::Failed {
                    response: ResponseEnd::Complete,
                    ..
                },
                Dir::Response,
            ) => Outcome::Complete,
            (
                Lifecycle::Failed {
                    request: RequestEnd::Aborted,
                    ..
                },
                Dir::Request,
            )
            | (
                Lifecycle::Failed {
                    response: ResponseEnd::Aborted,
                    ..
                },
                Dir::Response,
            ) => Outcome::Aborted,
            (
                Lifecycle::Failed {
                    response: ResponseEnd::Released,
                    ..
                },
                Dir::Response,
            ) => Outcome::Released,
        }
    }

    const fn error(self) -> Option<HttpErrorCode> {
        match self.lifecycle {
            Lifecycle::Running { .. } => None,
            Lifecycle::Failed { code, .. } => Some(code),
        }
    }

    const fn report(self) -> ExchangeReport {
        ExchangeReport {
            request: self.outcome(Dir::Request),
            response: self.outcome(Dir::Response),
            execution: self.execution,
            error: self.error(),
            progress_expired: self.progress_expired,
        }
    }

    // The word layout, low bits first: failed (1), request (1), response
    // (2), code (3), execution (2), progress (3), response head (1).

    const fn pack(self) -> u32 {
        let lifecycle = match self.lifecycle {
            Lifecycle::Running { request, response } => {
                (matches!(request, Flow::Complete) as u32) << 1
                    | (matches!(response, Flow::Complete) as u32) << 2
            }
            Lifecycle::Failed {
                code,
                request,
                response,
            } => {
                let response = match response {
                    ResponseEnd::Aborted => 0,
                    ResponseEnd::Complete => 1,
                    ResponseEnd::Released => 2,
                };
                let code = match code {
                    HttpErrorCode::BadRecord => 0,
                    HttpErrorCode::InvalidHead => 1,
                    HttpErrorCode::BodyLimit => 2,
                    HttpErrorCode::LengthMismatch => 3,
                    HttpErrorCode::UnsupportedFeature => 4,
                    HttpErrorCode::StreamInterrupted => 5,
                    HttpErrorCode::Cancelled => 6,
                    HttpErrorCode::DeadlineExceeded => 7,
                };
                1 | (matches!(request, RequestEnd::Complete) as u32) << 1
                    | response << 2
                    | code << 4
            }
        };
        let progress = match self.progress_expired {
            None => 0,
            Some(ProgressKind::FirstHead) => 1,
            Some(ProgressKind::Record) => 2,
            Some(ProgressKind::CreditStall) => 3,
            Some(ProgressKind::FinAfterEnd) => 4,
        };
        lifecycle
            | (self.execution.to_u8() as u32) << 7
            | progress << 9
            | (self.response_head as u32) << 12
    }

    const fn unpack(word: u32) -> Self {
        let request_complete = word >> 1 & 1 == 1;
        let response = word >> 2 & 3;
        let lifecycle = if word & 1 == 0 {
            Lifecycle::Running {
                request: if request_complete {
                    Flow::Complete
                } else {
                    Flow::Open
                },
                response: if response == 1 {
                    Flow::Complete
                } else {
                    Flow::Open
                },
            }
        } else {
            Lifecycle::Failed {
                code: match word >> 4 & 7 {
                    0 => HttpErrorCode::BadRecord,
                    1 => HttpErrorCode::InvalidHead,
                    2 => HttpErrorCode::BodyLimit,
                    3 => HttpErrorCode::LengthMismatch,
                    4 => HttpErrorCode::UnsupportedFeature,
                    5 => HttpErrorCode::StreamInterrupted,
                    6 => HttpErrorCode::Cancelled,
                    _ => HttpErrorCode::DeadlineExceeded,
                },
                request: if request_complete {
                    RequestEnd::Complete
                } else {
                    RequestEnd::Aborted
                },
                response: match response {
                    1 => ResponseEnd::Complete,
                    2 => ResponseEnd::Released,
                    _ => ResponseEnd::Aborted,
                },
            }
        };
        Self {
            lifecycle,
            // Two bits: the cast cannot truncate.
            execution: Execution::from_u8((word >> 7 & 3) as u8),
            progress_expired: match word >> 9 & 7 {
                1 => Some(ProgressKind::FirstHead),
                2 => Some(ProgressKind::Record),
                3 => Some(ProgressKind::CreditStall),
                4 => Some(ProgressKind::FinAfterEnd),
                _ => None,
            },
            response_head: word >> 12 & 1 == 1,
        }
    }
}

pub(crate) struct Exchange {
    /// The packed [`State`]: the single source of truth.
    state: AtomicU32,
    /// Wakes every waiter after each change; carries no state of its own.
    changed: Notify,
    /// This endpoint's sending direction.
    pub peer: FrameSender,
    /// This endpoint's recorded rotation freeze, for progress clocks.
    pub pause: PauseSignal,
    pub budgets: ProgressBudgets,
}

impl Exchange {
    pub fn new(
        peer: FrameSender,
        execution: Execution,
        pause: PauseSignal,
        budgets: ProgressBudgets,
    ) -> Self {
        Self {
            state: AtomicU32::new(State::new(execution).pack()),
            changed: Notify::new(),
            peer,
            pause,
            budgets,
        }
    }

    fn state(&self) -> State {
        State::unpack(self.state.load(Ordering::SeqCst))
    }

    /// Apply one event as a single atomic step and wake the waiters.
    fn apply(&self, event: Event) -> Effect {
        let mut word = self.state.load(Ordering::SeqCst);
        loop {
            let (next, effect) = State::unpack(word).on_event(event);
            match self.state.compare_exchange_weak(
                word,
                next.pack(),
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    self.changed.notify_waiters();
                    return effect;
                }
                // Another event landed first: decide again from its result.
                Err(current) => word = current,
            }
        }
    }

    /// Resolve with the first state for which `ready` holds.
    async fn wait_for(&self, ready: impl Fn(State) -> bool) -> State {
        loop {
            // Created before the state is read: a `Notified` receives every
            // `notify_waiters` call from its creation on, so a change between
            // the read and the await is not missed.
            let changed = self.changed.notified();
            let state = self.state();
            if ready(state) {
                return state;
            }
            changed.await;
        }
    }

    /// Resolve once the exchange has failed: every pump stops promptly.
    pub async fn stopped(&self) {
        self.wait_for(|state| state.error().is_some()).await;
    }

    pub fn is_stopped(&self) -> bool {
        self.state().error().is_some()
    }

    /// Resolve with the direction's outcome once it is terminal.
    pub async fn terminal(&self, dir: Dir) -> Outcome {
        self.wait_for(|state| state.outcome(dir) != Outcome::Pending)
            .await
            .outcome(dir)
    }

    /// Record that a progress budget expired; the caller then fails the
    /// exchange with `HTTP_DEADLINE_EXCEEDED`.
    pub fn note_progress_expired(&self, kind: ProgressKind) {
        self.apply(Event::ProgressExpired(kind));
    }

    pub fn execution(&self) -> Execution {
        self.state().execution
    }

    pub fn set_execution(&self, execution: Execution) {
        self.apply(Event::SetExecution(execution));
    }

    /// Record that a response head exists at this endpoint, which ends the
    /// response-head bound (M4-71).
    pub fn note_response_head(&self) {
        self.apply(Event::ResponseHead);
    }

    /// Resolve when the response-head bound `at` passes with no response
    /// head at this endpoint; never when `at` is `None` or once the head
    /// exists (M4-71).
    pub async fn response_head_missed(&self, at: Option<tokio::time::Instant>) {
        let Some(at) = at else {
            return std::future::pending().await;
        };
        tokio::select! {
            biased;
            _ = self.wait_for(|state| state.response_head) => std::future::pending().await,
            () = tokio::time::sleep_until(at) => {}
        }
    }

    /// Mark a direction complete unless it already aborted.
    pub fn complete(&self, dir: Dir) {
        self.apply(Event::Complete(dir));
    }

    pub fn is_complete(&self, dir: Dir) -> bool {
        self.state().outcome(dir) == Outcome::Complete
    }

    /// Atomically claim handler invocation: fails if the exchange already
    /// failed, so a RESET can never claim `not_dispatched` for a handler that
    /// is then started.
    pub fn begin_dispatch(&self) -> bool {
        self.apply(Event::BeginDispatch) == Effect::Applied
    }

    /// Record the first failure, abort unfinished directions, stop every
    /// pump and emit RESET once.  Completed directions stay complete.
    /// Returns the reset detail if this call recorded the first failure.
    pub fn abort(&self, code: HttpErrorCode) -> Option<ResetDetail> {
        self.fail(code, ResponseEnd::Aborted)
    }

    /// [`abort`](Self::abort) for a consumer that released the response body
    /// after its head: an unfinished response is recorded as
    /// [`Outcome::Released`] rather than [`Outcome::Aborted`] (M3-32).  The
    /// RESET and everything else are identical.
    pub fn release(&self, code: HttpErrorCode) -> Option<ResetDetail> {
        self.fail(code, ResponseEnd::Released)
    }

    fn fail(&self, code: HttpErrorCode, response: ResponseEnd) -> Option<ResetDetail> {
        match self.apply(Event::Fail { code, response }) {
            Effect::Reset { detail, first } => {
                // The sender emits RESET at most once.
                self.peer.reset(detail);
                first.then_some(detail)
            }
            Effect::Applied | Effect::Refused => None,
        }
    }

    pub fn error_code(&self) -> HttpErrorCode {
        self.state()
            .error()
            .unwrap_or(HttpErrorCode::StreamInterrupted)
    }

    pub fn report(&self) -> ExchangeReport {
        self.state().report()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    const EXECUTIONS: [Execution; 3] = [
        Execution::NotDispatched,
        Execution::Dispatched,
        Execution::Unknown,
    ];
    const KINDS: [ProgressKind; 4] = [
        ProgressKind::FirstHead,
        ProgressKind::Record,
        ProgressKind::CreditStall,
        ProgressKind::FinAfterEnd,
    ];

    fn events() -> Vec<Event> {
        let mut events = vec![
            Event::Complete(Dir::Request),
            Event::Complete(Dir::Response),
            Event::BeginDispatch,
            Event::ResponseHead,
        ];
        for code in HttpErrorCode::ALL {
            events.push(Event::Fail {
                code,
                response: ResponseEnd::Aborted,
            });
            events.push(Event::Fail {
                code,
                response: ResponseEnd::Released,
            });
        }
        events.extend(EXECUTIONS.map(Event::SetExecution));
        events.extend(KINDS.map(Event::ProgressExpired));
        events
    }

    /// Every state any sequence of events can reach from every start.
    fn reachable() -> Vec<State> {
        let mut seen = BTreeSet::new();
        let mut states = Vec::new();
        let mut queue: Vec<State> = EXECUTIONS.map(State::new).to_vec();
        while let Some(state) = queue.pop() {
            if !seen.insert(state.pack()) {
                continue;
            }
            states.push(state);
            queue.extend(events().into_iter().map(|event| state.on_event(event).0));
        }
        states
    }

    fn running(request: Flow, response: Flow) -> State {
        State {
            lifecycle: Lifecycle::Running { request, response },
            ..State::new(Execution::NotDispatched)
        }
    }

    #[test]
    fn every_reachable_state_survives_the_atomic_word() {
        let states = reachable();
        assert!(states.len() > 100, "the walk covered {}", states.len());
        for state in states {
            assert_eq!(State::unpack(state.pack()), state);
        }
    }

    #[test]
    fn a_direction_completes_once_and_only_while_running() {
        let open = running(Flow::Open, Flow::Open);
        let (state, effect) = open.on_event(Event::Complete(Dir::Request));
        assert_eq!(effect, Effect::Applied);
        assert_eq!(state, running(Flow::Complete, Flow::Open));
        assert_eq!(
            state.on_event(Event::Complete(Dir::Request)),
            (state, Effect::Refused)
        );
        let (state, effect) = state.on_event(Event::Complete(Dir::Response));
        assert_eq!(effect, Effect::Applied);
        assert_eq!(state, running(Flow::Complete, Flow::Complete));
        assert_eq!(state.report().request, Outcome::Complete);
        assert_eq!(state.report().response, Outcome::Complete);
        assert_eq!(state.report().error, None);
    }

    #[test]
    fn the_first_failure_ends_unfinished_directions_and_is_kept() {
        for (request, response, unfinished, want) in [
            (
                Flow::Open,
                Flow::Open,
                ResponseEnd::Aborted,
                (Outcome::Aborted, Outcome::Aborted),
            ),
            (
                Flow::Complete,
                Flow::Open,
                ResponseEnd::Released,
                (Outcome::Complete, Outcome::Released),
            ),
            (
                Flow::Open,
                Flow::Complete,
                ResponseEnd::Released,
                (Outcome::Aborted, Outcome::Complete),
            ),
        ] {
            let (failed, effect) = running(request, response).on_event(Event::Fail {
                code: HttpErrorCode::Cancelled,
                response: unfinished,
            });
            let detail = ResetDetail {
                code: HttpErrorCode::Cancelled,
                execution: Execution::NotDispatched,
            };
            assert_eq!(
                effect,
                Effect::Reset {
                    detail,
                    first: true
                }
            );
            let report = failed.report();
            assert_eq!((report.request, report.response), want);
            assert_eq!(report.error, Some(HttpErrorCode::Cancelled));

            // A later failure changes nothing and repeats the first detail.
            let (again, effect) = failed.on_event(Event::Fail {
                code: HttpErrorCode::BodyLimit,
                response: ResponseEnd::Released,
            });
            assert_eq!(again, failed);
            assert_eq!(
                effect,
                Effect::Reset {
                    detail,
                    first: false
                }
            );
            // Nor does a late completion.
            for dir in [Dir::Request, Dir::Response] {
                assert_eq!(
                    failed.on_event(Event::Complete(dir)),
                    (failed, Effect::Refused)
                );
            }
        }
    }

    #[test]
    fn a_completed_exchange_cannot_fail() {
        let done = running(Flow::Complete, Flow::Complete);
        for code in HttpErrorCode::ALL {
            for response in [ResponseEnd::Aborted, ResponseEnd::Released] {
                assert_eq!(
                    done.on_event(Event::Fail { code, response }),
                    (done, Effect::Refused)
                );
            }
        }
    }

    #[test]
    fn dispatch_is_refused_after_a_failure_and_reported_in_the_reset() {
        let open = running(Flow::Open, Flow::Open);
        let (dispatched, effect) = open.on_event(Event::BeginDispatch);
        assert_eq!(effect, Effect::Applied);
        assert_eq!(dispatched.execution, Execution::Dispatched);
        let fail = Event::Fail {
            code: HttpErrorCode::StreamInterrupted,
            response: ResponseEnd::Aborted,
        };
        let (_, effect) = dispatched.on_event(fail);
        assert!(matches!(
            effect,
            Effect::Reset { detail, .. } if detail.execution == Execution::Dispatched
        ));

        let (failed, effect) = open.on_event(fail);
        assert!(matches!(
            effect,
            Effect::Reset { detail, .. } if detail.execution == Execution::NotDispatched
        ));
        assert_eq!(
            failed.on_event(Event::BeginDispatch),
            (failed, Effect::Refused)
        );
        // The peer's authoritative record may still correct it.
        let (corrected, effect) = failed.on_event(Event::SetExecution(Execution::Unknown));
        assert_eq!(effect, Effect::Applied);
        assert_eq!(corrected.execution, Execution::Unknown);
        assert_eq!(corrected.lifecycle, failed.lifecycle);
    }

    #[test]
    fn only_the_first_expiry_before_a_failure_is_recorded() {
        let open = running(Flow::Open, Flow::Open);
        let (noted, effect) = open.on_event(Event::ProgressExpired(ProgressKind::Record));
        assert_eq!(effect, Effect::Applied);
        assert_eq!(noted.progress_expired, Some(ProgressKind::Record));
        assert_eq!(
            noted.on_event(Event::ProgressExpired(ProgressKind::FirstHead)),
            (noted, Effect::Refused)
        );
        let (failed, _) = open.on_event(Event::Fail {
            code: HttpErrorCode::Cancelled,
            response: ResponseEnd::Aborted,
        });
        assert_eq!(
            failed.on_event(Event::ProgressExpired(ProgressKind::Record)),
            (failed, Effect::Refused)
        );
        assert_eq!(failed.report().progress_expired, None);
    }

    #[test]
    fn a_response_head_is_recorded_in_every_state() {
        for state in reachable() {
            let (next, effect) = state.on_event(Event::ResponseHead);
            assert_eq!(effect, Effect::Applied);
            assert!(next.response_head);
            assert_eq!(next.lifecycle, state.lifecycle);
        }
    }

    /// No event sequence moves a direction out of a terminal outcome, loses
    /// the first error, or releases the request direction.
    #[test]
    fn terminal_outcomes_and_the_first_error_never_change() {
        for state in reachable() {
            assert_ne!(state.outcome(Dir::Request), Outcome::Released);
            for event in events() {
                let (next, _) = state.on_event(event);
                for dir in [Dir::Request, Dir::Response] {
                    if state.outcome(dir) != Outcome::Pending {
                        assert_eq!(next.outcome(dir), state.outcome(dir), "{event:?}");
                    }
                }
                if state.error().is_some() {
                    assert_eq!(next.error(), state.error(), "{event:?}");
                }
            }
        }
    }

    fn exchange() -> Exchange {
        let (peer, _rx, _) = crate::stream::channel(1024);
        Exchange::new(
            peer,
            Execution::NotDispatched,
            PauseSignal::never(),
            crate::BridgeConfig::default().progress(),
        )
    }

    /// The wake-up and the outcome are one value: a waiter that is woken
    /// reads the outcome that woke it, and a waiter that arrives late still
    /// resolves.
    #[tokio::test]
    async fn waiters_resolve_with_the_recorded_outcome() {
        let exchange = exchange();
        let before = async {
            tokio::join!(
                exchange.terminal(Dir::Request),
                exchange.terminal(Dir::Response),
                exchange.stopped(),
            )
        };
        let act = async {
            tokio::task::yield_now().await;
            exchange.complete(Dir::Request);
            tokio::task::yield_now().await;
            assert!(!exchange.is_stopped());
            assert!(exchange.release(HttpErrorCode::Cancelled).is_some());
        };
        let ((request, response, ()), ()) = tokio::join!(before, act);
        assert_eq!(request, Outcome::Complete);
        assert_eq!(response, Outcome::Released);
        assert!(exchange.is_stopped());
        assert_eq!(exchange.terminal(Dir::Response).await, Outcome::Released);
        exchange.stopped().await;
        assert!(exchange.abort(HttpErrorCode::BodyLimit).is_none());
        assert_eq!(exchange.error_code(), HttpErrorCode::Cancelled);
    }

    #[tokio::test(start_paused = true)]
    async fn a_response_head_ends_the_head_bound() {
        let exchange = exchange();
        let at = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        exchange.response_head_missed(Some(at)).await;
        assert_eq!(tokio::time::Instant::now(), at);

        let at = at + std::time::Duration::from_secs(5);
        exchange.note_response_head();
        let missed = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            exchange.response_head_missed(Some(at)),
        );
        assert!(missed.await.is_err(), "the bound no longer fires");
    }
}
