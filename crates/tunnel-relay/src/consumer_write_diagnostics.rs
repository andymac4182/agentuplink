//! Bounded diagnostics for public consumer response writes.
//!
//! The relay records only a saturating timeout count and a small recent-event
//! window at exact public response-write callsites.  No socket error, payload,
//! URL, path, token, or caller-provided text is stored.

use std::{future::Future, sync::Arc};

use serde::Serialize;
use tokio::time::{Instant, timeout_at};
use uuid::Uuid;

use crate::{
    peer_transport_diagnostics::cells::{
        Arena, Entry, Ledger, Order, Place, WordReader, WordWriter, code_of, variant,
    },
    runtime::StreamTerminalCause,
};

/// The outcome of one bounded public response write.
///
/// A timeout is distinct from a completed write, an authorization expiry,
/// and a transport error. Callers must not treat any outcome except `Sent`
/// as delivery success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConsumerWriteOutcome {
    Sent,
    TimedOut,
    Expired,
    Failed,
}

impl ConsumerWriteOutcome {
    #[must_use]
    pub(crate) const fn is_sent(self) -> bool {
        matches!(self, Self::Sent)
    }

    #[must_use]
    pub(crate) const fn is_timed_out(self) -> bool {
        matches!(self, Self::TimedOut)
    }

    /// The typed stream terminal cause this write outcome proves, if any.
    ///
    /// Only the relay's own physical write deadline proves a physical write
    /// timeout. `Expired` is the consumer's absolute authorization lifetime,
    /// `Failed` is a transport error whose text never crosses this boundary,
    /// and `Sent` closes nothing: all three stay unclassified so a later
    /// close keeps whatever cause its own site can prove.
    #[must_use]
    pub(crate) const fn terminal_cause(self) -> Option<StreamTerminalCause> {
        match self {
            Self::TimedOut => Some(StreamTerminalCause::PhysicalWriteTimeout),
            Self::Sent | Self::Expired | Self::Failed => None,
        }
    }
}

/// Classify one socket write against an already-created absolute deadline.
///
/// The future's error is deliberately discarded: the diagnostic boundary
/// needs only the typed distinction between completion, timeout, and failure,
/// and must not retain or expose transport text.
pub(crate) async fn send_until<F, T, E>(send: F, deadline: Instant) -> ConsumerWriteOutcome
where
    F: Future<Output = Result<T, E>>,
{
    match timeout_at(deadline, send).await {
        Ok(Ok(_)) => ConsumerWriteOutcome::Sent,
        Ok(Err(_)) => ConsumerWriteOutcome::Failed,
        Err(_) => ConsumerWriteOutcome::TimedOut,
    }
}

/// Classify a public response write against both its physical write bound and
/// the consumer authorization lifetime. Authorization expiry wins ties and
/// never contributes to the physical writer-timeout diagnostic.
pub(crate) async fn send_until_or_expired<F, T, E>(
    send: F,
    send_deadline: Instant,
    expiry_deadline: Instant,
) -> ConsumerWriteOutcome
where
    F: Future<Output = Result<T, E>>,
{
    if expiry_deadline <= Instant::now() {
        return ConsumerWriteOutcome::Expired;
    }
    tokio::select! {
        biased;
        _ = tokio::time::sleep_until(expiry_deadline) => ConsumerWriteOutcome::Expired,
        outcome = send_until(send, send_deadline) => outcome,
    }
}

/// The public ingress class that observed a response-write timeout.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsumerIngressKind {
    Local,
    Forwarded,
}

impl ConsumerIngressKind {
    const ALL: [Self; 2] = [Self::Local, Self::Forwarded];
}

/// Safe correlation scope for one public consumer response write.
///
/// Device and service UUIDs are authorization-scope identifiers already used
/// by relay diagnostics.  The ingress kind distinguishes an owner-local
/// response from a response written while forwarding from another relay.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
pub struct ConsumerWriteScope {
    pub device_id: Uuid,
    pub service_id: Uuid,
    pub ingress: ConsumerIngressKind,
}

impl ConsumerWriteScope {
    #[must_use]
    pub(crate) const fn new(
        device_id: Uuid,
        service_id: Uuid,
        ingress: ConsumerIngressKind,
    ) -> Self {
        Self {
            device_id,
            service_id,
            ingress,
        }
    }
}

/// One redacted timeout event retained in the bounded recent window.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
pub struct ConsumerWriteTimeoutSnapshot {
    /// Saturating monotonic occurrence number for this relay process.
    pub sequence: u64,
    pub scope: ConsumerWriteScope,
}

/// Redacted diagnostics returned to the typed relay snapshot.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ConsumerWriteDiagnosticSnapshot {
    /// Saturating monotonic count of timed-out public response writes.
    pub timeout_count: u64,
    /// At most this module's fixed recent-event bound is retained.
    pub recent_timeouts: Vec<ConsumerWriteTimeoutSnapshot>,
    /// True only when this snapshot could not be taken because too many
    /// reads of these diagnostics were in progress at once.  Every other
    /// field is then a placeholder and not an observation: the counts are
    /// unknown, not zero.  Absent from the serialized snapshot otherwise.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub unavailable: bool,
}

const MAX_RECENT_TIMEOUTS: usize = 8;

/// The cap on this diagnostic's storage: 2^14 blocks of 88 bytes, 1.4 MB.
/// A handful of events is retained; the rest is head-room.
const BLOCKS: usize = 1 << 14;

/// The ledger holding the timeout count and the recent events it counted.
struct ConsumerWriteDiagnosticState {
    arena: Arena,
    ledger: Ledger,
}

impl Default for ConsumerWriteDiagnosticState {
    fn default() -> Self {
        Self {
            arena: Arena::new(BLOCKS),
            ledger: Ledger::new(1, &[MAX_RECENT_TIMEOUTS]),
        }
    }
}

fn decode_timeout(sequence: u64, mut record: WordReader) -> Option<ConsumerWriteTimeoutSnapshot> {
    Some(ConsumerWriteTimeoutSnapshot {
        sequence,
        scope: ConsumerWriteScope {
            device_id: record.uuid()?,
            service_id: record.uuid()?,
            ingress: variant(&ConsumerIngressKind::ALL, record.u64()?)?,
        },
    })
}

/// Cloneable, bounded state for response-write timeout diagnostics.
#[derive(Clone, Default)]
pub(crate) struct ConsumerWriteDiagnostics {
    state: Arc<ConsumerWriteDiagnosticState>,
}

impl ConsumerWriteDiagnostics {
    /// Record a timeout without retaining any transport error or message
    /// content.  The count and the event window change in one atomic step
    /// and the event's occurrence number is the count that step reaches, so
    /// a snapshot cannot pair a count with a different scope or show a
    /// count whose event is not yet in the window.
    pub(crate) fn record_timeout(&self, scope: ConsumerWriteScope) -> ConsumerWriteTimeoutSnapshot {
        let state = &*self.state;
        let mut event = WordWriter::new();
        event.uuid(scope.device_id);
        event.uuid(scope.service_id);
        event.u64(code_of(&ConsumerIngressKind::ALL, &scope.ingress));
        let committed = state.ledger.commit(
            &state.arena,
            None,
            &[0],
            vec![Entry {
                place: Place::Push(0),
                order: Order::Count(0),
                record: event,
            }],
        );
        ConsumerWriteTimeoutSnapshot {
            // Zero only if the record was dropped for want of storage,
            // which the HTTP forward snapshot counts.
            sequence: committed
                .and_then(|committed| committed.counts.first().copied())
                .unwrap_or(0),
            scope,
        }
    }

    /// Return the bounded redacted view used by a relay's typed snapshot.
    #[must_use]
    pub(crate) fn snapshot(&self) -> ConsumerWriteDiagnosticSnapshot {
        let Some(view) = self.state.ledger.read(&self.state.arena) else {
            return ConsumerWriteDiagnosticSnapshot {
                unavailable: true,
                ..ConsumerWriteDiagnosticSnapshot::default()
            };
        };
        ConsumerWriteDiagnosticSnapshot {
            timeout_count: view.count(0),
            recent_timeouts: view
                .retained
                .into_iter()
                .filter_map(|retained| decode_timeout(retained.order, retained.record))
                .collect(),
            unavailable: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use tokio::time::{Duration, Instant, sleep};

    use uuid::Uuid;

    use super::{
        ConsumerIngressKind, ConsumerWriteDiagnostics, ConsumerWriteOutcome, ConsumerWriteScope,
        MAX_RECENT_TIMEOUTS, send_until_or_expired,
    };

    #[test]
    fn timeouts_are_counted_and_the_recent_window_stays_bounded() {
        let diagnostics = ConsumerWriteDiagnostics::default();
        let total = MAX_RECENT_TIMEOUTS as u64 + 3;
        for index in 1..=total {
            let ingress = if index % 2 == 0 {
                ConsumerIngressKind::Forwarded
            } else {
                ConsumerIngressKind::Local
            };
            let scope = ConsumerWriteScope::new(
                Uuid::from_u128(u128::from(index)),
                Uuid::from_u128(u128::from(index) << 64),
                ingress,
            );
            let event = diagnostics.record_timeout(scope);
            assert_eq!(event.sequence, index);
            assert_eq!(event.scope, scope);
        }
        let snapshot = diagnostics.snapshot();
        assert_eq!(snapshot.timeout_count, total);
        assert_eq!(snapshot.recent_timeouts.len(), MAX_RECENT_TIMEOUTS);
        for (offset, event) in snapshot.recent_timeouts.iter().enumerate() {
            let sequence = 4 + offset as u64;
            assert_eq!(event.sequence, sequence);
            assert_eq!(event.scope.device_id, Uuid::from_u128(u128::from(sequence)));
            assert_eq!(
                event.scope.service_id,
                Uuid::from_u128(u128::from(sequence) << 64)
            );
        }
    }

    #[tokio::test]
    async fn expired_write_does_not_poll_send_future() {
        let polled = Arc::new(AtomicBool::new(false));
        let send_polled = polled.clone();
        let outcome = send_until_or_expired(
            async move {
                send_polled.store(true, Ordering::SeqCst);
                Ok::<(), ()>(())
            },
            Instant::now() + Duration::from_secs(1),
            Instant::now() - Duration::from_millis(1),
        )
        .await;

        assert_eq!(outcome, ConsumerWriteOutcome::Expired);
        assert!(!polled.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn authorization_expiry_precedes_a_pending_physical_write_timeout() {
        let start = Instant::now();
        let outcome = send_until_or_expired(
            async {
                sleep(Duration::from_millis(50)).await;
                Ok::<(), ()>(())
            },
            start + Duration::from_secs(1),
            start + Duration::from_millis(5),
        )
        .await;

        assert_eq!(outcome, ConsumerWriteOutcome::Expired);
        assert!(!outcome.is_timed_out());
    }

    #[tokio::test]
    async fn physical_write_deadline_remains_a_timeout_before_expiry() {
        let start = Instant::now();
        let outcome = send_until_or_expired(
            std::future::pending::<Result<(), ()>>(),
            start + Duration::from_millis(5),
            start + Duration::from_secs(1),
        )
        .await;

        assert_eq!(outcome, ConsumerWriteOutcome::TimedOut);
        assert_ne!(outcome, ConsumerWriteOutcome::Expired);
    }
}
