//! Bounded diagnostics for one forwarded device peer stream.
//!
//! The relay keeps only saturating role counters and the latest observation
//! for each role.  Transport error text, peer payloads, routes, and
//! credentials never cross this diagnostic boundary.

use std::sync::{Arc, atomic::AtomicU64};

use serde::Serialize;
use uuid::Uuid;

use crate::actor::CarrierKey;

/// The shared wait-free cells every relay diagnostic in this crate records
/// into; see the module for the consistency each reader gets.
#[path = "diagnostics_cells.rs"]
pub(crate) mod cells;

use cells::{Arena, Entry, Ledger, Order, Place, WordReader, WordWriter, code_of, variant};

/// The side of a forwarded device peer stream that produced the observation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerTransportDiagnosticRole {
    /// The owner relay could not send a response on the selected carrier.
    OwnerSend,
    /// The owner relay stopped receiving the selected carrier's ingress.
    IngressReceive,
}

impl PeerTransportDiagnosticRole {
    /// In the order of the role counters.
    const ALL: [Self; 2] = [Self::OwnerSend, Self::IngressReceive];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OwnerSend => "owner_send",
            Self::IngressReceive => "ingress_receive",
        }
    }
}

/// Closed, payload-free categories for one peer-stream terminal observation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerTransportDiagnosticOutcome {
    TimedOut,
    GoAway,
    H3Error,
    QuicError,
    Cancelled,
    /// The authenticated peer membership admission expired.
    TrustExpired,
    Closed,
    ProtocolError,
    Other,
}

impl PeerTransportDiagnosticOutcome {
    /// Every outcome, for decoding a recorded event.
    pub(crate) const ALL: [Self; 9] = [
        Self::TimedOut,
        Self::GoAway,
        Self::H3Error,
        Self::QuicError,
        Self::Cancelled,
        Self::TrustExpired,
        Self::Closed,
        Self::ProtocolError,
        Self::Other,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TimedOut => "timed_out",
            Self::GoAway => "goaway",
            Self::H3Error => "h3_error",
            Self::QuicError => "quic_error",
            Self::Cancelled => "cancelled",
            Self::TrustExpired => "trust_expired",
            Self::Closed => "closed",
            Self::ProtocolError => "protocol_error",
            Self::Other => "other",
        }
    }
}

/// The bounded identity and terminal category for the latest role event.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PeerTransportDiagnosticEventSnapshot {
    /// Saturating process-local sequence number for observations.
    pub sequence: u64,
    pub device_id: Uuid,
    pub session_id: String,
    pub epoch: u64,
    pub generation: u64,
    pub connection_id: String,
    pub role: PeerTransportDiagnosticRole,
    pub outcome: PeerTransportDiagnosticOutcome,
}

/// Redacted diagnostics retained by the typed relay snapshot.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct PeerTransportDiagnosticSnapshot {
    /// Number of owner-side response-send observations.
    pub owner_send_count: u64,
    /// Number of owner-side ingress-receive terminal observations.
    pub ingress_receive_count: u64,
    /// Latest owner-side response-send observation, if any.
    pub last_owner_send: Option<PeerTransportDiagnosticEventSnapshot>,
    /// Latest owner-side ingress-receive observation, if any.
    pub last_ingress_receive: Option<PeerTransportDiagnosticEventSnapshot>,
    /// True only when this snapshot could not be taken because too many
    /// reads of these diagnostics were in progress at once.  Every other
    /// field is then a placeholder and not an observation: the counts are
    /// unknown, not zero.  Absent from the serialized snapshot otherwise.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub unavailable: bool,
}

/// The cap on this diagnostic's storage: 2^14 blocks of 88 bytes, 1.4 MB.
/// A handful of events is retained; the rest is head-room.
const BLOCKS: usize = 1 << 14;

/// The clock events are numbered from, and the ledger holding one counter
/// and the latest event per role.
struct PeerTransportDiagnosticState {
    arena: Arena,
    sequence: AtomicU64,
    ledger: Ledger,
}

impl Default for PeerTransportDiagnosticState {
    fn default() -> Self {
        Self {
            arena: Arena::new(BLOCKS),
            sequence: AtomicU64::new(0),
            ledger: Ledger::new(
                PeerTransportDiagnosticRole::ALL.len(),
                &[PeerTransportDiagnosticRole::ALL.len()],
            ),
        }
    }
}

fn decode_event(
    sequence: u64,
    mut record: WordReader,
) -> Option<PeerTransportDiagnosticEventSnapshot> {
    Some(PeerTransportDiagnosticEventSnapshot {
        sequence,
        device_id: record.uuid()?,
        session_id: record.text()?,
        epoch: record.u64()?,
        generation: record.u64()?,
        connection_id: record.text()?,
        role: variant(&PeerTransportDiagnosticRole::ALL, record.u64()?)?,
        outcome: variant(&PeerTransportDiagnosticOutcome::ALL, record.u64()?)?,
    })
}

/// Cloneable, bounded state for forwarded device transport diagnostics.
#[derive(Clone, Default)]
pub(crate) struct PeerTransportDiagnostics {
    state: Arc<PeerTransportDiagnosticState>,
}

impl PeerTransportDiagnostics {
    /// Record one static observation without retaining transport text.
    ///
    /// The role's count and its latest event change in one atomic step, and
    /// the sequence is drawn by the step that installs them, so the latest
    /// event is the one with the highest sequence and a snapshot never
    /// shows a count without the event it counted.
    pub(crate) fn record(
        &self,
        device_id: Uuid,
        carrier: &CarrierKey,
        role: PeerTransportDiagnosticRole,
        outcome: PeerTransportDiagnosticOutcome,
    ) {
        let state = &*self.state;
        let mut event = WordWriter::new();
        event.uuid(device_id);
        event.text(&carrier.session.session_id);
        event.u64(carrier.session.epoch);
        event.u64(carrier.generation);
        event.text(&carrier.connection_id);
        let index = code_of(&PeerTransportDiagnosticRole::ALL, &role);
        event.u64(index);
        event.u64(code_of(&PeerTransportDiagnosticOutcome::ALL, &outcome));
        let index = usize::try_from(index).unwrap_or(usize::MAX);
        state.ledger.commit(
            &state.arena,
            Some(&state.sequence),
            &[index],
            vec![Entry {
                place: Place::Key(0, index),
                order: Order::Sequence,
                record: event,
            }],
        );
    }

    /// Return the bounded redacted view used by a relay snapshot.
    #[must_use]
    pub(crate) fn snapshot(&self) -> PeerTransportDiagnosticSnapshot {
        let Some(view) = self.state.ledger.read(&self.state.arena) else {
            return PeerTransportDiagnosticSnapshot {
                unavailable: true,
                ..PeerTransportDiagnosticSnapshot::default()
            };
        };
        let mut snapshot = PeerTransportDiagnosticSnapshot {
            owner_send_count: view.count(0),
            ingress_receive_count: view.count(1),
            ..PeerTransportDiagnosticSnapshot::default()
        };
        for retained in view.retained {
            let Some(event) = decode_event(retained.order, retained.record) else {
                continue;
            };
            match event.role {
                PeerTransportDiagnosticRole::OwnerSend => snapshot.last_owner_send = Some(event),
                PeerTransportDiagnosticRole::IngressReceive => {
                    snapshot.last_ingress_receive = Some(event);
                }
            }
        }
        snapshot
    }
}

#[cfg(test)]
mod tests {
    use super::{PeerTransportDiagnosticOutcome, PeerTransportDiagnosticRole};

    /// A recorded event names its role and outcome by table position, so a
    /// variant missing from a table would not decode.
    #[test]
    fn every_role_and_outcome_is_in_its_decode_table() {
        for role in PeerTransportDiagnosticRole::ALL {
            match role {
                PeerTransportDiagnosticRole::OwnerSend
                | PeerTransportDiagnosticRole::IngressReceive => {}
            }
        }
        for outcome in PeerTransportDiagnosticOutcome::ALL {
            match outcome {
                PeerTransportDiagnosticOutcome::TimedOut
                | PeerTransportDiagnosticOutcome::GoAway
                | PeerTransportDiagnosticOutcome::H3Error
                | PeerTransportDiagnosticOutcome::QuicError
                | PeerTransportDiagnosticOutcome::Cancelled
                | PeerTransportDiagnosticOutcome::TrustExpired
                | PeerTransportDiagnosticOutcome::Closed
                | PeerTransportDiagnosticOutcome::ProtocolError
                | PeerTransportDiagnosticOutcome::Other => {}
            }
        }
        let mut labels: Vec<&str> = PeerTransportDiagnosticOutcome::ALL
            .iter()
            .map(|outcome| outcome.as_str())
            .collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), PeerTransportDiagnosticOutcome::ALL.len());
    }
}
