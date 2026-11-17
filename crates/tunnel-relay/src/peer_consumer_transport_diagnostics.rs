//! Bounded terminal diagnostics for forwarded consumer peer streams.
//!
//! Device data and consumer streams use separate HTTP/3 routes.  The relay
//! already retains typed terminal observations for forwarded device carriers;
//! this companion keeps the same distinction for consumer streams so a data
//! carrier failure cannot be mistaken for a public response-writer timeout.
//! Only saturating counters and the latest closed-category event are retained.

use std::{
    sync::{Arc, OnceLock, atomic::AtomicU64},
    time::Instant,
};

use serde::Serialize;
use uuid::Uuid;

use crate::peer_transport_diagnostics::{
    PeerTransportDiagnosticOutcome,
    cells::{Arena, Entry, Ledger, Order, Place, WordReader, WordWriter, code_of, variant},
};

/// The side of the forwarded consumer peer exchange that observed a terminal
/// event.  The names describe the relay-local direction, not a user payload.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerConsumerDiagnosticRole {
    /// The ingress relay could not forward a consumer request to the owner.
    IngressSend,
    /// The ingress relay could not receive a consumer response from the owner.
    IngressReceive,
    /// The owner relay could not send a consumer response to the ingress.
    OwnerSend,
    /// The owner relay could not receive a consumer request from the ingress.
    OwnerReceive,
}

/// Closed allowlist of HTTP/3 application codes retained for a consumer-peer
/// terminal event.  The original transport error text is never retained.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerConsumerDiagnosticH3Code {
    /// The peer sent a frame that was not valid in the current stream state.
    FrameUnexpected,
    /// The request or response stream was cancelled.
    RequestCancelled,
    /// The HTTP/3 connection closed without an error.
    NoError,
    /// An HTTP/3 error did not match the bounded allowlist.
    Other,
}

impl PeerConsumerDiagnosticH3Code {
    const ALL: [Self; 4] = [
        Self::FrameUnexpected,
        Self::RequestCancelled,
        Self::NoError,
        Self::Other,
    ];

    /// Return the stable redacted diagnostic label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FrameUnexpected => "h3_frame_unexpected",
            Self::RequestCancelled => "h3_request_cancelled",
            Self::NoError => "h3_no_error",
            Self::Other => "h3_other",
        }
    }
}

/// Authenticated bounded identity for one forwarded consumer request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PeerConsumerDiagnosticContext {
    pub(crate) tenant_id: Uuid,
    pub(crate) device_id: Uuid,
    pub(crate) session_id: String,
    pub(crate) epoch: u64,
    pub(crate) service_id: Uuid,
    pub(crate) request_id: String,
}

impl PeerConsumerDiagnosticRole {
    /// In the order of the counters and latest-event slots.
    const ALL: [Self; 4] = [
        Self::IngressSend,
        Self::IngressReceive,
        Self::OwnerSend,
        Self::OwnerReceive,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IngressSend => "ingress_send",
            Self::IngressReceive => "ingress_receive",
            Self::OwnerSend => "owner_send",
            Self::OwnerReceive => "owner_receive",
        }
    }
}

/// One bounded terminal event for a forwarded consumer stream.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PeerConsumerDiagnosticEventSnapshot {
    /// Saturating process-local sequence number.
    pub sequence: u64,
    /// Milliseconds from this relay process's monotonic diagnostic origin.
    /// Values from separate relay processes are not directly comparable.
    pub observed_at_ms: u64,
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub session_id: String,
    pub epoch: u64,
    pub service_id: Uuid,
    pub request_id: String,
    pub role: PeerConsumerDiagnosticRole,
    pub outcome: PeerTransportDiagnosticOutcome,
    pub h3_code: Option<PeerConsumerDiagnosticH3Code>,
}

/// Redacted consumer-peer terminal observations retained by a relay snapshot.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct PeerConsumerDiagnosticSnapshot {
    pub ingress_send_count: u64,
    pub ingress_receive_count: u64,
    pub owner_send_count: u64,
    pub owner_receive_count: u64,
    pub last_ingress_send: Option<PeerConsumerDiagnosticEventSnapshot>,
    pub last_ingress_receive: Option<PeerConsumerDiagnosticEventSnapshot>,
    pub last_owner_send: Option<PeerConsumerDiagnosticEventSnapshot>,
    pub last_owner_receive: Option<PeerConsumerDiagnosticEventSnapshot>,
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
struct PeerConsumerDiagnosticState {
    arena: Arena,
    sequence: AtomicU64,
    ledger: Ledger,
}

impl Default for PeerConsumerDiagnosticState {
    fn default() -> Self {
        Self {
            arena: Arena::new(BLOCKS),
            sequence: AtomicU64::new(0),
            ledger: Ledger::new(
                PeerConsumerDiagnosticRole::ALL.len(),
                &[PeerConsumerDiagnosticRole::ALL.len()],
            ),
        }
    }
}

fn decode_event(
    sequence: u64,
    mut record: WordReader,
) -> Option<PeerConsumerDiagnosticEventSnapshot> {
    Some(PeerConsumerDiagnosticEventSnapshot {
        sequence,
        observed_at_ms: record.u64()?,
        tenant_id: record.uuid()?,
        device_id: record.uuid()?,
        session_id: record.text()?,
        epoch: record.u64()?,
        service_id: record.uuid()?,
        request_id: record.text()?,
        role: variant(&PeerConsumerDiagnosticRole::ALL, record.u64()?)?,
        outcome: variant(&PeerTransportDiagnosticOutcome::ALL, record.u64()?)?,
        h3_code: match record.opt_u64()? {
            Some(code) => Some(variant(&PeerConsumerDiagnosticH3Code::ALL, code)?),
            None => None,
        },
    })
}

/// Cloneable bounded state for the consumer peer route.
#[derive(Clone, Default)]
pub(crate) struct PeerConsumerDiagnostics {
    state: Arc<PeerConsumerDiagnosticState>,
}

impl PeerConsumerDiagnostics {
    /// Record one typed terminal outcome without retaining transport text.
    ///
    /// The role's count and its latest event change in one atomic step, and
    /// the sequence is drawn by the step that installs them, so the latest
    /// event is the one with the highest sequence.
    pub(crate) fn record(
        &self,
        context: &PeerConsumerDiagnosticContext,
        role: PeerConsumerDiagnosticRole,
        outcome: PeerTransportDiagnosticOutcome,
        h3_code: Option<PeerConsumerDiagnosticH3Code>,
    ) {
        let state = &*self.state;
        let mut event = WordWriter::new();
        event.u64(diagnostic_now_ms());
        event.uuid(context.tenant_id);
        event.uuid(context.device_id);
        event.text(&context.session_id);
        event.u64(context.epoch);
        event.uuid(context.service_id);
        event.text(&context.request_id);
        let index = code_of(&PeerConsumerDiagnosticRole::ALL, &role);
        event.u64(index);
        event.u64(code_of(&PeerTransportDiagnosticOutcome::ALL, &outcome));
        event.opt_u64(h3_code.map(|code| code_of(&PeerConsumerDiagnosticH3Code::ALL, &code)));
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

    /// Return the bounded typed view used by the relay snapshot.
    #[must_use]
    pub(crate) fn snapshot(&self) -> PeerConsumerDiagnosticSnapshot {
        let Some(view) = self.state.ledger.read(&self.state.arena) else {
            return PeerConsumerDiagnosticSnapshot {
                unavailable: true,
                ..PeerConsumerDiagnosticSnapshot::default()
            };
        };
        let mut snapshot = PeerConsumerDiagnosticSnapshot {
            ingress_send_count: view.count(0),
            ingress_receive_count: view.count(1),
            owner_send_count: view.count(2),
            owner_receive_count: view.count(3),
            ..PeerConsumerDiagnosticSnapshot::default()
        };
        for retained in view.retained {
            let Some(event) = decode_event(retained.order, retained.record) else {
                continue;
            };
            let last = match event.role {
                PeerConsumerDiagnosticRole::IngressSend => &mut snapshot.last_ingress_send,
                PeerConsumerDiagnosticRole::IngressReceive => &mut snapshot.last_ingress_receive,
                PeerConsumerDiagnosticRole::OwnerSend => &mut snapshot.last_owner_send,
                PeerConsumerDiagnosticRole::OwnerReceive => &mut snapshot.last_owner_receive,
            };
            *last = Some(event);
        }
        snapshot
    }
}

static DIAGNOSTIC_ORIGIN: OnceLock<Instant> = OnceLock::new();

fn diagnostic_now_ms() -> u64 {
    DIAGNOSTIC_ORIGIN
        .get_or_init(Instant::now)
        .elapsed()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

/// Classify a transport error using only the bounded H3 code allowlist.
///
/// The input is inspected transiently at the relay boundary and is never
/// copied into a snapshot or emitted as a diagnostic string.
pub(crate) fn classify_h3_code(message: &str) -> PeerConsumerDiagnosticH3Code {
    if message.contains("H3_FRAME_UNEXPECTED") {
        PeerConsumerDiagnosticH3Code::FrameUnexpected
    } else if message.contains("H3_REQUEST_CANCELLED") {
        PeerConsumerDiagnosticH3Code::RequestCancelled
    } else if message.contains("H3_NO_ERROR") {
        PeerConsumerDiagnosticH3Code::NoError
    } else {
        PeerConsumerDiagnosticH3Code::Other
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use crate::peer_transport_diagnostics::PeerTransportDiagnosticOutcome;

    use super::{
        PeerConsumerDiagnosticContext, PeerConsumerDiagnosticH3Code, PeerConsumerDiagnosticRole,
        PeerConsumerDiagnostics, classify_h3_code,
    };

    #[test]
    fn h3_diagnostic_classification_is_closed_and_redacted() {
        assert_eq!(
            classify_h3_code("H3_FRAME_UNEXPECTED: secret transport detail"),
            PeerConsumerDiagnosticH3Code::FrameUnexpected
        );
        assert_eq!(
            classify_h3_code("H3_REQUEST_CANCELLED"),
            PeerConsumerDiagnosticH3Code::RequestCancelled
        );
        assert_eq!(
            classify_h3_code("H3_NO_ERROR"),
            PeerConsumerDiagnosticH3Code::NoError
        );
        assert_eq!(
            classify_h3_code("unrecognized transport detail"),
            PeerConsumerDiagnosticH3Code::Other
        );
    }

    #[test]
    fn event_snapshot_keeps_exact_bounded_forwarding_identity() {
        let diagnostics = PeerConsumerDiagnostics::default();
        let context = PeerConsumerDiagnosticContext {
            tenant_id: Uuid::from_u128(1),
            device_id: Uuid::from_u128(2),
            session_id: "session-7".to_owned(),
            epoch: 9,
            service_id: Uuid::from_u128(3),
            request_id: "request-11".to_owned(),
        };

        diagnostics.record(
            &context,
            PeerConsumerDiagnosticRole::OwnerSend,
            PeerTransportDiagnosticOutcome::H3Error,
            Some(PeerConsumerDiagnosticH3Code::FrameUnexpected),
        );

        let snapshot = diagnostics.snapshot();
        let event = snapshot.last_owner_send.expect("owner event is retained");
        assert_eq!(snapshot.owner_send_count, 1);
        assert_eq!(event.sequence, 1);
        assert_eq!(event.tenant_id, context.tenant_id);
        assert_eq!(event.device_id, context.device_id);
        assert_eq!(event.session_id, context.session_id);
        assert_eq!(event.epoch, context.epoch);
        assert_eq!(event.service_id, context.service_id);
        assert_eq!(event.request_id, context.request_id);
        assert_eq!(
            event.h3_code,
            Some(PeerConsumerDiagnosticH3Code::FrameUnexpected)
        );

        diagnostics.record(
            &context,
            PeerConsumerDiagnosticRole::IngressReceive,
            PeerTransportDiagnosticOutcome::Closed,
            None,
        );
        let second = diagnostics
            .snapshot()
            .last_ingress_receive
            .expect("ingress event is retained");
        assert!(event.observed_at_ms <= second.observed_at_ms);
    }
}
