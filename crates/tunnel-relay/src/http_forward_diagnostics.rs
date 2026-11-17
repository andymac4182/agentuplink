//! Bounded, payload-free diagnostics for `http-forward/1` exchanges.
//!
//! Each hop an exchange crosses on this relay records its queue high-water
//! marks when the hop ends: the owner actor's per-stream receive buffer and
//! credit-parked bytes, the peer HTTP/3 stream's credited in-flight bytes
//! and receive queue, and the ingress bridge's handoff and body queues.
//! Records contain identifiers, byte counts and closed-vocabulary labels
//! only; never header values, paths, bodies or credentials.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use serde::Serialize;
use tunnel_http_forward::{RecordPosition, TrackerSnapshot};

use crate::peer_transport_diagnostics::cells::{
    Arena, Entry, LabelTable, Ledger, Order, Place, Pool, Slot, WordReader, WordWriter, bump, read,
    reads_refused, records_dropped,
};

/// M6-C190 review: set to `1` to log each failed `http-forward/1` exchange
/// and each owner HTTP stream released without both FINs as a payload-free
/// `warn` line (`scripts/m6-soak.py` sets it).  Off by default: a routine
/// consumer cancel releases a stream without both FINs, so the lines would
/// otherwise scale with ordinary traffic.  The same variable enables the
/// connector's `http-exchange-failed` line.
pub const HTTP_EXCHANGE_LOG_ENV: &str = "AGENT_TUNNEL_HTTP_EXCHANGE_LOG";

/// Whether [`HTTP_EXCHANGE_LOG_ENV`] is `1`, read once per process.
#[must_use]
pub fn exchange_log_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var(HTTP_EXCHANGE_LOG_ENV).is_ok_and(|value| value == "1"))
}

/// The most recent records retained per kind.
pub const MAX_HTTP_FORWARD_RECORDS: usize = 64;

/// One peer hop's send and receive byte counts **as they stood at a single
/// instant**.
///
/// The peer hop's two published high-water figures are independent all-time
/// `max` latches, so both reading high is equally consistent with two
/// disjoint bursts (task row M8-C22).  This pair is the answer to that: both
/// levels live in one atomic word, every change to either is one atomic step
/// on that word, and the pair is the word as that step left it, so the two
/// numbers are a reading of the same moment rather than two readings joined
/// afterwards.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct HopBytePair {
    /// Credited bytes sent on the peer stream and not yet consumed by the
    /// peer.
    pub send_bytes: usize,
    /// Peer DATA bytes received here and not yet consumed by the next hop.
    pub receive_bytes: usize,
}

impl HopBytePair {
    /// The smaller of the two directions.  A coincident latch is ordered by
    /// this, because it is what a claim of *both* directions loaded rests on:
    /// a pair is better attested than another exactly when the weaker of its
    /// two halves is larger.
    #[must_use]
    pub const fn smaller(self) -> usize {
        if self.send_bytes < self.receive_bytes {
            self.send_bytes
        } else {
            self.receive_bytes
        }
    }
}

/// A peer hop's live byte pair, plus the best-attested coincident instant it
/// has reached.
///
/// Held behind an `Arc` by the hop itself.  Registering it with
/// [`HttpForwardDiagnostics`] gives it a cell in the diagnostics' own table,
/// into which it copies every reading, so the live pair is readable on the
/// forwarding snapshot for as long as the hop exists and disappears with it.
/// Without the live half, any assertion about the hop is post-hoc: a stalled
/// response direction terminates only at the export's 30 s output-credit
/// budget, so an observation window shorter than the exchange sees no record
/// at all.
#[derive(Debug, Default)]
pub struct HopLivePair {
    /// Both live levels and the published flag as one word: the flag in the
    /// top bit, send above receive below, [`LEVEL_BITS`] bits each (a hop's
    /// credit window is orders of magnitude below that).  Every change to
    /// either level is one atomic step on this word, so the word is always
    /// a pair that existed at one instant, and the step that changes a level
    /// also learns whether the hop was published at that instant.
    live: AtomicU64,
    /// The coincident pair as one word, so its two halves are always the
    /// two halves of one instant: send in the high half, receive in the low
    /// half.
    coincident: AtomicU64,
    /// Set once this hop has a published cell to mirror its readings into.
    published: OnceLock<PublishedHop>,
}

const HALF_MASK: u64 = u32::MAX as u64;

/// Width of one live level.
const LEVEL_BITS: u32 = 31;
const LEVEL_MASK: u64 = (1 << LEVEL_BITS) - 1;
/// Set in the live word, in one atomic step, when the hop is published.
const PUBLISHED: u64 = 1 << 63;

fn pack_pair(pair: HopBytePair) -> u64 {
    let half = |bytes: usize| u64::try_from(bytes).map_or(HALF_MASK, |bytes| bytes.min(HALF_MASK));
    (half(pair.send_bytes) << 32) | half(pair.receive_bytes)
}

fn unpack_pair(word: u64) -> HopBytePair {
    let half = |half: u64| usize::try_from(half & HALF_MASK).unwrap_or(usize::MAX);
    HopBytePair {
        send_bytes: half(word >> 32),
        receive_bytes: half(word),
    }
}

/// The two levels of a live word, as `(send, receive)`.
const fn live_levels(word: u64) -> (u64, u64) {
    ((word >> LEVEL_BITS) & LEVEL_MASK, word & LEVEL_MASK)
}

fn live_pair(word: u64) -> HopBytePair {
    let (send, receive) = live_levels(word);
    HopBytePair {
        send_bytes: usize::try_from(send).unwrap_or(usize::MAX),
        receive_bytes: usize::try_from(receive).unwrap_or(usize::MAX),
    }
}

/// One direction's change of level.
#[derive(Clone, Copy)]
enum LevelChange {
    Add(u64),
    Sub(u64),
}

impl LevelChange {
    /// A level stays within its field: it saturates at the top and at zero.
    fn apply(self, level: u64) -> u64 {
        match self {
            Self::Add(bytes) => level.saturating_add(bytes).min(LEVEL_MASK),
            Self::Sub(bytes) => level.saturating_sub(bytes),
        }
    }
}

fn level_change(bytes: usize, change: fn(u64) -> LevelChange) -> LevelChange {
    change(u64::try_from(bytes).unwrap_or(u64::MAX))
}

/// Replace the pair held in `word` only with a better-attested one, in a
/// single compare-and-swap of the packed word.
fn latch_pair(word: &AtomicU64, candidate: HopBytePair) {
    if candidate.smaller() == 0 {
        return;
    }
    let _ = word.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |held| {
        (candidate.smaller() > unpack_pair(held).smaller()).then(|| pack_pair(candidate))
    });
}

impl HopLivePair {
    /// Raise the send level by `bytes` just charged to the peer stream.
    pub fn add_send(&self, bytes: usize) {
        self.shift(Some(level_change(bytes, LevelChange::Add)), None);
    }

    /// Lower the send level by `bytes` the peer has reported consumed.
    /// Callers lower a level only by bytes they raised it by earlier.
    pub fn sub_send(&self, bytes: usize) {
        self.shift(Some(level_change(bytes, LevelChange::Sub)), None);
    }

    /// Raise the receive level by `bytes` just queued for the next hop.
    pub fn add_receive(&self, bytes: usize) {
        self.shift(None, Some(level_change(bytes, LevelChange::Add)));
    }

    /// Lower the receive level by `bytes` the next hop has consumed.
    pub fn sub_receive(&self, bytes: usize) {
        self.shift(None, Some(level_change(bytes, LevelChange::Sub)));
    }

    /// Move one level, in one atomic step on the live word.
    ///
    /// The step yields the pair exactly as it stood the instant the level
    /// moved -- this direction's new level beside the other direction's
    /// level in the same word -- and the coincident latch is offered that
    /// pair and no other, so it can only ever hold a pair that existed.
    /// Concurrent movers of the same level each contribute their own
    /// difference, so the level is exact however they interleave: there is
    /// no reading to go stale and nothing to publish again.
    fn shift(&self, send: Option<LevelChange>, receive: Option<LevelChange>) {
        let moved = |word: u64| {
            let (send_level, receive_level) = live_levels(word);
            let send_level = send.map_or(send_level, |change| change.apply(send_level));
            let receive_level = receive.map_or(receive_level, |change| change.apply(receive_level));
            (word & PUBLISHED) | (send_level << LEVEL_BITS) | receive_level
        };
        let before = self
            .live
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |word| Some(moved(word)))
            .unwrap_or_else(|word| word);
        let after = moved(before);
        latch_pair(&self.coincident, live_pair(after));
        // The cell is installed before the published flag is raised and
        // before the registration copies this hop's latch, so a mover that
        // finds no cell here moved before both and is covered by that copy.
        let Some(cell) = self.published.get().and_then(PublishedHop::cell) else {
            return;
        };
        latch_pair(&cell.coincident, live_pair(after));
        if before & PUBLISHED != 0 {
            // This move happened after the registration took the levels, so
            // it is this mover's to mirror; one that happened before is in
            // the levels the registration took.  Differences commute, so
            // the cell's levels are the hop's however the movers interleave.
            let (send_before, receive_before) = live_levels(before);
            let (send_after, receive_after) = live_levels(after);
            mirror_level(&cell.send_bytes, send_before, send_after);
            mirror_level(&cell.receive_bytes, receive_before, receive_after);
        }
    }

    /// Publish this hop in `published`'s cell.  `false` means the hop is
    /// already published and the offered cell was dropped unused.
    ///
    /// The cell is unpublished (ordinal zero) and reset here, then
    /// installed; the levels are taken in the same atomic step that raises
    /// the published flag, so every move is either in the levels taken or
    /// mirrored by its mover, never both and never neither.
    fn bind(&self, published: PublishedHop) -> bool {
        if let Some(cell) = published.cell() {
            cell.send_bytes.store(0, Ordering::SeqCst);
            cell.receive_bytes.store(0, Ordering::SeqCst);
            cell.coincident.store(0, Ordering::SeqCst);
        }
        if self.published.set(published).is_err() {
            return false;
        }
        let Some(cell) = self.published.get().and_then(PublishedHop::cell) else {
            return true;
        };
        let (send, receive) = live_levels(self.live.fetch_or(PUBLISHED, Ordering::SeqCst));
        cell.send_bytes.fetch_add(send, Ordering::SeqCst);
        cell.receive_bytes.fetch_add(receive, Ordering::SeqCst);
        latch_pair(&cell.coincident, self.coincident());
        true
    }

    /// The pair as it stands now.
    #[must_use]
    pub fn live(&self) -> HopBytePair {
        live_pair(self.live.load(Ordering::SeqCst))
    }

    /// The pair at the instant the smaller of the two was largest.
    #[must_use]
    pub fn coincident(&self) -> HopBytePair {
        unpack_pair(self.coincident.load(Ordering::SeqCst))
    }
}

/// Apply one level's difference to its mirrored cell.  The arithmetic
/// wraps, so a fall mirrored ahead of the registration's own addition is
/// made whole by it; the cell is not readable until that addition is done.
fn mirror_level(cell: &AtomicU64, before: u64, after: u64) {
    if after >= before {
        cell.fetch_add(after - before, Ordering::SeqCst);
    } else {
        cell.fetch_sub(before - after, Ordering::SeqCst);
    }
}

/// One published hop's cell in the diagnostics' table: the registration
/// ordinal (zero while the cell is unpublished), the hop's copied readings,
/// and its identifying record.
#[derive(Default)]
struct HopCell {
    ordinal: AtomicU64,
    send_bytes: AtomicU64,
    receive_bytes: AtomicU64,
    coincident: AtomicU64,
    identity: Slot,
}

/// A hop's hold on its published cell.  Dropped with the hop, which
/// unpublishes the cell and recycles it, so no teardown path can leak one.
struct PublishedHop {
    shared: Arc<Shared>,
    index: u64,
}

impl PublishedHop {
    fn cell(&self) -> Option<&HopCell> {
        self.shared.hops.node(self.index).map(|node| &node.body)
    }
}

impl fmt::Debug for PublishedHop {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublishedHop")
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

impl Drop for PublishedHop {
    fn drop(&mut self) {
        if let Some(cell) = self.cell() {
            cell.ordinal.store(0, Ordering::SeqCst);
            cell.identity.clear(&self.shared.arena);
        }
        self.shared.hops.release(self.index);
    }
}

/// One peer hop that is still open, sampled from the forwarding snapshot.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct HttpLiveHopRecord {
    /// `ingress_remote` or `owner_peer`.
    pub role: &'static str,
    pub request_id: Option<String>,
    pub stream_id: Option<u64>,
    /// The hop's send/receive bytes as of this snapshot pass.
    pub live: HopBytePair,
    /// The best-attested coincident pair this hop has reached so far.
    pub coincident: HopBytePair,
    /// The hop's per-direction credit window.
    pub window: usize,
}

/// A payload-free record-grammar position of one direction: counters of the
/// record headers seen and where the byte stream stops.  Nothing here is
/// derived from a payload octet.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct HttpRecordPosition {
    pub heads: u32,
    pub bodies: u64,
    pub ends: u32,
    pub body_bytes: u64,
    pub total_bytes: u64,
    /// `boundary`, `partial_header`, `partial_head` or `partial_body`.
    pub position: &'static str,
    /// Bytes of the unfinished header or payload that arrived.
    pub partial_received: u32,
    /// The unfinished payload's declared length (zero inside a header).
    pub partial_total: u32,
    pub invalid: bool,
}

impl From<TrackerSnapshot> for HttpRecordPosition {
    fn from(snapshot: TrackerSnapshot) -> Self {
        let (partial_received, partial_total) = match snapshot.position {
            RecordPosition::Boundary => (0, 0),
            RecordPosition::Header { received } => (u32::from(received), 0),
            RecordPosition::Payload {
                received, total, ..
            } => (received, total),
        };
        Self {
            heads: snapshot.heads,
            bodies: snapshot.bodies,
            ends: snapshot.ends,
            body_bytes: snapshot.body_bytes,
            total_bytes: snapshot.total_bytes,
            position: snapshot.position.label(),
            partial_received,
            partial_total,
            invalid: snapshot.invalid,
        }
    }
}

/// The owner's view of one HTTP stream at a completed scheduled rotation.
///
/// The record positions and parked/buffered bytes are captured when the
/// owner froze its writer at QUIESCE (so the request position is exactly
/// what was sequenced below the relay fence); the fences and acknowledgement
/// cursors are the attempt's drain proof, read at its commit decision.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct HttpRotationObservation {
    pub stream_id: u64,
    pub operation_id: String,
    pub request_id: Option<String>,
    /// The completed-rotation count this attempt reaches when it completes.
    pub rotation: u64,
    pub rotation_id: String,
    pub old_generation: u64,
    pub new_generation: u64,
    /// Owner→device bytes sequenced before the freeze.
    pub request: HttpRecordPosition,
    /// The owner's FIN was sequenced before the freeze.
    pub request_fin_sequenced: bool,
    /// Device→owner bytes received before the freeze.
    pub response: HttpRecordPosition,
    pub response_fin_received: bool,
    /// Owner→device bytes held unsequenced (credit, replay or the freeze).
    pub parked_bytes: usize,
    /// Device→owner bytes held for the reader: credit withheld by the owner.
    pub receive_buffered_bytes: usize,
    /// `fin` or `reset` when a terminal waited behind the freeze.
    pub deferred_terminal: Option<&'static str>,
    /// The owner's `last_emitted` when it froze.
    pub frozen_last_emitted: u64,
    pub relay_fence: Option<u64>,
    pub connector_fence: Option<u64>,
    pub relay_acknowledged: Option<u64>,
    pub connector_acknowledged: Option<u64>,
}

/// The live owner view of one HTTP stream in a relay snapshot.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct RelayHttpStreamSnapshot {
    /// Owner→device bytes sequenced so far.
    pub request: HttpRecordPosition,
    pub request_fin_sequenced: bool,
    /// Device→owner bytes received in order so far.
    pub response: HttpRecordPosition,
    pub response_fin_received: bool,
    /// Owner→device bytes waiting unsequenced (credit, replay or freeze).
    pub parked_bytes: usize,
    /// Device→owner bytes waiting for the reader.
    pub receive_buffered_bytes: usize,
    /// Cumulative owner→device send credit and bytes sent.
    pub send_credit: u64,
    pub sent_bytes: u64,
    /// `fin` or `reset` while a terminal waits behind parked data or a
    /// freeze.
    pub deferred_terminal: Option<&'static str>,
    pub local_reset: Option<u16>,
    pub peer_reset: Option<u16>,
    pub cancel_sent: bool,
    pub reset_sequence: Option<u64>,
    pub reset_generation: Option<u64>,
    pub reset_deferred_by_freeze: bool,
    /// The owner's writer is frozen for rotation or recovery.
    pub frozen: bool,
    /// M3-22: this stream's own most recent rotation observations, newest
    /// last.  Unlike the relay-wide `rotations` ring, these cannot be evicted
    /// by other streams while this one is live.
    pub rotation_observations: Vec<HttpRotationObservation>,
}

/// The owner published `STREAM_FORGET` for an HTTP stream and removed it.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct HttpForgetRecord {
    pub stream_id: u64,
    pub operation_id: String,
    pub request_id: Option<String>,
}

/// One owner-actor logical stream carrying an HTTP exchange.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct HttpOwnerStreamRecord {
    pub stream_id: u64,
    pub operation_id: String,
    /// Peer request identity when the consumer arrived through another relay.
    pub request_id: Option<String>,
    /// Largest number of device→owner DATA bytes held for the reader, charged
    /// to the session budget and bounded by the owner's advertised credit.
    pub receive_buffer_high_water: usize,
    /// The owner's advertised per-stream receive window.
    pub receive_window: usize,
    /// Largest number of owner→device bytes parked for send credit.
    pub parked_bytes_high_water: usize,
    /// Largest number of sent-but-unacknowledged bytes retained for replay.
    pub replay_bytes_high_water: usize,
    /// Owner→device DATA payload bytes emitted.
    pub sent_bytes: u64,
    /// Device→owner DATA payload bytes delivered to the reader.
    pub delivered_bytes: u64,
    /// `fin`, `reset` or `closed`: how the owner released the stream.
    pub release: &'static str,
    /// The RESET reason code emitted or received, when any.
    pub reset_reason: Option<u16>,
    /// Final owner→device (sequenced) and device→owner (received) record
    /// positions.
    pub request: HttpRecordPosition,
    pub response: HttpRecordPosition,
    /// The owner's own RESET: its sequence, the generation of the carrier it
    /// was queued on, and whether a rotation freeze deferred it.
    pub reset_sequence: Option<u64>,
    pub reset_generation: Option<u64>,
    pub reset_deferred_by_freeze: bool,
    /// The owner sent a scoped control `CANCEL` for this stream.
    pub cancel_sent: bool,
}

/// One bridge or peer-hop exchange endpoint on this relay.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct HttpExchangeRecord {
    /// `ingress_local`, `ingress_remote` or `owner_peer`.
    pub role: &'static str,
    pub request_id: Option<String>,
    pub stream_id: Option<u64>,
    /// Bridge→carrier request handoff high-water bytes (ingress roles).
    pub request_handoff_high_water: usize,
    /// Carrier→bridge response handoff high-water bytes (ingress roles).
    pub response_handoff_high_water: usize,
    /// Queued public response body high-water bytes (ingress roles).
    pub response_body_high_water: usize,
    /// Largest credited in-flight bytes this relay had sent on the peer
    /// HTTP/3 stream but the peer had not yet consumed.
    pub peer_send_in_flight_high_water: usize,
    /// Largest number of peer DATA bytes received and queued here but not
    /// yet consumed by the next hop.
    pub peer_receive_queue_high_water: usize,
    /// The send/receive pair **at one instant**: the moment the smaller of
    /// the hop's two directions was largest.  The two fields above are
    /// independent all-time latches and cannot show simultaneity; this one
    /// can, because it is written as a pair from a single mutation point
    /// (task row M8-C22).
    pub peer_coincident: HopBytePair,
    /// The peer hop's per-direction credit window, when a peer hop exists.
    pub peer_window: usize,
    /// Terminal labels: `complete`, `aborted` or `pending`, and for the
    /// response direction also `released` (the consumer let go of the body
    /// after its head, M3-32).
    pub request_outcome: &'static str,
    pub response_outcome: &'static str,
    /// The first sanitized `HTTP_*` code, when any.  An `owner_peer` record
    /// carries one only when the owner's own record validation or progress
    /// budget failed the exchange.
    pub error_code: Option<&'static str>,
    /// `not_dispatched`, `dispatched` or `unknown`.  An `owner_peer` record
    /// holds no dispatch knowledge beyond its own validation.
    pub execution: &'static str,
    /// The transport progress budget that expired at this endpoint, when
    /// one did: `first_head`, `record`, `credit_stall` or `fin_after_end`.
    pub progress_expired: Option<&'static str>,
}

/// The retained diagnostic snapshot.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct HttpForwardDiagnosticSnapshot {
    pub owner_streams: Vec<HttpOwnerStreamRecord>,
    pub exchanges: Vec<HttpExchangeRecord>,
    pub rotations: Vec<HttpRotationObservation>,
    pub forgotten: Vec<HttpForgetRecord>,
    pub owner_streams_recorded: u64,
    pub exchanges_recorded: u64,
    pub rotations_recorded: u64,
    pub forgotten_recorded: u64,
    /// Public requests refused by head normalization before any owner
    /// route, peer stream or tunnel stream was opened.
    pub ingress_rejected_before_admission: u64,
    /// M3-16: `PRINCIPAL_SESSIONS_END` messages queued to a device after a
    /// watched consumer's grant was revoked, and those the control queue
    /// refused.
    pub principal_sessions_end_sent: u64,
    pub principal_sessions_end_failed: u64,
    /// Revocations not sent because the connector did not advertise
    /// `principal-sessions-end-v1`.
    pub principal_sessions_end_unsupported: u64,
    /// Highest HTTP peer-hop bytes this relay had in flight to (sent) and
    /// queued from (received) any one peer across all its streams, and the
    /// per-direction aggregate bound.
    pub hop_aggregate_send_high_water: usize,
    pub hop_aggregate_receive_high_water: usize,
    pub hop_aggregate_limit: usize,
    /// Every peer hop still open on this relay, with its live send/receive
    /// pair and its coincident latch.  An observation window shorter than an
    /// exchange sees the hop here; `exchanges` above only gains the hop once
    /// it has terminated.
    pub live_peer_hops: Vec<HttpLiveHopRecord>,
    /// Record labels that did not fit this process's label table and were
    /// reported as `other`.  Zero unless the table is smaller than the
    /// label vocabularies, which is a defect to fix in the table's size.
    pub label_overflow: u64,
    /// Diagnostic records of any relay diagnostic in this process (and the
    /// counts that went with them) not recorded because diagnostic storage
    /// was at its cap (at most 11.5 MB per diagnostic).  That takes several
    /// thousand recorders in flight at once, or a snapshot reader stalled
    /// mid-read under heavy recording; the reported state stays consistent
    /// and the records refused are counted here.
    pub diagnostic_records_dropped: u64,
    /// Snapshots of any relay diagnostic in this process refused, and
    /// reported as `unavailable`, because too many reads of it were in
    /// progress at once.
    pub diagnostic_reads_refused: u64,
    /// True only when this snapshot could not be taken because too many
    /// reads of these diagnostics were in progress at once.  Every other
    /// field is then a placeholder and not an observation: the counts are
    /// unknown, not zero.  Absent from the serialized snapshot otherwise.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub unavailable: bool,
}

/// Every static label a record carries, indexed so a record can name one in
/// a single word.  The table is shared by every label field of every
/// recorder in the process.  The labels are closed vocabularies: three
/// roles, three releases, four record positions, two deferred terminals,
/// four outcomes, three execution states, four progress budgets, the empty
/// default, and the sanitized `HTTP_*` codes of `tunnel-http-forward`,
/// together a few dozen.  One that does not fit is counted in
/// `label_overflow` and asserted against in a debug build.
static LABELS: LabelTable<128> = LabelTable::new();

fn encode_position(record: &mut WordWriter, position: &HttpRecordPosition) {
    record.u64(u64::from(position.heads));
    record.u64(position.bodies);
    record.u64(u64::from(position.ends));
    record.u64(position.body_bytes);
    record.u64(position.total_bytes);
    record.label(&LABELS, position.position);
    record.u64(u64::from(position.partial_received));
    record.u64(u64::from(position.partial_total));
    record.flag(position.invalid);
}

fn decode_u32(record: &mut WordReader) -> Option<u32> {
    u32::try_from(record.u64()?).ok()
}

fn decode_opt_u16(record: &mut WordReader) -> Option<Option<u16>> {
    match record.opt_u64()? {
        Some(value) => Some(Some(u16::try_from(value).ok()?)),
        None => Some(None),
    }
}

fn decode_position(record: &mut WordReader) -> Option<HttpRecordPosition> {
    Some(HttpRecordPosition {
        heads: decode_u32(record)?,
        bodies: record.u64()?,
        ends: decode_u32(record)?,
        body_bytes: record.u64()?,
        total_bytes: record.u64()?,
        position: record.label(&LABELS)?,
        partial_received: decode_u32(record)?,
        partial_total: decode_u32(record)?,
        invalid: record.flag()?,
    })
}

fn encode_owner_stream(value: &HttpOwnerStreamRecord) -> WordWriter {
    let mut record = WordWriter::new();
    record.u64(value.stream_id);
    record.text(&value.operation_id);
    record.opt_text(value.request_id.as_deref());
    record.size(value.receive_buffer_high_water);
    record.size(value.receive_window);
    record.size(value.parked_bytes_high_water);
    record.size(value.replay_bytes_high_water);
    record.u64(value.sent_bytes);
    record.u64(value.delivered_bytes);
    record.label(&LABELS, value.release);
    record.opt_u64(value.reset_reason.map(u64::from));
    encode_position(&mut record, &value.request);
    encode_position(&mut record, &value.response);
    record.opt_u64(value.reset_sequence);
    record.opt_u64(value.reset_generation);
    record.flag(value.reset_deferred_by_freeze);
    record.flag(value.cancel_sent);
    record
}

fn decode_owner_stream(mut record: WordReader) -> Option<HttpOwnerStreamRecord> {
    let record = &mut record;
    Some(HttpOwnerStreamRecord {
        stream_id: record.u64()?,
        operation_id: record.text()?,
        request_id: record.opt_text()?,
        receive_buffer_high_water: record.size()?,
        receive_window: record.size()?,
        parked_bytes_high_water: record.size()?,
        replay_bytes_high_water: record.size()?,
        sent_bytes: record.u64()?,
        delivered_bytes: record.u64()?,
        release: record.label(&LABELS)?,
        reset_reason: decode_opt_u16(record)?,
        request: decode_position(record)?,
        response: decode_position(record)?,
        reset_sequence: record.opt_u64()?,
        reset_generation: record.opt_u64()?,
        reset_deferred_by_freeze: record.flag()?,
        cancel_sent: record.flag()?,
    })
}

fn encode_exchange(value: &HttpExchangeRecord) -> WordWriter {
    let mut record = WordWriter::new();
    record.label(&LABELS, value.role);
    record.opt_text(value.request_id.as_deref());
    record.opt_u64(value.stream_id);
    record.size(value.request_handoff_high_water);
    record.size(value.response_handoff_high_water);
    record.size(value.response_body_high_water);
    record.size(value.peer_send_in_flight_high_water);
    record.size(value.peer_receive_queue_high_water);
    record.size(value.peer_coincident.send_bytes);
    record.size(value.peer_coincident.receive_bytes);
    record.size(value.peer_window);
    record.label(&LABELS, value.request_outcome);
    record.label(&LABELS, value.response_outcome);
    record.opt_label(&LABELS, value.error_code);
    record.label(&LABELS, value.execution);
    record.opt_label(&LABELS, value.progress_expired);
    record
}

fn decode_exchange(mut record: WordReader) -> Option<HttpExchangeRecord> {
    Some(HttpExchangeRecord {
        role: record.label(&LABELS)?,
        request_id: record.opt_text()?,
        stream_id: record.opt_u64()?,
        request_handoff_high_water: record.size()?,
        response_handoff_high_water: record.size()?,
        response_body_high_water: record.size()?,
        peer_send_in_flight_high_water: record.size()?,
        peer_receive_queue_high_water: record.size()?,
        peer_coincident: HopBytePair {
            send_bytes: record.size()?,
            receive_bytes: record.size()?,
        },
        peer_window: record.size()?,
        request_outcome: record.label(&LABELS)?,
        response_outcome: record.label(&LABELS)?,
        error_code: record.opt_label(&LABELS)?,
        execution: record.label(&LABELS)?,
        progress_expired: record.opt_label(&LABELS)?,
    })
}

fn encode_rotation(value: &HttpRotationObservation) -> WordWriter {
    let mut record = WordWriter::new();
    record.u64(value.stream_id);
    record.text(&value.operation_id);
    record.opt_text(value.request_id.as_deref());
    record.u64(value.rotation);
    record.text(&value.rotation_id);
    record.u64(value.old_generation);
    record.u64(value.new_generation);
    encode_position(&mut record, &value.request);
    record.flag(value.request_fin_sequenced);
    encode_position(&mut record, &value.response);
    record.flag(value.response_fin_received);
    record.size(value.parked_bytes);
    record.size(value.receive_buffered_bytes);
    record.opt_label(&LABELS, value.deferred_terminal);
    record.u64(value.frozen_last_emitted);
    record.opt_u64(value.relay_fence);
    record.opt_u64(value.connector_fence);
    record.opt_u64(value.relay_acknowledged);
    record.opt_u64(value.connector_acknowledged);
    record
}

fn decode_rotation(mut record: WordReader) -> Option<HttpRotationObservation> {
    let record = &mut record;
    Some(HttpRotationObservation {
        stream_id: record.u64()?,
        operation_id: record.text()?,
        request_id: record.opt_text()?,
        rotation: record.u64()?,
        rotation_id: record.text()?,
        old_generation: record.u64()?,
        new_generation: record.u64()?,
        request: decode_position(record)?,
        request_fin_sequenced: record.flag()?,
        response: decode_position(record)?,
        response_fin_received: record.flag()?,
        parked_bytes: record.size()?,
        receive_buffered_bytes: record.size()?,
        deferred_terminal: record.opt_label(&LABELS)?,
        frozen_last_emitted: record.u64()?,
        relay_fence: record.opt_u64()?,
        connector_fence: record.opt_u64()?,
        relay_acknowledged: record.opt_u64()?,
        connector_acknowledged: record.opt_u64()?,
    })
}

fn encode_forget(value: &HttpForgetRecord) -> WordWriter {
    let mut record = WordWriter::new();
    record.u64(value.stream_id);
    record.text(&value.operation_id);
    record.opt_text(value.request_id.as_deref());
    record
}

fn decode_forget(mut record: WordReader) -> Option<HttpForgetRecord> {
    Some(HttpForgetRecord {
        stream_id: record.u64()?,
        operation_id: record.text()?,
        request_id: record.opt_text()?,
    })
}

/// The recorder's cells.  Each record kind is one ledger holding that
/// kind's recorded count and its retained records, changed together; the
/// remaining counters and high-water marks are each reported alone and are
/// independent of one another and of the ledgers.
struct Shared {
    arena: Arena,
    owner_streams: Ledger,
    exchanges: Ledger,
    rotations: Ledger,
    forgotten: Ledger,
    ingress_rejected_before_admission: AtomicU64,
    principal_sessions_end_sent: AtomicU64,
    principal_sessions_end_failed: AtomicU64,
    principal_sessions_end_unsupported: AtomicU64,
    hop_aggregate_send_high_water: AtomicU64,
    hop_aggregate_receive_high_water: AtomicU64,
    /// Published live hops, one cell each, and the count ever registered.
    hops: Pool<HopCell>,
    hop_registrations: AtomicU64,
}

impl Default for Shared {
    fn default() -> Self {
        Self {
            arena: Arena::new(BLOCKS),
            owner_streams: Ledger::new(1, &[MAX_HTTP_FORWARD_RECORDS]),
            exchanges: Ledger::new(1, &[MAX_HTTP_FORWARD_RECORDS]),
            rotations: Ledger::new(1, &[MAX_HTTP_FORWARD_RECORDS]),
            forgotten: Ledger::new(1, &[MAX_HTTP_FORWARD_RECORDS]),
            ingress_rejected_before_admission: AtomicU64::new(0),
            principal_sessions_end_sent: AtomicU64::new(0),
            principal_sessions_end_failed: AtomicU64::new(0),
            principal_sessions_end_unsupported: AtomicU64::new(0),
            hop_aggregate_send_high_water: AtomicU64::new(0),
            hop_aggregate_receive_high_water: AtomicU64::new(0),
            hops: Pool::new(MAX_LIVE_HOP_CELLS),
            hop_registrations: AtomicU64::new(0),
        }
    }
}

impl fmt::Debug for Shared {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpForwardDiagnostics")
            .field("live_hop_cells", &self.hops.allocated())
            .finish_non_exhaustive()
    }
}

/// The cap on this diagnostic's record storage: 2^17 blocks of 88 bytes,
/// 11.5 MB.  About a thousand blocks are retained; the rest is head-room
/// for recorders in flight and for blocks parked behind a reader.  At the
/// cap a record is refused and counted.
const BLOCKS: usize = 1 << 17;

/// The cap on live hops published at once, about 4 MB of cells; a hop
/// beyond it is not published.
const MAX_LIVE_HOP_CELLS: usize = 1 << 16;

/// How often one live hop cell is read again when its hop changes mid-read.
const LIVE_HOP_READ_ATTEMPTS: usize = 4;

impl Shared {
    /// Count one record of a kind and retain it, in one atomic step: the
    /// record's place in the ring is the count that step reaches, so a
    /// snapshot showing a count of `n` holds the `n`-th record.  The step
    /// takes the record's blocks and at most three tree nodes.
    fn push(&self, kind: &Ledger, record: WordWriter) {
        kind.commit(
            &self.arena,
            None,
            &[0],
            vec![Entry {
                place: Place::Push(0),
                order: Order::Count(0),
                record,
            }],
        );
    }

    /// One kind's recorded count and its retained records, oldest first.
    /// `None` if the read was refused.
    fn kind<T>(
        &self,
        kind: &Ledger,
        decode: impl Fn(WordReader) -> Option<T>,
    ) -> Option<(u64, Vec<T>)> {
        let view = kind.read(&self.arena)?;
        let recorded = view.count(0);
        let records = view
            .retained
            .into_iter()
            .filter_map(|retained| decode(retained.record))
            .collect();
        Some((recorded, records))
    }

    /// Every published hop, in registration order.  A cell is accepted only
    /// if its registration ordinal is the same before and after it is read,
    /// so a hop that ends, or a cell reused for another hop, mid-read is
    /// read again rather than reported with mixed fields.  A cell is read
    /// at most [`LIVE_HOP_READ_ATTEMPTS`] times: one whose hop was replaced
    /// under every one of them is left out of this snapshot, as a hop that
    /// began or ended while the snapshot was taken may be, so the read is
    /// bounded by the number of cells whatever the hops do meanwhile.
    fn live_hops(&self) -> Vec<HttpLiveHopRecord> {
        let mut hops = Vec::new();
        for index in 0..self.hops.allocated() {
            let Some(cell) = self.hops.node(index).map(|node| &node.body) else {
                continue;
            };
            for _ in 0..LIVE_HOP_READ_ATTEMPTS {
                let ordinal = cell.ordinal.load(Ordering::SeqCst);
                if ordinal == 0 {
                    break;
                }
                let record = cell.identity.read(&self.arena).and_then(|mut identity| {
                    Some(HttpLiveHopRecord {
                        role: identity.label(&LABELS)?,
                        request_id: identity.opt_text()?,
                        stream_id: identity.opt_u64()?,
                        window: identity.size()?,
                        live: HopBytePair {
                            send_bytes: usize::try_from(cell.send_bytes.load(Ordering::SeqCst))
                                .ok()?,
                            receive_bytes: usize::try_from(
                                cell.receive_bytes.load(Ordering::SeqCst),
                            )
                            .ok()?,
                        },
                        coincident: unpack_pair(cell.coincident.load(Ordering::SeqCst)),
                    })
                });
                if cell.ordinal.load(Ordering::SeqCst) == ordinal {
                    if let Some(record) = record {
                        hops.push((ordinal, record));
                    }
                    break;
                }
            }
        }
        hops.sort_by_key(|(ordinal, _)| *ordinal);
        hops.into_iter().map(|(_, record)| record).collect()
    }
}

/// Shared bounded recorder.  A recorder is never held up by one that is
/// descheduled: each record is written whole and then installed with its
/// count in one compare-and-swap, and each lone counter is its own atomic.
#[derive(Clone, Debug, Default)]
pub struct HttpForwardDiagnostics {
    inner: Arc<Shared>,
}

impl HttpForwardDiagnostics {
    pub fn record_owner_stream(&self, record: HttpOwnerStreamRecord) {
        self.inner
            .push(&self.inner.owner_streams, encode_owner_stream(&record));
    }

    pub fn record_exchange(&self, record: HttpExchangeRecord) {
        self.inner
            .push(&self.inner.exchanges, encode_exchange(&record));
    }

    pub fn record_rotation(&self, record: HttpRotationObservation) {
        self.inner
            .push(&self.inner.rotations, encode_rotation(&record));
    }

    pub fn record_forget(&self, record: HttpForgetRecord) {
        self.inner
            .push(&self.inner.forgotten, encode_forget(&record));
    }

    pub fn record_principal_sessions_end(&self, sent: bool) {
        if sent {
            bump(&self.inner.principal_sessions_end_sent);
        } else {
            bump(&self.inner.principal_sessions_end_failed);
        }
    }

    pub fn record_principal_sessions_end_unsupported(&self) {
        bump(&self.inner.principal_sessions_end_unsupported);
    }

    pub fn record_ingress_rejection(&self) {
        bump(&self.inner.ingress_rejected_before_admission);
    }

    /// Publish one open peer hop's live pair on the snapshot.
    ///
    /// The hop is given a cell here and holds it until its shared state is
    /// dropped, which unpublishes the cell, so there is no deregistration
    /// path to forget.  A hop is published once; registering one that is
    /// already published changes nothing.
    pub fn register_live_hop(
        &self,
        role: &'static str,
        request_id: Option<String>,
        stream_id: Option<u64>,
        window: usize,
        pair: &Arc<HopLivePair>,
    ) {
        let shared = &self.inner;
        let Some(index) = shared.hops.acquire() else {
            return;
        };
        let published = PublishedHop {
            shared: Arc::clone(shared),
            index,
        };
        let Some(cell) = published.cell() else {
            return;
        };
        let ordinal = bump(&shared.hop_registrations);
        let mut identity = WordWriter::new();
        identity.label(&LABELS, role);
        identity.opt_text(request_id.as_deref());
        identity.opt_u64(stream_id);
        identity.size(window);
        cell.identity.set(&shared.arena, identity);
        // An already published hop keeps its cell; the one just prepared is
        // recycled as the rejected hold is dropped.
        if !pair.bind(published) {
            return;
        }
        if let Some(cell) = pair.published.get().and_then(PublishedHop::cell) {
            cell.ordinal.store(ordinal, Ordering::SeqCst);
        }
    }

    pub fn note_hop_aggregate(&self, send: usize, receive: usize) {
        self.inner
            .hop_aggregate_send_high_water
            .fetch_max(send as u64, Ordering::SeqCst);
        self.inner
            .hop_aggregate_receive_high_water
            .fetch_max(receive as u64, Ordering::SeqCst);
    }

    /// Call `hook` at each step of every later exchange record, to park a
    /// recorder between its steps.
    #[cfg(test)]
    fn park_exchange_recorders(&self, hook: crate::peer_transport_diagnostics::cells::CommitHook) {
        self.inner.exchanges.park_commits(hook);
    }

    /// The four record kinds are four states read one after another, and
    /// the lone counters are read alone: nothing a snapshot reports relates
    /// one of them to another.  Within a kind the count and the records are
    /// one state.
    #[must_use]
    pub fn snapshot(&self) -> HttpForwardDiagnosticSnapshot {
        let shared = &*self.inner;
        let high_water =
            |mark: &AtomicU64| usize::try_from(mark.load(Ordering::SeqCst)).unwrap_or(usize::MAX);
        let (
            Some((owner_streams_recorded, owner_streams)),
            Some((exchanges_recorded, exchanges)),
            Some((rotations_recorded, rotations)),
            Some((forgotten_recorded, forgotten)),
        ) = (
            shared.kind(&shared.owner_streams, decode_owner_stream),
            shared.kind(&shared.exchanges, decode_exchange),
            shared.kind(&shared.rotations, decode_rotation),
            shared.kind(&shared.forgotten, decode_forget),
        )
        else {
            return HttpForwardDiagnosticSnapshot {
                diagnostic_records_dropped: records_dropped(),
                diagnostic_reads_refused: reads_refused(),
                unavailable: true,
                ..HttpForwardDiagnosticSnapshot::default()
            };
        };
        HttpForwardDiagnosticSnapshot {
            live_peer_hops: shared.live_hops(),
            owner_streams,
            exchanges,
            rotations,
            forgotten,
            owner_streams_recorded,
            exchanges_recorded,
            rotations_recorded,
            forgotten_recorded,
            ingress_rejected_before_admission: read(&shared.ingress_rejected_before_admission),
            principal_sessions_end_sent: read(&shared.principal_sessions_end_sent),
            principal_sessions_end_failed: read(&shared.principal_sessions_end_failed),
            principal_sessions_end_unsupported: read(&shared.principal_sessions_end_unsupported),
            hop_aggregate_send_high_water: high_water(&shared.hop_aggregate_send_high_water),
            hop_aggregate_receive_high_water: high_water(&shared.hop_aggregate_receive_high_water),
            hop_aggregate_limit: crate::http::forward::HOP_AGGREGATE_BYTES,
            label_overflow: LABELS.overflowed(),
            diagnostic_records_dropped: records_dropped(),
            diagnostic_reads_refused: reads_refused(),
            unavailable: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;

    use super::*;

    /// Move the send level to `level`.  Valid where the caller is the only
    /// mover of the send level, as every use here is.
    fn set_send(pair: &HopLivePair, level: usize) {
        let current = pair.live().send_bytes;
        if level >= current {
            pair.add_send(level - current);
        } else {
            pair.sub_send(current - level);
        }
    }

    /// Move the receive level to `level`; see [`set_send`].
    fn set_receive(pair: &HopLivePair, level: usize) {
        let current = pair.live().receive_bytes;
        if level >= current {
            pair.add_receive(level - current);
        } else {
            pair.sub_receive(current - level);
        }
    }

    #[test]
    fn records_are_bounded_and_counted() {
        let diagnostics = HttpForwardDiagnostics::default();
        for index in 0..(MAX_HTTP_FORWARD_RECORDS + 3) {
            diagnostics.record_exchange(HttpExchangeRecord {
                role: "ingress_local",
                stream_id: Some(index as u64),
                ..HttpExchangeRecord::default()
            });
            diagnostics.record_owner_stream(HttpOwnerStreamRecord {
                stream_id: index as u64,
                ..HttpOwnerStreamRecord::default()
            });
        }
        let snapshot = diagnostics.snapshot();
        assert_eq!(snapshot.exchanges.len(), MAX_HTTP_FORWARD_RECORDS);
        assert_eq!(snapshot.owner_streams.len(), MAX_HTTP_FORWARD_RECORDS);
        assert_eq!(
            snapshot.exchanges_recorded,
            (MAX_HTTP_FORWARD_RECORDS + 3) as u64
        );
        assert_eq!(snapshot.exchanges[0].stream_id, Some(3));
    }

    /// The property the two independent `max` latches do not have: two
    /// disjoint bursts must not produce a pair, because at no instant were
    /// both directions loaded (task row M8-C22).
    #[test]
    fn disjoint_bursts_latch_no_coincident_pair() {
        let pair = HopLivePair::default();
        // Burst one: the send direction fills and drains, receive idle.
        set_send(&pair, 190_000);
        set_send(&pair, 0);
        // Burst two: the receive direction fills and drains, send idle.
        set_receive(&pair, 190_000);
        set_receive(&pair, 0);
        assert_eq!(pair.coincident(), HopBytePair::default());
        assert_eq!(pair.coincident().smaller(), 0);
    }

    /// The pair is the instant the *smaller* half is largest, not the two
    /// directions' separate maxima joined afterwards.
    #[test]
    fn coincident_pair_keeps_the_best_attested_instant() {
        let pair = HopLivePair::default();
        // An instant with a large send and a tiny receive.
        set_send(&pair, 190_000);
        set_receive(&pair, 10);
        assert_eq!(
            pair.coincident(),
            HopBytePair {
                send_bytes: 190_000,
                receive_bytes: 10,
            }
        );
        // A better-attested instant: both halves substantial.  The smaller
        // half rises from 10 to 40_000, so this one replaces it.
        set_receive(&pair, 40_000);
        assert_eq!(
            pair.coincident(),
            HopBytePair {
                send_bytes: 190_000,
                receive_bytes: 40_000,
            }
        );
        // The send direction drains.  A fall never latches, and the live
        // reading follows it down while the latch stands.
        set_send(&pair, 0);
        assert_eq!(
            pair.live(),
            HopBytePair {
                send_bytes: 0,
                receive_bytes: 40_000,
            }
        );
        assert_eq!(pair.coincident().smaller(), 40_000);
        // A larger single direction with a smaller partner does not displace
        // it: 190_000/40_000 is better attested than 200_000/20.
        set_send(&pair, 200_000);
        set_receive(&pair, 20);
        assert_eq!(pair.coincident().smaller(), 40_000);
    }

    /// A live hop is published while it exists and disappears with it, so a
    /// window shorter than the exchange can see the hop and a finished one
    /// leaves no stale entry.
    #[test]
    fn live_hops_are_published_then_reaped() {
        let diagnostics = HttpForwardDiagnostics::default();
        let pair = Arc::new(HopLivePair::default());
        set_send(&pair, 120);
        set_receive(&pair, 340);
        diagnostics.register_live_hop(
            "owner_peer",
            Some("r-1".to_owned()),
            Some(7),
            196_608,
            &pair,
        );
        let snapshot = diagnostics.snapshot();
        assert_eq!(snapshot.live_peer_hops.len(), 1);
        let hop = &snapshot.live_peer_hops[0];
        assert_eq!(hop.role, "owner_peer");
        assert_eq!(hop.stream_id, Some(7));
        assert_eq!(hop.window, 196_608);
        assert_eq!(hop.live.send_bytes, 120);
        assert_eq!(hop.live.receive_bytes, 340);
        assert_eq!(hop.coincident.smaller(), 120);
        drop(pair);
        assert!(diagnostics.snapshot().live_peer_hops.is_empty());
    }

    fn position(seed: u32) -> HttpRecordPosition {
        HttpRecordPosition {
            heads: seed,
            bodies: u64::from(seed) + 1,
            ends: seed + 2,
            body_bytes: u64::from(seed) + 3,
            total_bytes: u64::from(seed) + 4,
            position: "partial_body",
            partial_received: seed + 5,
            partial_total: seed + 6,
            invalid: seed % 2 == 1,
        }
    }

    /// Every field of every record kind survives the recorder unchanged.
    #[test]
    fn every_record_field_is_retained_exactly() {
        let diagnostics = HttpForwardDiagnostics::default();
        let owner = HttpOwnerStreamRecord {
            stream_id: 7,
            operation_id: "operation-with-a-long-identifier-0123456789".to_owned(),
            request_id: Some("r-1".to_owned()),
            receive_buffer_high_water: 11,
            receive_window: 12,
            parked_bytes_high_water: 13,
            replay_bytes_high_water: 14,
            sent_bytes: 15,
            delivered_bytes: 16,
            release: "reset",
            reset_reason: Some(u16::MAX),
            request: position(20),
            response: position(31),
            reset_sequence: Some(u64::MAX),
            reset_generation: None,
            reset_deferred_by_freeze: true,
            cancel_sent: false,
        };
        let exchange = HttpExchangeRecord {
            role: "ingress_remote",
            request_id: None,
            stream_id: Some(0),
            request_handoff_high_water: 1,
            response_handoff_high_water: 2,
            response_body_high_water: 3,
            peer_send_in_flight_high_water: 4,
            peer_receive_queue_high_water: 5,
            peer_coincident: HopBytePair {
                send_bytes: 6,
                receive_bytes: usize::MAX,
            },
            peer_window: 196_608,
            request_outcome: "complete",
            response_outcome: "released",
            error_code: Some("HTTP_UPSTREAM_TIMEOUT"),
            execution: "unknown",
            progress_expired: None,
        };
        let rotation = HttpRotationObservation {
            stream_id: 9,
            operation_id: String::new(),
            request_id: Some(String::new()),
            rotation: 3,
            rotation_id: "rotation-3".to_owned(),
            old_generation: 4,
            new_generation: 5,
            request: position(40),
            request_fin_sequenced: true,
            response: position(51),
            response_fin_received: false,
            parked_bytes: 60,
            receive_buffered_bytes: 61,
            deferred_terminal: Some("fin"),
            frozen_last_emitted: 62,
            relay_fence: Some(63),
            connector_fence: None,
            relay_acknowledged: Some(0),
            connector_acknowledged: Some(64),
        };
        let forget = HttpForgetRecord {
            stream_id: 70,
            operation_id: "op".to_owned(),
            request_id: None,
        };
        diagnostics.record_owner_stream(owner.clone());
        diagnostics.record_exchange(exchange.clone());
        diagnostics.record_exchange(HttpExchangeRecord::default());
        diagnostics.record_rotation(rotation.clone());
        diagnostics.record_forget(forget.clone());
        diagnostics.record_principal_sessions_end(true);
        diagnostics.record_principal_sessions_end(false);
        diagnostics.record_principal_sessions_end(false);
        diagnostics.record_principal_sessions_end_unsupported();
        diagnostics.record_ingress_rejection();
        diagnostics.note_hop_aggregate(9, 2);
        diagnostics.note_hop_aggregate(3, 8);
        let snapshot = diagnostics.snapshot();
        assert_eq!(snapshot.owner_streams, vec![owner]);
        assert_eq!(
            snapshot.exchanges,
            vec![exchange, HttpExchangeRecord::default()]
        );
        assert_eq!(snapshot.rotations, vec![rotation]);
        assert_eq!(snapshot.forgotten, vec![forget]);
        assert_eq!(snapshot.owner_streams_recorded, 1);
        assert_eq!(snapshot.exchanges_recorded, 2);
        assert_eq!(snapshot.rotations_recorded, 1);
        assert_eq!(snapshot.forgotten_recorded, 1);
        assert_eq!(snapshot.principal_sessions_end_sent, 1);
        assert_eq!(snapshot.principal_sessions_end_failed, 2);
        assert_eq!(snapshot.principal_sessions_end_unsupported, 1);
        assert_eq!(snapshot.ingress_rejected_before_admission, 1);
        assert_eq!(snapshot.hop_aggregate_send_high_water, 9);
        assert_eq!(snapshot.hop_aggregate_receive_high_water, 8);
    }

    /// A published hop's later readings reach the snapshot, hops are listed
    /// in registration order, and a finished hop's cell is reused.
    #[test]
    fn live_hops_follow_their_pairs_and_reuse_cells() {
        let diagnostics = HttpForwardDiagnostics::default();
        let first = Arc::new(HopLivePair::default());
        let second = Arc::new(HopLivePair::default());
        diagnostics.register_live_hop("owner_peer", None, Some(1), 10, &first);
        diagnostics.register_live_hop("ingress_remote", Some("r-2".to_owned()), None, 20, &second);
        // Registering a published hop again changes nothing.
        diagnostics.register_live_hop("owner_peer", None, Some(99), 10, &first);
        set_send(&first, 500);
        set_receive(&first, 70);
        set_receive(&second, 9);
        let snapshot = diagnostics.snapshot();
        assert_eq!(snapshot.live_peer_hops.len(), 2);
        let hop = &snapshot.live_peer_hops[0];
        assert_eq!(
            (hop.role, hop.stream_id, hop.window),
            ("owner_peer", Some(1), 10)
        );
        assert_eq!(hop.live, first.live());
        assert_eq!(hop.coincident, first.coincident());
        assert_eq!(hop.coincident.smaller(), 70);
        let hop = &snapshot.live_peer_hops[1];
        assert_eq!(hop.role, "ingress_remote");
        assert_eq!(hop.request_id.as_deref(), Some("r-2"));
        assert_eq!(hop.live.receive_bytes, 9);
        assert_eq!(hop.coincident, HopBytePair::default());

        drop(first);
        let third = Arc::new(HopLivePair::default());
        diagnostics.register_live_hop("owner_peer", None, Some(3), 30, &third);
        let snapshot = diagnostics.snapshot();
        let streams: Vec<Option<u64>> = snapshot
            .live_peer_hops
            .iter()
            .map(|hop| hop.stream_id)
            .collect();
        assert_eq!(streams, [None, Some(3)]);
        // The reused cell carries nothing of the hop that held it before.
        assert_eq!(snapshot.live_peer_hops[1].live, HopBytePair::default());
        assert_eq!(
            snapshot.live_peer_hops[1].coincident,
            HopBytePair::default()
        );
        drop((second, third));
        assert!(diagnostics.snapshot().live_peer_hops.is_empty());
    }

    /// Both directions noted from two threads: the coincident pair is always
    /// one that was latched as a pair, and the published copy settles on the
    /// hop's own readings.
    #[test]
    fn concurrent_notes_latch_whole_pairs_and_settle_the_published_copy() {
        let diagnostics = HttpForwardDiagnostics::default();
        let pair = Arc::new(HopLivePair::default());
        diagnostics.register_live_hop("owner_peer", None, Some(1), 10, &pair);
        let sender = {
            let pair = Arc::clone(&pair);
            std::thread::spawn(move || {
                for level in 1..=50_000_usize {
                    set_send(&pair, level * 2);
                }
            })
        };
        let receiver = {
            let pair = Arc::clone(&pair);
            std::thread::spawn(move || {
                for level in 1..=50_000_usize {
                    set_receive(&pair, level * 2 + 1);
                }
            })
        };
        while !(sender.is_finished() && receiver.is_finished()) {
            let held = pair.coincident();
            // Sends are even and receives odd, or the pair is still empty.
            assert!(held == HopBytePair::default() || held.send_bytes % 2 == 0);
            assert!(held == HopBytePair::default() || held.receive_bytes % 2 == 1);
        }
        sender.join().expect("sender finishes");
        receiver.join().expect("receiver finishes");
        let snapshot = diagnostics.snapshot();
        assert_eq!(snapshot.live_peer_hops.len(), 1);
        assert_eq!(snapshot.live_peer_hops[0].live, pair.live());
        assert_eq!(snapshot.live_peer_hops[0].coincident, pair.coincident());
        assert_eq!(
            pair.live(),
            HopBytePair {
                send_bytes: 100_000,
                receive_bytes: 100_001,
            }
        );
        assert_eq!(pair.coincident().smaller(), 100_000);
    }

    /// Exchange recorders on several threads are parked between the steps
    /// of their records while a reader snapshots continuously.  In every
    /// snapshot a count of `n` comes with the `n`-th record: the ring holds
    /// exactly the last `min(n, 64)` records by position.
    #[test]
    fn parked_recorders_never_show_a_count_ahead_of_its_record() {
        const WRITERS: u64 = 4;
        const PER_WRITER: u64 = 1_500;
        let diagnostics = HttpForwardDiagnostics::default();
        let steps = Arc::new(AtomicU64::new(0));
        {
            let steps = Arc::clone(&steps);
            diagnostics.park_exchange_recorders(Box::new(move |_step| {
                if steps.fetch_add(1, Ordering::SeqCst).is_multiple_of(61) {
                    std::thread::sleep(std::time::Duration::from_micros(300));
                } else {
                    std::thread::yield_now();
                }
            }));
        }
        let writers: Vec<_> = (0..WRITERS)
            .map(|writer| {
                let diagnostics = diagnostics.clone();
                std::thread::spawn(move || {
                    for round in 0..PER_WRITER {
                        diagnostics.record_exchange(HttpExchangeRecord {
                            role: "ingress_remote",
                            request_id: Some(format!("r-{writer}-{round}")),
                            stream_id: Some(writer * PER_WRITER + round),
                            ..HttpExchangeRecord::default()
                        });
                    }
                })
            })
            .collect();
        let verify = |snapshot: &HttpForwardDiagnosticSnapshot| {
            let recorded = snapshot.exchanges_recorded;
            assert_eq!(
                snapshot.exchanges.len() as u64,
                recorded.min(MAX_HTTP_FORWARD_RECORDS as u64)
            );
            for record in &snapshot.exchanges {
                let stream = record.stream_id.expect("stream id retained");
                assert_eq!(
                    record.request_id,
                    Some(format!("r-{}-{}", stream / PER_WRITER, stream % PER_WRITER))
                );
            }
            recorded
        };
        let mut last = 0;
        while writers.iter().any(|writer| !writer.is_finished()) {
            let recorded = verify(&diagnostics.snapshot());
            assert!(recorded >= last);
            last = recorded;
        }
        for writer in writers {
            writer.join().expect("recorder finishes");
        }
        assert_eq!(verify(&diagnostics.snapshot()), WRITERS * PER_WRITER);
        assert_eq!(diagnostics.snapshot().label_overflow, 0);
    }

    /// Each level moved by two tasks at once, as a hop's are (a charge and a
    /// credit; a push and a pop), on a multi-thread runtime, with the hop
    /// published while they run.  Every mover contributes its own
    /// difference, so the final levels are exact, the published copy equals
    /// them, and neither a live reading nor the coincident latch ever
    /// exceeds the most that can be outstanding at once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn interleaved_movers_keep_exact_levels_and_a_bounded_latch() {
        const ROUNDS: usize = 20_000;
        const WINDOW: usize = 8;
        const SEND: usize = 700;
        const RECEIVE: usize = 300;
        // Each round leaves a residue, so the exact final level is not zero.
        const SEND_KEPT: usize = 1;
        const RECEIVE_KEPT: usize = 2;
        // Outstanding at once: a full channel, the one being offered and
        // the one taken but not yet lowered; plus every residue so far.
        let send_bound = (WINDOW + 2) * SEND + ROUNDS * SEND_KEPT;
        let receive_bound = (WINDOW + 2) * RECEIVE + ROUNDS * RECEIVE_KEPT;

        let diagnostics = HttpForwardDiagnostics::default();
        let pair = Arc::new(HopLivePair::default());
        let mut movers = Vec::new();
        for (raise, lower, bytes, kept) in [
            (
                HopLivePair::add_send as fn(&HopLivePair, usize),
                HopLivePair::sub_send as fn(&HopLivePair, usize),
                SEND,
                SEND_KEPT,
            ),
            (
                HopLivePair::add_receive,
                HopLivePair::sub_receive,
                RECEIVE,
                RECEIVE_KEPT,
            ),
        ] {
            let (raised, mut to_lower) = tokio::sync::mpsc::channel::<usize>(WINDOW);
            let raiser = Arc::clone(&pair);
            movers.push(tokio::spawn(async move {
                for _ in 0..ROUNDS {
                    raise(&raiser, bytes);
                    raised.send(bytes - kept).await.expect("lowering task");
                }
            }));
            let lowerer = Arc::clone(&pair);
            movers.push(tokio::spawn(async move {
                while let Some(bytes) = to_lower.recv().await {
                    lower(&lowerer, bytes);
                }
            }));
        }
        let moving = Arc::new(AtomicBool::new(true));
        let observer = {
            let pair = Arc::clone(&pair);
            let diagnostics = diagnostics.clone();
            let moving = Arc::clone(&moving);
            tokio::spawn(async move {
                let mut samples = 0_u64;
                let mut registered = false;
                while moving.load(Ordering::SeqCst) {
                    let live = pair.live();
                    assert!(live.send_bytes <= send_bound, "{live:?}");
                    assert!(live.receive_bytes <= receive_bound, "{live:?}");
                    let held = pair.coincident();
                    assert!(held.send_bytes <= send_bound, "{held:?}");
                    assert!(held.receive_bytes <= receive_bound, "{held:?}");
                    samples += 1;
                    if !registered && live.send_bytes > 0 && live.receive_bytes > 0 {
                        // Published mid-flight, under both movers of both
                        // levels.
                        diagnostics.register_live_hop("owner_peer", None, Some(1), 10, &pair);
                        registered = true;
                    }
                    tokio::task::yield_now().await;
                }
                (samples, registered)
            })
        };
        for mover in movers {
            mover.await.expect("mover finishes");
        }
        moving.store(false, Ordering::SeqCst);
        let (samples, registered) = observer.await.expect("observer finishes");
        assert!(samples > 0);
        if !registered {
            diagnostics.register_live_hop("owner_peer", None, Some(1), 10, &pair);
        }

        assert_eq!(
            pair.live(),
            HopBytePair {
                send_bytes: ROUNDS * SEND_KEPT,
                receive_bytes: ROUNDS * RECEIVE_KEPT,
            }
        );
        let held = pair.coincident();
        assert!(held.smaller() > 0, "both levels were loaded together");
        assert!(held.send_bytes <= send_bound, "{held:?}");
        assert!(held.receive_bytes <= receive_bound, "{held:?}");
        let snapshot = diagnostics.snapshot();
        assert_eq!(snapshot.live_peer_hops.len(), 1);
        assert_eq!(snapshot.live_peer_hops[0].live, pair.live());
        assert_eq!(snapshot.live_peer_hops[0].coincident, held);
    }
}
