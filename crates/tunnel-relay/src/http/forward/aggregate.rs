//! The per-peer aggregate bound on `http-forward/1` peer-hop bytes (review
//! finding D of implementation gate 3).
//!
//! Each hop stream has its own credited window of
//! [`PEER_HOP_WINDOW_BYTES`](super::PEER_HOP_WINDOW_BYTES).  docs/cluster.md
//! also bounds one peer connection to 8 MiB across all its streams and both
//! directions, so N saturated HTTP streams to one peer must not each receive
//! an independent window.  One [`HopAggregate`] per remote peer (keyed by
//! its node identity) therefore holds two counters shared by every HTTP hop
//! stream this relay runs with that peer:
//!
//! * **send**: encoded bytes this relay has sent and the peer has not yet
//!   reported consumed.  A writer waits (never fails) when its next chunk
//!   would take the aggregate above [`HOP_AGGREGATE_BYTES`];
//! * **receive**: encoded bytes received from that peer and still queued
//!   here.  A compliant peer can never exceed the bound, because its own
//!   send aggregate for this relay bounds it; a violation closes the stream.
//!
//! With half the connection ceiling per direction, both directions together
//! stay within 8 MiB.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use tokio::sync::{Notify, mpsc, oneshot};
use tunnel_cluster::peer_frame::CONNECTION_BYTE_BUDGET;

/// The aggregate bound per direction per peer, in encoded hop bytes.
pub const HOP_AGGREGATE_BYTES: usize = CONNECTION_BYTE_BUDGET / 2;

/// The shared counters for one remote peer.
///
/// The two directions are independent of each other, and each direction's
/// level is one atomic whose every change is a single compare-and-swap, so
/// the bound decision and the charge it permits are one step.  Each
/// high-water mark is a monotonic maximum of the levels its direction's
/// charges produced.
#[derive(Debug)]
pub(crate) struct HopAggregate {
    sent_in_flight: AtomicU64,
    received_queued: AtomicU64,
    send_high_water: AtomicU64,
    receive_high_water: AtomicU64,
    changed: Notify,
    limit: u64,
}

impl HopAggregate {
    pub(crate) fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            sent_in_flight: AtomicU64::new(0),
            received_queued: AtomicU64::new(0),
            send_high_water: AtomicU64::new(0),
            receive_high_water: AtomicU64::new(0),
            changed: Notify::new(),
            limit: limit as u64,
        })
    }

    /// Wait until `cost` more in-flight bytes fit, then charge them.
    /// Resolves `false` if `stopped` resolves first; nothing is charged then.
    pub(crate) async fn acquire_send(
        &self,
        cost: u64,
        stopped: impl std::future::Future<Output = ()>,
    ) -> bool {
        tokio::pin!(stopped);
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            // A single chunk larger than the whole bound still proceeds once
            // nothing else is in flight, so no stream can wedge.
            let charged = self.sent_in_flight.fetch_update(
                Ordering::AcqRel,
                Ordering::Acquire,
                |in_flight| {
                    (in_flight == 0 || in_flight.saturating_add(cost) <= self.limit)
                        .then(|| in_flight.saturating_add(cost))
                },
            );
            if let Ok(before) = charged {
                self.send_high_water
                    .fetch_max(before.saturating_add(cost), Ordering::AcqRel);
                return true;
            }
            tokio::select! {
                () = &mut stopped => return false,
                () = notified => {}
            }
        }
    }

    /// The peer consumed (or the stream released) `bytes` in-flight bytes.
    pub(crate) fn release_send(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        saturating_release(&self.sent_in_flight, bytes);
        self.changed.notify_waiters();
    }

    /// Charge received bytes.  Returns `false` (charging nothing) when the
    /// peer exceeded the aggregate it must respect.
    pub(crate) fn charge_receive(&self, bytes: u64) -> bool {
        let charged =
            self.received_queued
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |queued| {
                    queued.checked_add(bytes).filter(|next| *next <= self.limit)
                });
        match charged {
            Ok(before) => {
                self.receive_high_water
                    .fetch_max(before.saturating_add(bytes), Ordering::AcqRel);
                true
            }
            Err(_) => false,
        }
    }

    pub(crate) fn release_receive(&self, bytes: u64) {
        saturating_release(&self.received_queued, bytes);
    }

    /// `(send high water, receive high water)` in encoded bytes.
    pub(crate) fn high_water(&self) -> (usize, usize) {
        (
            usize::try_from(self.send_high_water.load(Ordering::Acquire)).unwrap_or(usize::MAX),
            usize::try_from(self.receive_high_water.load(Ordering::Acquire)).unwrap_or(usize::MAX),
        )
    }

    #[cfg(test)]
    pub(crate) fn current(&self) -> (u64, u64) {
        (
            self.sent_in_flight.load(Ordering::Acquire),
            self.received_queued.load(Ordering::Acquire),
        )
    }
}

fn saturating_release(level: &AtomicU64, bytes: u64) {
    // The closure always returns `Some`, so the update cannot fail.
    let _ = level.fetch_update(Ordering::AcqRel, Ordering::Acquire, |held| {
        Some(held.saturating_sub(bytes))
    });
}

/// Lookups queued for the registry task.  A lookup never blocks the task, so
/// the queue only absorbs a burst of streams opening at once; a caller that
/// finds it full waits for a slot rather than being refused.
const HOP_AGGREGATE_LOOKUP_QUEUE: usize = 32;

struct HopAggregateLookup {
    peer_node: String,
    reply: oneshot::Sender<Arc<HopAggregate>>,
}

/// The aggregates of one relay, keyed by remote peer node identity.
///
/// The map is owned by one registry task, started by the first lookup on the
/// runtime that performs it; every clone of this handle reaches the same
/// task, which ends when the last clone is dropped.
#[derive(Clone, Debug, Default)]
pub(crate) struct HopAggregates {
    lookups: Arc<OnceLock<mpsc::Sender<HopAggregateLookup>>>,
    /// Set by the first lookup that found the registry task gone, so that
    /// is logged once per relay.
    registry_gone_logged: Arc<AtomicBool>,
}

impl std::fmt::Debug for HopAggregateLookup {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("HopAggregateLookup").finish()
    }
}

impl HopAggregates {
    /// The shared aggregate for `peer_node`.  Idle entries are evicted
    /// before the bounded map grows past the peer destination bound.
    ///
    /// `None` if the registry task is gone (its runtime is shutting down):
    /// the shared bound for the peer cannot be reached, and a stream given a
    /// counter of its own would escape it, so the caller must refuse the hop.
    pub(crate) async fn for_peer(&self, peer_node: &str) -> Option<Arc<HopAggregate>> {
        let lookups = self.lookups.get_or_init(|| {
            let (lookups, queued) = mpsc::channel(HOP_AGGREGATE_LOOKUP_QUEUE);
            tokio::spawn(run_registry(queued));
            lookups
        });
        let (reply, answer) = oneshot::channel();
        let lookup = HopAggregateLookup {
            peer_node: peer_node.to_owned(),
            reply,
        };
        if lookups.send(lookup).await.is_ok()
            && let Ok(aggregate) = answer.await
        {
            return Some(aggregate);
        }
        if !self.registry_gone_logged.swap(true, Ordering::AcqRel) {
            tracing::warn!(
                phase = "http_forward_peer_hop_aggregate_registry_gone",
                "peer hop aggregate registry is not running; refusing peer hops"
            );
        }
        None
    }
}

async fn run_registry(mut lookups: mpsc::Receiver<HopAggregateLookup>) {
    let mut map: HashMap<String, Arc<HopAggregate>> = HashMap::new();
    while let Some(HopAggregateLookup { peer_node, reply }) = lookups.recv().await {
        let aggregate = match map.get(&peer_node) {
            Some(aggregate) => Arc::clone(aggregate),
            None => {
                if map.len() >= tunnel_transport::DEFAULT_PEER_DESTINATIONS {
                    map.retain(|_, aggregate| Arc::strong_count(aggregate) > 1);
                }
                let aggregate = HopAggregate::new(HOP_AGGREGATE_BYTES);
                map.insert(peer_node, Arc::clone(&aggregate));
                aggregate
            }
        };
        // A caller that stopped waiting simply drops its share.
        let _ = reply.send(aggregate);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_sender_waits_for_the_shared_bound_and_resumes_on_release() {
        let aggregate = HopAggregate::new(100);
        assert!(aggregate.acquire_send(60, std::future::pending()).await);
        assert!(aggregate.acquire_send(40, std::future::pending()).await);
        let waiter = {
            let aggregate = Arc::clone(&aggregate);
            tokio::spawn(async move { aggregate.acquire_send(10, std::future::pending()).await })
        };
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        assert!(!waiter.is_finished(), "the bound is shared and full");
        aggregate.release_send(20);
        assert!(waiter.await.expect("join"));
        assert_eq!(aggregate.current().0, 90);
        // A stopped waiter charges nothing.
        assert!(!aggregate.acquire_send(50, async {}).await);
        assert_eq!(aggregate.current().0, 90);
        assert_eq!(aggregate.high_water().0, 100);
    }

    #[test]
    fn a_receiver_refuses_bytes_beyond_the_bound_without_charging() {
        let aggregate = HopAggregate::new(100);
        assert!(aggregate.charge_receive(100));
        assert!(!aggregate.charge_receive(1));
        aggregate.release_receive(30);
        assert!(aggregate.charge_receive(30));
        assert_eq!(aggregate.current().1, 100);
    }

    #[tokio::test]
    async fn aggregates_are_per_peer_and_shared_by_its_streams() {
        let aggregates = HopAggregates::default();
        let first = aggregates.for_peer("relay-a").await.expect("registry");
        let second = aggregates.for_peer("relay-a").await.expect("registry");
        assert!(Arc::ptr_eq(&first, &second));
        let other = aggregates.for_peer("relay-b").await.expect("registry");
        assert!(!Arc::ptr_eq(&first, &other));
        // Every clone of the handle reaches the same registry.
        let clone = aggregates.clone();
        let cloned = clone.for_peer("relay-a").await.expect("registry");
        assert!(Arc::ptr_eq(&first, &cloned));
    }

    #[tokio::test]
    async fn idle_aggregates_are_evicted_at_the_peer_destination_bound() {
        let aggregates = HopAggregates::default();
        let held = aggregates.for_peer("held").await.expect("registry");
        for index in 0..tunnel_transport::DEFAULT_PEER_DESTINATIONS {
            let idle = aggregates.for_peer(&format!("idle-{index}")).await;
            drop(idle.expect("registry"));
        }
        // The held entry survived the eviction; an idle one was rebuilt.
        let again = aggregates.for_peer("held").await.expect("registry");
        assert!(Arc::ptr_eq(&held, &again));
    }

    /// Without its registry task a relay cannot find the peer's shared
    /// counters.  A lookup then refuses rather than hand the stream counters
    /// of its own, which would lift the per-peer aggregate bound.
    #[test]
    fn a_lookup_without_the_registry_task_is_refused() {
        let runtime = || {
            tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("runtime")
        };
        let aggregates = HopAggregates::default();
        let first = runtime();
        assert!(first.block_on(aggregates.for_peer("relay-a")).is_some());
        // Dropping the runtime drops the registry task it was started on.
        drop(first);
        let second = runtime();
        assert!(second.block_on(aggregates.for_peer("relay-a")).is_none());
        assert!(second.block_on(aggregates.for_peer("relay-b")).is_none());
        assert!(aggregates.registry_gone_logged.load(Ordering::Acquire));
    }
}
