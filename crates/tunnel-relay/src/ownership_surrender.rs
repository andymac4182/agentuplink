//! A relay whose membership no longer entitles it to serve surrenders the
//! device ownership it holds (task rows M7-C181, M7-C182, M7-C184).
//!
//! Before M7-C181, a relay whose own membership went unready refused new work
//! but kept every device session it owned and kept renewing their owner
//! leases for as long as its Redis connection lived, so a successor could not
//! claim those devices until the process stopped.
//!
//! The watcher here polls [`MembershipRuntime::ownership_surrender_cause`],
//! which names a cause only when one of these holds:
//!
//! - **M7-C181:** the relay's own verified record no longer approves the key
//!   it serves, confirmed by [`OWN_KEY_SURRENDER_CONFIRMATIONS`] passes;
//! - **M7-C182 (a):** a fresh signed checkpoint does not name this node,
//!   confirmed by the same number of passes;
//! - **M7-C182 (b):** the checkpoint names this node but its record stays
//!   below the checkpoint's minimum version for one record lifetime plus
//!   skew (the publish race has had time to settle);
//! - **M7-C184:** membership stays unready for any reason except an
//!   unreachable catalog for longer than the longest owner lease plus that
//!   margin.
//!
//! While a cause holds, every poll asks the relay actor to close each owned
//! session with the cause's typed reason and release its lease through the
//! fenced compare-and-release path. The actor evaluates the condition again
//! itself, immediately before it collects the sessions, so a re-sign that
//! lands while the request is queued closes nothing. Repeating the request on
//! every poll closes a registration that was already in flight when the first
//! surrender ran; new registrations are refused because the relay is
//! unready. When membership returns to `Ready`, every count resets and
//! devices may attach again.
//!
//! An unreachable catalog, a single failed pass, and clock-offset health
//! (which is not membership state at all) never name a cause; they only
//! withdraw readiness (M7-C86, M7-C90, M7-C91).
//!
//! [`OWN_KEY_SURRENDER_CONFIRMATIONS`]: crate::membership_runtime::OWN_KEY_SURRENDER_CONFIRMATIONS

use std::{sync::Arc, time::Duration};

use tokio_util::sync::CancellationToken;

use crate::{
    RelayError,
    actor::RelayHandle,
    membership_runtime::{MembershipRuntime, OwnershipSurrenderCause},
};

/// How often the watcher reads the retained surrender condition. It reads
/// only in-process state, never Redis. With the 1..=5 s reconcile interval
/// and two confirming passes, an own-key or node-removed surrender starts no
/// later than about one reconcile interval plus this poll after the first
/// pass that observed the condition.
pub const OWNERSHIP_SURRENDER_POLL: Duration = Duration::from_secs(1);

/// Surrender once if a surrender cause holds now, re-checked inside the
/// actor. Returns the cause and the number of sessions closed, or `None`
/// when no cause holds (either here or at the actor's re-check).
pub async fn surrender_if_required(
    membership: &Arc<MembershipRuntime>,
    relay: &RelayHandle,
) -> Result<Option<(OwnershipSurrenderCause, usize)>, RelayError> {
    // A cheap pre-check keeps an entitled relay from queuing a command every
    // poll; the authoritative check is the one the actor runs.
    if membership.ownership_surrender_cause().is_none() {
        return Ok(None);
    }
    let recheck = Arc::clone(membership);
    relay
        .surrender_ownership(Box::new(move || recheck.ownership_surrender_cause()))
        .await
}

/// Poll the surrender condition until `shutdown` is cancelled or the relay
/// actor has stopped.
pub async fn ownership_surrender_loop(
    membership: Arc<MembershipRuntime>,
    relay: RelayHandle,
    poll: Duration,
    shutdown: CancellationToken,
) {
    let mut ticker = tokio::time::interval(poll);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            _ = ticker.tick() => {
                match surrender_if_required(&membership, &relay).await {
                    Ok(_) => {}
                    Err(RelayError::Shutdown) => break,
                    Err(error) => {
                        tracing::warn!(?error, "ownership surrender failed");
                    }
                }
            }
        }
    }
}
