//! A relay whose own served peer key is retired surrenders the device
//! ownership it holds (task row M7-C181).
//!
//! Before this, a relay whose own key its signed membership record stopped
//! approving went unready (`Unready(MissingLocalKey)`) and refused new work,
//! but kept every device session it owned and kept renewing their owner
//! leases for as long as its Redis connection lived, so a successor could not
//! claim those devices until the process stopped.
//!
//! The watcher here polls [`MembershipRuntime::own_key_surrender_required`],
//! which is true only after [`OWN_KEY_SURRENDER_CONFIRMATIONS`] consecutive
//! reconcile passes concluded `MissingLocalKey`. While it holds, every poll
//! asks the relay actor to close each owned session with the typed
//! `LOCAL_IDENTITY_RETIRED` reason and release its lease through the fenced
//! compare-and-release path. Repeating the request on every poll closes a
//! registration that was already in flight when the first surrender ran;
//! new registrations are refused because the relay is unready. When a
//! re-signed record approves the served key again, the count resets, the
//! relay becomes ready, and devices may attach to it again.
//!
//! Transient causes -- a checkpoint fetch or catalog read failure, a rejected
//! or expired record, clock-offset health -- never satisfy the condition and
//! only withdraw readiness (M7-C86, M7-C90, M7-C91).
//!
//! [`OWN_KEY_SURRENDER_CONFIRMATIONS`]: crate::membership_runtime::OWN_KEY_SURRENDER_CONFIRMATIONS

use std::{sync::Arc, time::Duration};

use tokio_util::sync::CancellationToken;

use crate::{RelayError, actor::RelayHandle, membership_runtime::MembershipRuntime};

/// How often the watcher reads the retained surrender condition. It reads
/// only in-process state, never Redis. With the 1..=5 s reconcile interval
/// and two confirming passes, a surrender starts at most one reconcile
/// interval plus this poll after the first pass that saw the key missing.
pub const OWN_KEY_SURRENDER_POLL: Duration = Duration::from_secs(1);

/// Surrender once if the confirmed own-key condition holds now. Returns the
/// number of sessions closed, or `None` when the condition does not hold.
pub async fn surrender_if_own_key_retired(
    membership: &MembershipRuntime,
    relay: &RelayHandle,
) -> Result<Option<usize>, RelayError> {
    if !membership.own_key_surrender_required() {
        return Ok(None);
    }
    relay.surrender_ownership().await.map(Some)
}

/// Poll the surrender condition until `shutdown` is cancelled or the relay
/// actor has stopped.
pub async fn own_key_surrender_loop(
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
                match surrender_if_own_key_retired(&membership, &relay).await {
                    Ok(_) => {}
                    Err(RelayError::Shutdown) => break,
                    Err(error) => {
                        tracing::warn!(?error, "own-key ownership surrender failed");
                    }
                }
            }
        }
    }
}
