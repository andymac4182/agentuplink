//! Observe exchange completion and transport retirement in one actor snapshot.
//! A completed filesystem handler can precede STREAM_FORGET and its barriers.

use serde::Serialize;
use tokio::{sync::watch, time::Instant};
use tunnel_client::ConnectionStatus;

use super::{Result, fail};

/// Closed predicates and counts only, including every final session predicate.
#[derive(Clone, Debug, Serialize)]
pub(super) struct DeviceTerminal {
    pub exchanges: u64,
    pub mutations_dispatched: u64,
    pub bytes_written: u64,
    pub active: bool,
    pub session_matches: bool,
    pub epoch_matches: bool,
    pub streams: usize,
    pub replay_frames: usize,
    pub rotations_completed: u64,
    pub recovery_attempt: Option<u64>,
    pub recovery_successor_generation: Option<u64>,
}

impl DeviceTerminal {
    pub fn from_status(status: &ConnectionStatus, session_id: &str, epoch: u64) -> Self {
        Self {
            exchanges: status.fs.exchanges,
            mutations_dispatched: status.fs.mutations_dispatched,
            bytes_written: status.fs.bytes_written,
            active: status.phase == "active",
            session_matches: status.session_id.as_deref() == Some(session_id),
            epoch_matches: status.epoch == Some(epoch),
            streams: status.streams,
            replay_frames: status.replay_frames,
            rotations_completed: status.rotations_completed,
            recovery_attempt: status.recovery_attempt,
            recovery_successor_generation: status.recovery_successor_generation,
        }
    }

    fn contradiction(&self) -> Option<&'static str> {
        if self.exchanges > 3 {
            Some("extra_exchange")
        } else if self.mutations_dispatched != 0 {
            Some("mutation_dispatched")
        } else if self.bytes_written != 0 {
            Some("bytes_written")
        } else if !self.active {
            Some("inactive_session")
        } else if !self.session_matches {
            Some("session_changed")
        } else if !self.epoch_matches {
            Some("epoch_changed")
        } else if self.rotations_completed != 0 {
            Some("rotation_observed")
        } else if self.recovery_attempt.is_some() {
            Some("recovery_attempt_observed")
        } else if self.recovery_successor_generation.is_some() {
            Some("recovery_successor_observed")
        } else {
            None
        }
    }

    pub fn quiescent(&self) -> bool {
        self.contradiction().is_none()
            && self.exchanges == 3
            && self.streams == 0
            && self.replay_frames == 0
    }

    fn refusal(&self, reason: &str) -> super::HarnessError {
        fail(&format!(
            "device terminal observation refused reason={reason} terminal={self:?}"
        ))
    }
}

/// The existing ledger wait bounds both completion and retirement. No new
/// request, replay, session close, grace period or deadline reset is involved.
/// Invalid identity/accounting/lifecycle evidence is terminal immediately.
pub(super) async fn await_device_terminal(
    mut status: watch::Receiver<ConnectionStatus>,
    session_id: &str,
    epoch: u64,
    deadline: Instant,
) -> Result<DeviceTerminal> {
    let mut reported_retirement_wait = false;
    loop {
        let observed = DeviceTerminal::from_status(&status.borrow_and_update(), session_id, epoch);
        if let Some(reason) = observed.contradiction() {
            return Err(observed.refusal(reason));
        }
        if Instant::now() >= deadline {
            return Err(observed.refusal("deadline"));
        }
        if observed.quiescent() {
            return Ok(observed);
        }
        if observed.exchanges == 3 && !reported_retirement_wait {
            // At most one pending line per gate, followed by the final verdict.
            // This records a real observed gap without claiming the historical
            // hosted failure's discarded scalar can now be recovered.
            eprintln!("fs fid terminal retirement pending terminal={observed:?}");
            reported_retirement_wait = true;
        }
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(deadline) => {
                return Err(observed.refusal("deadline"));
            }
            changed = status.changed() => {
                if changed.is_err() {
                    return Err(observed.refusal("status_channel_closed"));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::production_cluster::fs_client_e2e::LEDGER_WAIT;
    use futures_util::{FutureExt, poll};
    use std::task::Poll;

    fn status(exchanges: u64, streams: usize, replay_frames: usize) -> ConnectionStatus {
        let mut status = ConnectionStatus {
            phase: "active".into(),
            session_id: Some("expected-session".into()),
            epoch: Some(7),
            streams,
            replay_frames,
            ..ConnectionStatus::default()
        };
        status.fs.exchanges = exchanges;
        status
    }

    #[tokio::test(start_paused = true)]
    async fn fs_fid_terminal_waits_for_retirement_after_completed_handler() {
        // These are observer-unit inputs. The live fixture still uses the real
        // connector watch; production Done and STREAM_FORGET are independent.
        let (send, receive) = watch::channel(status(3, 1, 1));
        let wait =
            await_device_terminal(receive, "expected-session", 7, Instant::now() + LEDGER_WAIT);
        tokio::pin!(wait);
        assert!(
            matches!(poll!(&mut wait), Poll::Pending),
            "handler completion alone must not end observation"
        );
        send.send(status(3, 1, 0)).expect("final ACK published");
        assert!(
            matches!(poll!(&mut wait), Poll::Pending),
            "zero replay alone does not retire the stream"
        );
        send.send(status(3, 0, 0))
            .expect("forget barrier completed");
        let terminal = wait
            .await
            .expect("same snapshot now proves every predicate");
        assert!(terminal.quiescent());
        assert_eq!(terminal.exchanges, 3);
        assert_eq!(terminal.streams, 0);
        assert_eq!(terminal.replay_frames, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn fs_fid_terminal_rejects_each_wrong_terminal_scalar_without_waiting() {
        for (reason, mutate) in [
            (
                "extra_exchange",
                (|s: &mut ConnectionStatus| s.fs.exchanges = 4) as fn(&mut ConnectionStatus),
            ),
            ("mutation_dispatched", |s: &mut ConnectionStatus| {
                s.fs.mutations_dispatched = 1
            }),
            ("bytes_written", |s: &mut ConnectionStatus| {
                s.fs.bytes_written = 1
            }),
            ("inactive_session", |s: &mut ConnectionStatus| {
                s.phase = "closed".into()
            }),
            ("session_changed", |s: &mut ConnectionStatus| {
                s.session_id = Some("other-session".into())
            }),
            ("epoch_changed", |s: &mut ConnectionStatus| {
                s.epoch = Some(8)
            }),
            ("rotation_observed", |s: &mut ConnectionStatus| {
                s.rotations_completed = 1
            }),
            ("recovery_attempt_observed", |s: &mut ConnectionStatus| {
                s.recovery_attempt = Some(1)
            }),
            ("recovery_successor_observed", |s: &mut ConnectionStatus| {
                s.recovery_successor_generation = Some(2)
            }),
        ] {
            let mut bad = status(3, 0, 0);
            mutate(&mut bad);
            let (_send, receive) = watch::channel(bad);
            let result =
                await_device_terminal(receive, "expected-session", 7, Instant::now() + LEDGER_WAIT)
                    .now_or_never()
                    .expect("contradictory evidence must reject immediately");
            let error = result.expect_err("wrong terminal evidence").to_string();
            assert!(error.contains(reason), "{error}");
            assert!(
                error.contains("terminal=DeviceTerminal"),
                "refusal must retain scalar snapshot: {error}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn fs_fid_terminal_cannot_wait_through_a_lifecycle_contradiction() {
        let (send, receive) = watch::channel(status(3, 1, 0));
        let wait =
            await_device_terminal(receive, "expected-session", 7, Instant::now() + LEDGER_WAIT);
        tokio::pin!(wait);
        assert!(matches!(poll!(&mut wait), Poll::Pending));
        let mut changed = status(3, 0, 0);
        changed.rotations_completed = 1;
        send.send(changed).expect("changed lifecycle published");
        let result = poll!(&mut wait);
        assert!(
            matches!(result, Poll::Ready(Err(_))),
            "a later quiet snapshot cannot erase an observed contradiction"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn fs_fid_terminal_bounds_missing_completion_stream_retirement_and_replay() {
        for pending in [status(2, 0, 0), status(3, 1, 0), status(3, 0, 1)] {
            let (send, receive) = watch::channel(pending.clone());
            let start = Instant::now();
            let wait = await_device_terminal(receive, "expected-session", 7, start + LEDGER_WAIT);
            tokio::pin!(wait);
            assert!(matches!(poll!(&mut wait), Poll::Pending));
            tokio::time::advance(LEDGER_WAIT / 2).await;
            send.send(pending.clone())
                .expect("update cannot renew deadline");
            assert!(matches!(poll!(&mut wait), Poll::Pending));
            tokio::time::advance(LEDGER_WAIT / 2).await;
            let error = wait
                .await
                .expect_err("unmet predicate remains a failure")
                .to_string();
            assert!(error.contains("reason=deadline"), "{error}");
            assert!(
                error.contains(&format!("exchanges: {}", pending.fs.exchanges)),
                "{error}"
            );
            assert!(
                error.contains(&format!("streams: {}", pending.streams)),
                "{error}"
            );
            assert!(
                error.contains(&format!("replay_frames: {}", pending.replay_frames)),
                "{error}"
            );
            assert_eq!(Instant::now() - start, LEDGER_WAIT);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn fs_fid_terminal_rejects_closed_observation_and_expired_budget() {
        let (send, receive) = watch::channel(status(3, 1, 0));
        drop(send);
        let error =
            await_device_terminal(receive, "expected-session", 7, Instant::now() + LEDGER_WAIT)
                .await
                .expect_err("missing retirement publication")
                .to_string();
        assert!(error.contains("status_channel_closed"), "{error}");
        let (_send, receive) = watch::channel(status(3, 0, 0));
        let error = await_device_terminal(receive, "expected-session", 7, Instant::now())
            .await
            .expect_err("late success cannot extend existing budget")
            .to_string();
        assert!(error.contains("reason=deadline"), "{error}");
    }
}
