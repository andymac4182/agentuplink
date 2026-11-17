//! The physical drain barriers one pending `STREAM_FORGET` needs, one per
//! carrier the stream used.
//!
//! ```text
//! per carrier:  (absent) --Queue--> Queued --Complete--> Completed
//! whole set:    any --Retry--> every carrier absent again
//! ```
//!
//! A barrier completes only after it was queued, so "completed but never
//! queued" cannot be represented.  `Retry` is the bounded restart taken when
//! every barrier completed but the owner's proof did not validate yet.

use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BarrierPhase {
    /// The barrier command is in the carrier's writer queue.
    Queued,
    /// The carrier's writer reached the barrier.
    Completed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BarrierEvent<'a, K> {
    /// A barrier command was queued on this carrier.
    Queue(&'a K),
    /// This carrier's writer reported a completed barrier.
    Complete(&'a K),
    /// Forget every barrier so that the deadline tick queues them again.
    Retry,
}

/// The event does not apply to that carrier's barrier; nothing changed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct IllegalBarrierTransition {
    /// The carrier's phase when the event was refused (`None`: not queued).
    pub(super) from: Option<BarrierPhase>,
}

#[derive(Clone, Debug)]
pub(super) struct ForgetBarriers<K>(BTreeMap<K, BarrierPhase>);

impl<K> Default for ForgetBarriers<K> {
    fn default() -> Self {
        Self(BTreeMap::new())
    }
}

impl<K: Ord + Clone> ForgetBarriers<K> {
    /// The only writer of the barrier phases.
    ///
    /// Refused: `Queue` for a carrier whose barrier is already queued or
    /// completed, and `Complete` for one that is not queued or is already
    /// completed.  `Retry` is always legal.
    pub(super) fn transition(
        &mut self,
        event: BarrierEvent<'_, K>,
    ) -> Result<(), IllegalBarrierTransition> {
        match event {
            BarrierEvent::Queue(key) => match self.0.get(key).copied() {
                None => {
                    self.0.insert(key.clone(), BarrierPhase::Queued);
                    Ok(())
                }
                from @ Some(_) => Err(IllegalBarrierTransition { from }),
            },
            BarrierEvent::Complete(key) => match self.0.get_mut(key) {
                Some(phase @ BarrierPhase::Queued) => {
                    *phase = BarrierPhase::Completed;
                    Ok(())
                }
                Some(BarrierPhase::Completed) => Err(IllegalBarrierTransition {
                    from: Some(BarrierPhase::Completed),
                }),
                None => Err(IllegalBarrierTransition { from: None }),
            },
            BarrierEvent::Retry => {
                self.0.clear();
                Ok(())
            }
        }
    }

    /// The carrier's barrier was queued (and may have completed).
    pub(super) fn queued(&self, key: &K) -> bool {
        self.0.contains_key(key)
    }

    /// The carrier's barrier completed.
    pub(super) fn completed(&self, key: &K) -> bool {
        self.0.get(key) == Some(&BarrierPhase::Completed)
    }

    /// How many carriers have a queued or completed barrier.
    #[cfg(test)]
    pub(super) fn queued_len(&self) -> usize {
        self.0.len()
    }

    /// How many carriers have a completed barrier.
    #[cfg(test)]
    pub(super) fn completed_len(&self) -> usize {
        self.0
            .values()
            .filter(|phase| **phase == BarrierPhase::Completed)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn barrier_transition_table_is_exact() {
        let mut barriers = ForgetBarriers::<u8>::default();
        assert!(!barriers.queued(&1) && !barriers.completed(&1));
        // A barrier never completes before it is queued.
        assert_eq!(
            barriers.transition(BarrierEvent::Complete(&1)),
            Err(IllegalBarrierTransition { from: None })
        );
        assert_eq!(barriers.queued_len(), 0);

        assert_eq!(barriers.transition(BarrierEvent::Queue(&1)), Ok(()));
        assert!(barriers.queued(&1) && !barriers.completed(&1));
        // It is queued once.
        assert_eq!(
            barriers.transition(BarrierEvent::Queue(&1)),
            Err(IllegalBarrierTransition {
                from: Some(BarrierPhase::Queued)
            })
        );

        assert_eq!(barriers.transition(BarrierEvent::Complete(&1)), Ok(()));
        assert!(barriers.queued(&1) && barriers.completed(&1));
        // It completes once, and is not queued again after completing.
        assert_eq!(
            barriers.transition(BarrierEvent::Complete(&1)),
            Err(IllegalBarrierTransition {
                from: Some(BarrierPhase::Completed)
            })
        );
        assert_eq!(
            barriers.transition(BarrierEvent::Queue(&1)),
            Err(IllegalBarrierTransition {
                from: Some(BarrierPhase::Completed)
            })
        );
        assert_eq!((barriers.queued_len(), barriers.completed_len()), (1, 1));
    }

    #[test]
    fn carriers_are_independent_and_retry_forgets_them_all() {
        let mut barriers = ForgetBarriers::<u8>::default();
        assert_eq!(barriers.transition(BarrierEvent::Queue(&1)), Ok(()));
        assert_eq!(barriers.transition(BarrierEvent::Queue(&2)), Ok(()));
        assert_eq!(barriers.transition(BarrierEvent::Complete(&2)), Ok(()));
        assert!(barriers.queued(&1) && !barriers.completed(&1));
        assert!(barriers.completed(&2));
        assert_eq!((barriers.queued_len(), barriers.completed_len()), (2, 1));

        assert_eq!(barriers.transition(BarrierEvent::Retry), Ok(()));
        assert_eq!((barriers.queued_len(), barriers.completed_len()), (0, 0));
        assert!(!barriers.queued(&2) && !barriers.completed(&2));
        // After a retry each barrier starts over.
        assert_eq!(barriers.transition(BarrierEvent::Retry), Ok(()));
        assert_eq!(barriers.transition(BarrierEvent::Queue(&2)), Ok(()));
        assert_eq!(barriers.transition(BarrierEvent::Complete(&2)), Ok(()));
    }
}
