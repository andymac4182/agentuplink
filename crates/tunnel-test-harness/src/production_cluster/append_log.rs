//! An append-only recorder for gate observations, shared by reference.
//!
//! A gate's handlers, proxies and callbacks record what they saw while the
//! scenario reads it back, so the recorder is shared.  Every record is written
//! once and never changed, which is all the sharing needs: an index is
//! reserved with one atomic add, and the record is stored in the set-once cell
//! that index names.  Nothing is ever moved, overwritten or removed, so a
//! reader needs no exclusion from a writer.
//!
//! **Order.**  Records are read back in reservation order.  Two appends that
//! do not overlap in time are therefore read back in the order they happened,
//! and two that do overlap are read back in one of the two orders, exactly as
//! if each had been applied at a single instant.  A snapshot returns every
//! append that completed before it began, and may or may not include one that
//! was still in flight.

use std::sync::{
    OnceLock,
    atomic::{AtomicUsize, Ordering},
};

const CHUNK: usize = 32;

struct Chunk<T> {
    slots: [OnceLock<T>; CHUNK],
    next: OnceLock<Box<Chunk<T>>>,
}

impl<T> Chunk<T> {
    fn new() -> Self {
        Self {
            slots: std::array::from_fn(|_| OnceLock::new()),
            next: OnceLock::new(),
        }
    }
}

/// An unbounded append-only log of set-once records.
///
/// An append walks the chunk list to its cell, so it costs one step per
/// [`CHUNK`] records already held.  Gate recorders hold hundreds to a few
/// thousand records, never a data path's worth.
pub(super) struct AppendLog<T> {
    reserved: AtomicUsize,
    head: Chunk<T>,
}

impl<T> Default for AppendLog<T> {
    fn default() -> Self {
        Self {
            reserved: AtomicUsize::new(0),
            head: Chunk::new(),
        }
    }
}

impl<T> std::fmt::Debug for AppendLog<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Payload-free: a recorder's contents are never printed.
        formatter
            .debug_struct("AppendLog")
            .field("len", &self.len())
            .finish()
    }
}

impl<T> AppendLog<T> {
    /// Append one record.
    pub(super) fn push(&self, value: T) {
        let index = self.reserved.fetch_add(1, Ordering::AcqRel);
        self.store(index, value);
    }

    /// Append one record unless `bound` records were already appended.
    /// Returns the record when the log is full.
    pub(super) fn push_bounded(&self, bound: usize, value: T) -> Result<(), T> {
        match self
            .reserved
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |reserved| {
                (reserved < bound).then_some(reserved + 1)
            }) {
            Ok(index) => {
                self.store(index, value);
                Ok(())
            }
            Err(_) => Err(value),
        }
    }

    fn store(&self, index: usize, value: T) {
        let mut chunk = &self.head;
        for _ in 0..index / CHUNK {
            chunk = chunk.next.get_or_init(|| Box::new(Chunk::new()));
        }
        // The index was reserved by this call alone, so its cell is empty.
        let stored = chunk.slots[index % CHUNK].set(value).is_ok();
        debug_assert!(stored, "a reserved append-log cell is written once");
    }

    /// The number of records appended, counting any still being stored.
    pub(super) fn len(&self) -> usize {
        self.reserved.load(Ordering::Acquire)
    }

    /// Every stored record, in reservation order.
    pub(super) fn iter(&self) -> impl Iterator<Item = &T> {
        let reserved = self.len();
        let mut chunk = Some(&self.head);
        let mut index = 0;
        std::iter::from_fn(move || {
            while index < reserved {
                let current = chunk?;
                let slot = index % CHUNK;
                index += 1;
                let value = current.slots[slot].get();
                if slot + 1 == CHUNK {
                    chunk = current.next.get().map(|next| &**next);
                }
                if value.is_some() {
                    return value;
                }
            }
            None
        })
    }

    /// The most recently appended stored record.
    pub(super) fn last(&self) -> Option<&T> {
        self.iter().last()
    }

    /// A copy of every stored record, in reservation order.
    pub(super) fn snapshot(&self) -> Vec<T>
    where
        T: Clone,
    {
        self.iter().cloned().collect()
    }
}

impl<T> Drop for AppendLog<T> {
    fn drop(&mut self) {
        // Unlink the chunks one at a time so a long log is not dropped by
        // recursion.
        let mut next = self.head.next.take();
        while let Some(mut chunk) = next {
            next = chunk.next.take();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AppendLog, CHUNK};
    use std::sync::Arc;

    #[test]
    fn records_are_read_back_in_append_order_across_chunks() {
        let log = AppendLog::default();
        let count = CHUNK * 3 + 5;
        for value in 0..count {
            log.push(value);
        }
        assert_eq!(log.len(), count);
        assert_eq!(log.snapshot(), (0..count).collect::<Vec<_>>());
        assert_eq!(log.iter().count(), count);
    }

    #[test]
    fn a_bounded_append_refuses_the_record_past_its_bound() {
        let log = AppendLog::default();
        assert_eq!(log.push_bounded(2, "a"), Ok(()));
        assert_eq!(log.push_bounded(2, "b"), Ok(()));
        assert_eq!(log.push_bounded(2, "c"), Err("c"));
        assert_eq!(log.snapshot(), vec!["a", "b"]);
    }

    #[test]
    fn concurrent_appends_lose_nothing_and_keep_each_writer_in_order() {
        const WRITERS: usize = 4;
        const EACH: usize = CHUNK * 8;
        let log = Arc::new(AppendLog::default());
        let threads: Vec<_> = (0..WRITERS)
            .map(|writer| {
                let log = Arc::clone(&log);
                std::thread::spawn(move || {
                    for sequence in 0..EACH {
                        log.push((writer, sequence));
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().expect("writer joins");
        }
        let records = log.snapshot();
        assert_eq!(records.len(), WRITERS * EACH);
        for writer in 0..WRITERS {
            let own: Vec<usize> = records
                .iter()
                .filter(|(from, _)| *from == writer)
                .map(|(_, sequence)| *sequence)
                .collect();
            assert_eq!(own, (0..EACH).collect::<Vec<_>>());
        }
    }

    #[test]
    fn a_long_log_drops_without_recursing() {
        let log = AppendLog::default();
        for value in 0..CHUNK * 2_000 {
            log.push(value);
        }
        drop(log);
    }
}
