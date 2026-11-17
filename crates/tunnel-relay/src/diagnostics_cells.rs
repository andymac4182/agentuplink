//! Lock-free recording and wait-free reading for bounded relay diagnostics.
//!
//! Diagnostics are recorded from synchronous and asynchronous hot paths on
//! many tasks and read by the status and metrics endpoints.
//!
//! * A counter nothing else is reported against is a plain atomic.
//! * Everything a snapshot reports *together* -- counts, their breakdown,
//!   the latest event and the recent ring of one diagnostic family -- lives
//!   in one [`Ledger`]: an immutable tree of words named by one root word.
//!   A recorder builds a new root that shares every untouched node with the
//!   old one and installs it with a single compare-and-swap, so a reader
//!   always sees a state some serialised recorder would have produced: a
//!   count never runs ahead of, or behind, the records it counts, and every
//!   breakdown sums to its total because both come from the same root.
//! * Records are encoded into `u64` words in blocks only their writer can
//!   reach until they are installed, and are immutable afterwards.
//! * A reader announces itself in one of a small fixed table of reader
//!   cells before it loads a root.  Blocks a recorder unlinks are parked,
//!   stamped with the arena epoch, and returned to the free list only once
//!   every announced reader started after that epoch.  A reader therefore
//!   reads its root, and everything the root names, in one pass with no
//!   validation and no retry.  Its own work is the size of one state plus
//!   one bounded batch of parked blocks it helps reclaim when it finishes
//!   ([`RECLAIM_BATCH`]); no recorder can make it repeat anything.  If
//!   every reader cell is taken the read is refused, counted, and reported
//!   as unavailable -- never as an empty state.
//!
//! # Memory
//!
//! Storage is fixed-size chunks of [`CHUNK_NODES`] nodes, allocated on
//! first use and never returned, under a per-pool cap given at
//! construction.  A block node is 88 bytes.  The relay's arenas are capped
//! at 2^17 blocks (11.5 MB) for the peer-fault and HTTP-forward
//! diagnostics and 2^14 blocks (1.4 MB) for each of the three small ones,
//! so the worst-case resident memory of all five is about 27.5 MB, plus
//! at most about 4 MB of live-hop cells.  What is retained is a few
//! hundred to a couple of thousand blocks per arena; the rest of the cap
//! is head-room for recorders in flight and for blocks parked behind a
//! reader.
//!
//! A reader descheduled in the middle of a read holds back every block
//! unlinked while it is stalled, about twenty per record.  Under a
//! sustained hundred thousand records a second that is two million blocks
//! a second: the cap is reached in well under a second, after which
//! records (and their counts) are refused and counted in
//! [`records_dropped`] until the reader resumes, and the reported state
//! stays consistent throughout.  That is the price of the cap; without a
//! stalled reader a cap of 2^17 blocks is not reached below several
//! thousand recorders in flight at once.
//!
//! # Cost of one record
//!
//! The nodes on the paths to the words it changes (the tree has a fan-out
//! of seven, so two to four levels) plus the record's own blocks,
//! independent of how many counters the family has.  A peer fault is
//! encoded twice, for the recent ring and for its stage's latest tuple: 8
//! to 10 path nodes plus two records of 4 or 5 blocks.  That is about
//! seven atomic read-modify-writes when uncontended -- one free-list
//! compare-and-swap per record and one for the path nodes, the clock, the
//! root, the epoch, and one to give the replaced blocks back -- plus a
//! scan of the [`READER_CELLS`] reader cells and at most one bounded batch
//! of reclamation.
//!
//! # What can delay a caller
//!
//! A recorder whose root compare-and-swap loses to another recorder's
//! install rebuilds from the new root (lock-free: some recorder always
//! completes); a free-list, parked-list or reader-cell compare-and-swap
//! that loses to another's is repeated.  A pool chunk is built by the
//! caller that needs it and then offered with `OnceLock::set`, so no
//! caller waits for another's allocation; the only shared step is the
//! store of the finished chunk's pointer.  The first use of a label-table
//! entry stores one static reference the same way.  A reader never repeats
//! work because of a recorder.
//!
//! Records hold identifiers, counters and closed-vocabulary labels only, as
//! the diagnostics that use this module require.

use std::{
    fmt,
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

use uuid::Uuid;

const ORD: Ordering = Ordering::SeqCst;

/// Bits of a pool index inside a packed word.
const INDEX_BITS: u32 = 24;
const INDEX_MASK: u64 = (1 << INDEX_BITS) - 1;
/// The index that names no node.
const NIL: u64 = INDEX_MASK;
/// Nodes in one pool chunk: 90 KB of blocks, built by whoever first needs
/// it.
pub(crate) const CHUNK_NODES: usize = 1024;
/// Reader cells in one arena: how many snapshots of it may be in progress
/// at once before one is refused.  Recorders scan this many cells.
pub(crate) const READER_CELLS: usize = 32;
/// Parked blocks one reclamation examines.  Larger than the blocks one
/// record unlinks, so reclamation outpaces parking.
pub(crate) const RECLAIM_BATCH: usize = 64;
/// Payload words per record block.
const BLOCK_WORDS: usize = 7;

/// Add one to a counter without wrapping and return the new value.
pub(crate) fn bump(counter: &AtomicU64) -> u64 {
    match counter.fetch_update(ORD, ORD, |value| value.checked_add(1)) {
        Ok(previous) => previous + 1,
        Err(_) => u64::MAX,
    }
}

/// The current value of a counter.
pub(crate) fn read(counter: &AtomicU64) -> u64 {
    counter.load(ORD)
}

/// The position of `value` in a closed vocabulary table.
pub(crate) fn code_of<T: PartialEq>(all: &[T], value: &T) -> u64 {
    all.iter()
        .position(|candidate| candidate == value)
        .map_or(u64::MAX, |position| position as u64)
}

/// The vocabulary entry a recorded code names.
pub(crate) fn variant<T: Copy>(all: &[T], code: u64) -> Option<T> {
    all.get(usize::try_from(code).ok()?).copied()
}

fn locate(index: u64) -> (usize, usize) {
    let index = usize::try_from(index).unwrap_or(usize::MAX);
    (index / CHUNK_NODES, index % CHUNK_NODES)
}

fn next_tag(word: u64) -> u64 {
    (word >> INDEX_BITS).wrapping_add(1) << INDEX_BITS
}

/// One pool node: a link used by the free list (and by record chains) and a
/// body made only of atomics.
pub(crate) struct Node<B> {
    link: AtomicU64,
    pub(crate) body: B,
}

impl<B: Default> Default for Node<B> {
    fn default() -> Self {
        Self {
            link: AtomicU64::new(NIL),
            body: B::default(),
        }
    }
}

/// One fixed-size chunk of nodes, absent until first needed.
type Chunk<B> = OnceLock<Box<[Node<B>]>>;

/// A capped pool of reusable nodes addressed by index.
///
/// Free nodes sit on an index stack whose head carries a version tag, so a
/// pop cannot be fooled by a node that was popped and pushed back.  The pool
/// grows, one fixed-size chunk at a time, only when the stack is empty --
/// every existing node is then retained, parked or held by a recorder in
/// flight -- and never past its cap; nodes are never returned to the
/// allocator while the pool lives.
pub(crate) struct Pool<B> {
    chunks: Box<[Chunk<B>]>,
    /// The cap: no index at or above it is ever handed out.
    limit: u64,
    allocated: AtomicU64,
    free: AtomicU64,
}

impl<B> fmt::Debug for Pool<B> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Pool")
            .field("allocated", &self.allocated.load(ORD))
            .field("limit", &self.limit)
            .finish()
    }
}

impl<B: Default> Pool<B> {
    /// An empty pool that will never hold more than `limit` nodes.
    pub(crate) fn new(limit: usize) -> Self {
        let limit = limit.min(usize::try_from(NIL).unwrap_or(usize::MAX));
        Self {
            chunks: (0..limit.div_ceil(CHUNK_NODES))
                .map(|_| OnceLock::new())
                .collect(),
            limit: limit as u64,
            allocated: AtomicU64::new(0),
            free: AtomicU64::new(NIL),
        }
    }

    /// The node at `index`, if that index has been allocated.
    pub(crate) fn node(&self, index: u64) -> Option<&Node<B>> {
        if index >= self.limit {
            return None;
        }
        let (chunk, offset) = locate(index);
        self.chunks.get(chunk)?.get()?.get(offset)
    }

    /// One more than the highest index ever handed out.
    pub(crate) fn allocated(&self) -> u64 {
        self.allocated.load(ORD)
    }

    /// Take exclusive ownership of a node.  `None` only when every node the
    /// cap allows is in use.
    pub(crate) fn acquire(&self) -> Option<u64> {
        let mut head = self.free.load(ORD);
        loop {
            let index = head & INDEX_MASK;
            if index == NIL {
                break;
            }
            let Some(node) = self.node(index) else {
                break;
            };
            let next = node.link.load(ORD) & INDEX_MASK;
            match self
                .free
                .compare_exchange_weak(head, next_tag(head) | next, ORD, ORD)
            {
                Ok(_) => return Some(index),
                Err(observed) => head = observed,
            }
        }
        let index = self
            .allocated
            .fetch_update(ORD, ORD, |count| (count < self.limit).then_some(count + 1))
            .ok()?;
        let (chunk, offset) = locate(index);
        let slot = self.chunks.get(chunk)?;
        if slot.get().is_none() {
            // Built here, outside any shared step, then offered: if another
            // caller offered first, this copy is dropped and theirs used.
            let built: Box<[Node<B>]> = (0..CHUNK_NODES).map(|_| Node::default()).collect();
            let _ = slot.set(built);
        }
        slot.get()?.get(offset).map(|_| index)
    }

    /// Take `want` nodes, appending them to `taken`: as many as the free
    /// list holds in one compare-and-swap, the rest newly allocated.  On
    /// exhaustion nothing is kept and `false` is returned.
    pub(crate) fn acquire_many(&self, want: usize, taken: &mut Vec<u64>) -> bool {
        let start = taken.len();
        let mut head = self.free.load(ORD);
        loop {
            taken.truncate(start);
            let mut index = head & INDEX_MASK;
            // A link read from a node another caller has since taken may be
            // stale; the walk is bounded by `want` and the compare-and-swap
            // below accepts it only if the list did not change.
            while taken.len() - start < want && index != NIL {
                let Some(node) = self.node(index) else {
                    break;
                };
                taken.push(index);
                index = node.link.load(ORD) & INDEX_MASK;
            }
            if taken.len() == start {
                break;
            }
            match self
                .free
                .compare_exchange_weak(head, next_tag(head) | index, ORD, ORD)
            {
                Ok(_) => break,
                Err(observed) => head = observed,
            }
        }
        while taken.len() - start < want {
            if let Some(index) = self.acquire() {
                taken.push(index);
            } else {
                self.release_many(taken.get(start..).unwrap_or(&[]));
                taken.truncate(start);
                return false;
            }
        }
        true
    }

    /// Give exclusively owned nodes back in one compare-and-swap.
    pub(crate) fn release_many(&self, indices: &[u64]) {
        let (Some(first), Some(last)) = (indices.first(), indices.last()) else {
            return;
        };
        for pair in indices.windows(2) {
            if let [index, next] = pair
                && let Some(node) = self.node(*index)
            {
                node.link.store(*next, ORD);
            }
        }
        let Some(last) = self.node(*last) else {
            return;
        };
        let mut head = self.free.load(ORD);
        loop {
            last.link.store(head & INDEX_MASK, ORD);
            match self
                .free
                .compare_exchange_weak(head, next_tag(head) | *first, ORD, ORD)
            {
                Ok(_) => return,
                Err(observed) => head = observed,
            }
        }
    }

    /// Give an exclusively owned node back.
    pub(crate) fn release(&self, index: u64) {
        let Some(node) = self.node(index) else {
            return;
        };
        let mut head = self.free.load(ORD);
        loop {
            node.link.store(head & INDEX_MASK, ORD);
            match self
                .free
                .compare_exchange_weak(head, next_tag(head) | index, ORD, ORD)
            {
                Ok(_) => return,
                Err(observed) => head = observed,
            }
        }
    }
}

/// One block: its payload words, and three words used only while it is
/// parked between being unlinked and being reused.
#[derive(Default)]
pub(crate) struct WordBlock {
    words: [AtomicU64; BLOCK_WORDS],
    /// The arena epoch at which the block was unlinked.
    retired_at: AtomicU64,
    /// The next parked block of the list this block is in.
    parked: AtomicU64,
    /// For the first block of a set-aside list: the next such list.
    list: AtomicU64,
}

const READER_IDLE: u64 = 0;
const READER_ANNOUNCING: u64 = 1;
/// Added to an epoch so it cannot be mistaken for the two states above.
const READER_EPOCH: u64 = 2;

/// Records and counts that could not be recorded because an arena was at
/// its cap, across every diagnostic in the process.
static RECORDS_DROPPED: AtomicU64 = AtomicU64::new(0);

/// Reads refused because every reader cell of an arena was taken, across
/// every diagnostic in the process.
static READS_REFUSED: AtomicU64 = AtomicU64::new(0);

/// How many records (and the counts that went with them) were refused
/// because an arena was at its cap.  Without a stalled reader a recorder in
/// flight holds a few dozen blocks, so an arena of 2^17 blocks is not
/// exhausted below several thousand recorders in flight at once.  A reader
/// descheduled mid-read holds back about twenty blocks per record made
/// while it is stalled, so under a sustained hundred thousand records a
/// second the cap is reached in well under a second; records are then
/// refused and counted here until the reader resumes.
pub(crate) fn records_dropped() -> u64 {
    read(&RECORDS_DROPPED)
}

/// How many reads were refused, and reported as unavailable, because
/// [`READER_CELLS`] reads of the same arena were already in progress.
pub(crate) fn reads_refused() -> u64 {
    read(&READS_REFUSED)
}

/// The blocks records and ledger states are written into, the blocks
/// parked until no reader can still reach them, and the announced readers.
pub(crate) struct Arena {
    blocks: Pool<WordBlock>,
    /// The first block of the list recorders park onto, or [`NIL`].
    parked: AtomicU64,
    /// A version above the first block of the first set-aside list: the
    /// remainders of parked lists a bounded reclamation did not finish.
    set_aside: AtomicU64,
    /// Advanced once for each batch of unlinked blocks.
    epoch: AtomicU64,
    /// One word per reader that may be announced at once.
    readers: [AtomicU64; READER_CELLS],
    /// Records this arena refused for want of blocks.
    dropped: AtomicU64,
}

impl fmt::Debug for Arena {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Arena")
            .field("blocks", &self.blocks.allocated())
            .finish_non_exhaustive()
    }
}

/// A reader's announcement, withdrawn when dropped.
pub(crate) struct Reading<'a> {
    arena: &'a Arena,
    cell: usize,
}

impl Drop for Reading<'_> {
    fn drop(&mut self) {
        if let Some(cell) = self.arena.readers.get(self.cell) {
            cell.store(READER_IDLE, ORD);
        }
        self.arena.reclaim();
    }
}

impl Arena {
    /// An arena that will never hold more than `blocks` blocks (88 bytes
    /// each).
    pub(crate) fn new(blocks: usize) -> Self {
        Self {
            blocks: Pool::new(blocks),
            parked: AtomicU64::new(NIL),
            set_aside: AtomicU64::new(NIL),
            epoch: AtomicU64::new(0),
            readers: std::array::from_fn(|_| AtomicU64::new(READER_IDLE)),
            dropped: AtomicU64::new(0),
        }
    }

    /// Count one record refused for want of blocks.
    fn refuse_record(&self) {
        bump(&self.dropped);
        bump(&RECORDS_DROPPED);
    }

    /// Records this arena refused for want of blocks.
    #[cfg(test)]
    pub(crate) fn dropped(&self) -> u64 {
        read(&self.dropped)
    }

    /// Take every reader cell that is free, so the next read is refused.
    #[cfg(test)]
    pub(crate) fn occupy_readers(&self) -> Vec<Reading<'_>> {
        std::iter::from_fn(|| self.announce()).collect()
    }

    /// Blocks ever allocated.
    #[cfg(test)]
    pub(crate) fn allocated(&self) -> u64 {
        self.blocks.allocated()
    }

    /// Whether any block is parked awaiting a reader.
    #[cfg(test)]
    pub(crate) fn has_parked(&self) -> bool {
        self.parked.load(ORD) != NIL || self.set_aside.load(ORD) & INDEX_MASK != NIL
    }

    fn block(&self, index: u64) -> Option<&WordBlock> {
        self.blocks.node(index).map(|node| &node.body)
    }

    /// Write `words` into freshly acquired blocks and return the first.
    fn store(&self, words: &[u64]) -> Option<u64> {
        let mut indices = Vec::new();
        if !self
            .blocks
            .acquire_many((words.len() + 1).div_ceil(BLOCK_WORDS), &mut indices)
        {
            return None;
        }
        let mut stream = std::iter::once(words.len() as u64).chain(words.iter().copied());
        for (position, index) in indices.iter().enumerate() {
            let node = self.blocks.node(*index)?;
            for cell in &node.body.words {
                cell.store(stream.next().unwrap_or(0), ORD);
            }
            node.link
                .store(indices.get(position + 1).copied().unwrap_or(NIL), ORD);
        }
        indices.first().copied()
    }

    /// Replace the first word of a record this caller has not installed.
    fn patch(&self, head: u64, value: u64) {
        if let Some(cell) = self.block(head).and_then(|block| block.words.get(1)) {
            cell.store(value, ORD);
        }
    }

    /// The blocks of a chain this caller owns or has just unlinked.
    fn chain(&self, head: u64) -> Vec<u64> {
        let mut indices = Vec::new();
        let mut index = head;
        let mut budget = self.blocks.allocated();
        while index != NIL && budget > 0 {
            let Some(node) = self.blocks.node(index) else {
                break;
            };
            indices.push(index);
            index = node.link.load(ORD) & INDEX_MASK;
            budget -= 1;
        }
        indices
    }

    /// Recycle at once a chain no reader can reach.
    fn discard(&self, head: u64) {
        self.blocks.release_many(&self.chain(head));
    }

    /// Read a chain, trusting each block only while `published` still holds.
    fn load(&self, head: u64, published: impl Fn() -> bool) -> Option<Vec<u64>> {
        let mut words = Vec::new();
        let mut index = head;
        let mut remaining = None::<u64>;
        loop {
            let node = self.blocks.node(index)?;
            let mut block = [0_u64; BLOCK_WORDS];
            for (value, cell) in block.iter_mut().zip(&node.body.words) {
                *value = cell.load(ORD);
            }
            let next = node.link.load(ORD) & INDEX_MASK;
            if !published() {
                return None;
            }
            let mut values = block.iter().copied();
            let mut left = match remaining {
                Some(left) => left,
                None => values.next()?,
            };
            for value in values {
                if left == 0 {
                    break;
                }
                words.push(value);
                left -= 1;
            }
            if left == 0 {
                return Some(words);
            }
            if next == NIL {
                return None;
            }
            remaining = Some(left);
            index = next;
        }
    }

    /// Announce a reader, or `None` if every reader cell is taken.
    /// Everything reachable from a root loaded after this returns stays
    /// intact until the announcement is dropped: the cell reads
    /// "announcing" before the epoch is read, and a recorder parks a block
    /// only after it has installed the root that unlinks it and advanced
    /// the epoch, so a reader that could still load the old root is always
    /// seen, announcing or at an earlier epoch, by whoever reclaims that
    /// block.
    fn announce(&self) -> Option<Reading<'_>> {
        let (index, cell) = self.readers.iter().enumerate().find(|(_, cell)| {
            cell.compare_exchange(READER_IDLE, READER_ANNOUNCING, ORD, ORD)
                .is_ok()
        })?;
        let epoch = self.epoch.load(ORD);
        cell.store(epoch.saturating_add(READER_EPOCH), ORD);
        Some(Reading {
            arena: self,
            cell: index,
        })
    }

    /// The earliest epoch an announced reader started at; `None` when no
    /// reader is announced.  A scan of [`READER_CELLS`] words.
    fn earliest_reader(&self) -> Option<u64> {
        let mut earliest = None::<u64>;
        for cell in &self.readers {
            match cell.load(ORD) {
                READER_IDLE => {}
                READER_ANNOUNCING => return Some(0),
                since => {
                    let since = since - READER_EPOCH;
                    earliest = Some(earliest.map_or(since, |held| held.min(since)));
                }
            }
        }
        earliest
    }

    /// Set aside a list of parked blocks this caller owns.
    fn set_aside(&self, first: u64) {
        let Some(block) = self.block(first) else {
            return;
        };
        let mut head = self.set_aside.load(ORD);
        loop {
            block.list.store(head & INDEX_MASK, ORD);
            match self
                .set_aside
                .compare_exchange_weak(head, next_tag(head) | first, ORD, ORD)
            {
                Ok(_) => return,
                Err(observed) => head = observed,
            }
        }
    }

    /// Take ownership of one set-aside list.
    fn take_aside(&self) -> Option<u64> {
        let mut head = self.set_aside.load(ORD);
        loop {
            let first = head & INDEX_MASK;
            // A `list` word read from a block another caller has since
            // taken may be stale; the versioned compare-and-swap rejects it.
            let next = self.block(first)?.list.load(ORD) & INDEX_MASK;
            match self
                .set_aside
                .compare_exchange_weak(head, next_tag(head) | next, ORD, ORD)
            {
                Ok(_) => return Some(first),
                Err(observed) => head = observed,
            }
        }
    }

    fn park(&self, indices: &[u64]) {
        let (Some(first), Some(last)) = (indices.first(), indices.last()) else {
            return;
        };
        for pair in indices.windows(2) {
            if let [index, next] = pair
                && let Some(block) = self.block(*index)
            {
                block.parked.store(*next, ORD);
            }
        }
        let Some(last) = self.block(*last) else {
            return;
        };
        let mut head = self.parked.load(ORD);
        loop {
            last.parked.store(head, ORD);
            match self.parked.compare_exchange_weak(head, *first, ORD, ORD) {
                Ok(_) => return,
                Err(observed) => head = observed,
            }
        }
    }

    /// Dispose of blocks the caller has just unlinked by installing a new
    /// root.  The epoch is advanced first, so a reader announced from now
    /// on loads a root that no longer names them.  With no earlier reader
    /// they go straight back to the free list; otherwise they are parked.
    /// Either way the caller then reclaims one bounded batch of what is
    /// parked, which is more than one record parks, so parked blocks do not
    /// accumulate once the reader holding them back has finished.
    fn retire(&self, indices: &[u64]) {
        if indices.is_empty() {
            return;
        }
        let epoch = bump(&self.epoch);
        match self.earliest_reader() {
            Some(earliest) if earliest < epoch => {
                for index in indices {
                    if let Some(block) = self.block(*index) {
                        block.retired_at.store(epoch, ORD);
                    }
                }
                self.park(indices);
            }
            _ => self.blocks.release_many(indices),
        }
        self.reclaim();
    }

    /// Examine at most [`RECLAIM_BATCH`] parked blocks, returning to the
    /// free list those no reader can reach.
    ///
    /// The caller takes ownership of one list -- a set-aside remainder if
    /// there is one, otherwise everything parked, in one swap -- so it owns
    /// what it walks.  Blocks a reader may still reach are parked again,
    /// and the part of the list not examined is set aside for a later call,
    /// so the work of one call does not grow with the number of parked
    /// blocks.  Set-aside lists are taken before newly parked blocks, so
    /// every parked block is examined in turn.
    fn reclaim(&self) {
        let Some(first) = self.take_aside().or_else(|| {
            (self.parked.load(ORD) != NIL)
                .then(|| self.parked.swap(NIL, ORD))
                .filter(|first| *first != NIL)
        }) else {
            return;
        };
        let earliest = self.earliest_reader();
        let (mut free, mut keep) = (Vec::new(), Vec::new());
        let mut index = first;
        while free.len() + keep.len() < RECLAIM_BATCH {
            let Some(block) = self.block(index) else {
                break;
            };
            if earliest.is_none_or(|earliest| block.retired_at.load(ORD) <= earliest) {
                free.push(index);
            } else {
                keep.push(index);
            }
            index = block.parked.load(ORD);
        }
        self.blocks.release_many(&free);
        self.park(&keep);
        if index != NIL {
            self.set_aside(index);
        }
    }

    /// The word at `index` of the tree under `root`; `None` if the tree was
    /// replaced and recycled while it was read without an announcement.
    fn tree_get(&self, root: u64, top_span: usize, index: usize) -> Option<u64> {
        let mut node = root;
        let mut span = top_span;
        let mut offset = index;
        loop {
            if node == NIL {
                return Some(0);
            }
            let word = self.block(node)?.words.get(offset / span)?.load(ORD);
            if span == 1 {
                return Some(word);
            }
            node = word.checked_sub(1).unwrap_or(NIL);
            offset %= span;
            span /= BLOCK_WORDS;
        }
    }

    /// Copy every word of the tree under `node` into `words`.  The caller
    /// has announced itself, so the tree is intact.
    fn tree_fill(&self, node: u64, span: usize, base: usize, words: &mut [u64]) {
        let Some(block) = self.block(node) else {
            return;
        };
        for (slot, cell) in block.words.iter().enumerate() {
            let at = base + slot * span;
            if at >= words.len() {
                return;
            }
            let word = cell.load(ORD);
            if span == 1 {
                if let Some(target) = words.get_mut(at) {
                    *target = word;
                }
            } else if let Some(child) = word.checked_sub(1) {
                self.tree_fill(child, span / BLOCK_WORDS, at, words);
            }
        }
    }

    /// Build, from blocks in `fresh`, the node that replaces `old` once the
    /// sorted `writes` under it are applied.  Untouched children are shared.
    /// `None` if the old tree was recycled under the caller.
    fn tree_put(
        &self,
        old: u64,
        span: usize,
        base: usize,
        writes: &[(usize, u64)],
        fresh: &mut Vec<u64>,
        replaced: &mut Vec<u64>,
    ) -> Option<u64> {
        let mut words = [0_u64; BLOCK_WORDS];
        if old != NIL {
            let block = self.block(old)?;
            for (word, cell) in words.iter_mut().zip(&block.words) {
                *word = cell.load(ORD);
            }
            replaced.push(old);
        }
        if span == 1 {
            for (index, value) in writes {
                *words.get_mut(index.checked_sub(base)?)? = *value;
            }
        } else {
            let mut rest = writes;
            while let Some((first, _)) = rest.first() {
                let slot = first.checked_sub(base)? / span;
                let end = base + (slot + 1) * span;
                let cut = rest
                    .iter()
                    .position(|(index, _)| *index >= end)
                    .unwrap_or(rest.len());
                let (mine, later) = rest.split_at(cut);
                let child = words.get(slot)?.checked_sub(1).unwrap_or(NIL);
                let built = self.tree_put(
                    child,
                    span / BLOCK_WORDS,
                    base + slot * span,
                    mine,
                    fresh,
                    replaced,
                )?;
                *words.get_mut(slot)? = built + 1;
                rest = later;
            }
        }
        let node = fresh.pop()?;
        for (word, cell) in words.iter().zip(&self.block(node)?.words) {
            cell.store(*word, ORD);
        }
        Some(node)
    }
}

/// How many times a slot read is repeated when the slot changes under it.
const SLOT_READ_ATTEMPTS: usize = 4;

/// One atomically replaced record: empty, or the record last set.
///
/// A slot's blocks are recycled as soon as it is replaced, so a read is
/// validated against the slot word and, if the slot keeps changing, gives
/// up after a fixed number of attempts and reports it empty -- which it
/// was, between two of those changes, only for a slot being cleared.
/// Callers use it for a record set once and cleared once.
pub(crate) struct Slot(AtomicU64);

impl Default for Slot {
    fn default() -> Self {
        Self(AtomicU64::new(NIL))
    }
}

impl Slot {
    fn replace(&self, arena: &Arena, head: u64) {
        let mut current = self.0.load(ORD);
        loop {
            match self
                .0
                .compare_exchange_weak(current, next_tag(current) | head, ORD, ORD)
            {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
        if current & INDEX_MASK != NIL {
            arena.discard(current & INDEX_MASK);
        }
    }

    /// Replace the held record and recycle the one displaced.
    pub(crate) fn set(&self, arena: &Arena, record: WordWriter) {
        match arena.store(&record.0) {
            Some(head) => self.replace(arena, head),
            None => arena.refuse_record(),
        }
    }

    /// Empty the slot and recycle what it held.
    pub(crate) fn clear(&self, arena: &Arena) {
        self.replace(arena, NIL);
    }

    /// The held record, read whole or not at all.
    pub(crate) fn read(&self, arena: &Arena) -> Option<WordReader> {
        for _ in 0..SLOT_READ_ATTEMPTS {
            let word = self.0.load(ORD);
            if word & INDEX_MASK == NIL {
                return None;
            }
            if let Some(words) = arena.load(word & INDEX_MASK, || self.0.load(ORD) == word) {
                return Some(WordReader { words, at: 0 });
            }
        }
        None
    }
}

/// Where an entry's record is kept.
#[derive(Clone, Copy)]
pub(crate) enum Place {
    /// The next position of a group used as a ring: the newest commits are
    /// retained, the oldest displaced.
    Push(usize),
    /// A fixed position of a group: the latest commit there is retained.
    Key(usize, usize),
}

/// The order reported for an entry, assigned by the commit that installs it.
#[derive(Clone, Copy)]
pub(crate) enum Order {
    /// The commit's draw from the clock it was given.  A commit that loses
    /// the race to install draws again, so within one ledger a later
    /// commit always carries a later sequence.
    Sequence,
    /// The value the named counter reaches in the same commit.
    Count(usize),
}

/// One record offered to a ledger.
pub(crate) struct Entry {
    pub(crate) place: Place,
    pub(crate) order: Order,
    pub(crate) record: WordWriter,
}

/// What a commit installed.
pub(crate) struct Committed {
    /// The clock draw the installed state carries; zero without a clock.
    pub(crate) sequence: u64,
    /// The bumped counters' new values, in the order they were named.
    pub(crate) counts: Vec<u64>,
}

/// One retained record of a ledger state.
pub(crate) struct Retained {
    pub(crate) group: usize,
    pub(crate) order: u64,
    pub(crate) record: WordReader,
}

/// One state of a ledger.
pub(crate) struct LedgerView {
    pub(crate) counts: Vec<u64>,
    /// Sorted by group, then by order, lowest first.
    pub(crate) retained: Vec<Retained>,
}

impl LedgerView {
    pub(crate) fn count(&self, index: usize) -> u64 {
        self.counts.get(index).copied().unwrap_or(0)
    }
}

/// A test-only pause point inside [`Ledger::commit`].
#[cfg(test)]
pub(crate) type CommitHook = Box<dyn Fn(&'static str) + Send + Sync>;

/// One diagnostic family's whole reported state, replaced atomically.
///
/// The state is an array of words -- the counters, then for each group a
/// push count and one record reference per position -- held as a tree with
/// a fan-out of seven under one root word.  A commit reads the words it
/// changes, builds the nodes on the paths to them in private blocks
/// (sharing every other node with the current tree), and installs the new
/// root with one compare-and-swap; if another commit installed first it
/// rebuilds from that one.  The commit that installs a root parks the nodes
/// and records its root no longer names, so each is recycled once, and only
/// after no reader can reach it.
pub(crate) struct Ledger {
    /// A version above the index of the root node.
    cell: AtomicU64,
    counters: usize,
    /// Each group's first word (its push count) and its capacity.
    groups: Vec<(usize, usize)>,
    /// Words in the state.
    total: usize,
    /// Words under each child of the root.
    top_span: usize,
    #[cfg(test)]
    hook: OnceLock<CommitHook>,
    /// Passes a reader made over a state, to show a read is one pass.
    #[cfg(test)]
    passes: AtomicU64,
}

impl Ledger {
    /// A ledger of `counters` counters and one group per capacity given.
    pub(crate) fn new(counters: usize, capacities: &[usize]) -> Self {
        let mut total = counters;
        let mut groups = Vec::with_capacity(capacities.len());
        for capacity in capacities {
            groups.push((total, *capacity));
            total += 1 + capacity;
        }
        let mut top_span = 1;
        while top_span * BLOCK_WORDS < total {
            top_span *= BLOCK_WORDS;
        }
        Self {
            cell: AtomicU64::new(NIL),
            counters,
            groups,
            total,
            top_span,
            #[cfg(test)]
            hook: OnceLock::new(),
            #[cfg(test)]
            passes: AtomicU64::new(0),
        }
    }

    /// Call `hook` at each step of every later commit.
    #[cfg(test)]
    pub(crate) fn park_commits(&self, hook: CommitHook) {
        let _ = self.hook.set(hook);
    }

    /// Passes readers have made over a state of this ledger.
    #[cfg(test)]
    pub(crate) fn read_passes(&self) -> u64 {
        read(&self.passes)
    }

    fn at(&self, _step: &'static str) {
        #[cfg(test)]
        if let Some(hook) = self.hook.get() {
            hook(_step);
        }
    }

    /// The group a place names, if the place exists.
    fn group_of(&self, place: Place) -> Option<(usize, usize)> {
        let (group, key) = match place {
            Place::Push(group) => (group, 0),
            Place::Key(group, key) => (group, key),
        };
        self.groups
            .get(group)
            .copied()
            .filter(|(_, capacity)| key < *capacity)
    }

    /// How many nodes lie on the paths to the sorted `writes`.
    fn nodes_for(&self, writes: &[(usize, u64)]) -> usize {
        let mut nodes = 0;
        let mut cover = BLOCK_WORDS;
        loop {
            let mut last = None;
            for (index, _) in writes {
                if last != Some(index / cover) {
                    last = Some(index / cover);
                    nodes += 1;
                }
            }
            if cover >= self.top_span * BLOCK_WORDS {
                return nodes;
            }
            cover *= BLOCK_WORDS;
        }
    }

    /// Add one to each named counter and install each entry, as one atomic
    /// change, drawing the sequence from `clock` if one is given.  `None`
    /// only if the arena is at its cap: nothing was recorded and the
    /// refusal is counted in [`records_dropped`].
    pub(crate) fn commit(
        &self,
        arena: &Arena,
        clock: Option<&AtomicU64>,
        bumps: &[usize],
        entries: Vec<Entry>,
    ) -> Option<Committed> {
        let mut offered = Vec::with_capacity(entries.len());
        for entry in entries {
            let Some((base, capacity)) = self.group_of(entry.place) else {
                debug_assert!(false, "a diagnostic entry names no place in its ledger");
                continue;
            };
            // Word zero of an installed record is its order.
            let mut words = Vec::with_capacity(entry.record.0.len() + 1);
            words.push(0);
            words.extend(entry.record.0);
            let Some(head) = arena.store(&words) else {
                for (_, _, head, _, _) in offered {
                    arena.discard(head);
                }
                arena.refuse_record();
                return None;
            };
            offered.push((entry.place, entry.order, head, base, capacity as u64));
        }
        self.at("stored");
        'attempt: loop {
            let word = self.cell.load(ORD);
            let root = word & INDEX_MASK;
            let sequence = clock.map_or(0, bump);
            let mut writes: Vec<(usize, u64)> = Vec::new();
            let mut counts = Vec::with_capacity(bumps.len());
            let mut displaced = Vec::new();
            macro_rules! word_at {
                ($index:expr) => {{
                    let index: usize = $index;
                    let pending = writes
                        .iter()
                        .find(|(written, _)| *written == index)
                        .map(|(_, value)| *value);
                    match pending.or_else(|| arena.tree_get(root, self.top_span, index)) {
                        Some(value) => value,
                        // The root was replaced and its tree recycled.
                        None => continue 'attempt,
                    }
                }};
            }
            macro_rules! write {
                ($index:expr, $value:expr) => {{
                    let (index, value): (usize, u64) = ($index, $value);
                    match writes.iter_mut().find(|(written, _)| *written == index) {
                        Some(pending) => pending.1 = value,
                        None => writes.push((index, value)),
                    }
                }};
            }
            for index in bumps {
                if *index >= self.counters {
                    counts.push(0);
                    continue;
                }
                let count = word_at!(*index).saturating_add(1);
                write!(*index, count);
                counts.push(count);
            }
            for (place, order, head, base, capacity) in &offered {
                let order = match order {
                    Order::Sequence => sequence,
                    Order::Count(index) if *index < self.counters => word_at!(*index),
                    Order::Count(_) => 0,
                };
                arena.patch(*head, order);
                let slot = match place {
                    Place::Push(_) => {
                        let pushed = word_at!(*base);
                        write!(*base, pushed.saturating_add(1));
                        // The remainder is below the capacity, a `usize`.
                        *base + 1 + usize::try_from(pushed % *capacity).unwrap_or(0)
                    }
                    Place::Key(_, key) => *base + 1 + *key,
                };
                if let Some(held) = word_at!(slot).checked_sub(1) {
                    displaced.push(held);
                }
                write!(slot, *head + 1);
            }
            self.at("read");
            if writes.is_empty() {
                return Some(Committed { sequence, counts });
            }
            writes.sort_unstable();
            let mut fresh = Vec::new();
            if !arena
                .blocks
                .acquire_many(self.nodes_for(&writes), &mut fresh)
            {
                for (_, _, head, _, _) in offered {
                    arena.discard(head);
                }
                arena.refuse_record();
                return None;
            }
            let acquired = fresh.clone();
            let mut replaced = Vec::new();
            let built = arena.tree_put(root, self.top_span, 0, &writes, &mut fresh, &mut replaced);
            self.at("install");
            if let Some(built) = built
                && self
                    .cell
                    .compare_exchange(word, next_tag(word) | built, ORD, ORD)
                    .is_ok()
            {
                arena.blocks.release_many(&fresh);
                for head in displaced {
                    replaced.extend(arena.chain(head));
                }
                arena.retire(&replaced);
                self.at("installed");
                return Some(Committed { sequence, counts });
            }
            arena.blocks.release_many(&acquired);
        }
    }

    /// The current state, with every retained record, or `None` if every
    /// reader cell of the arena is taken: the read is then refused and
    /// counted in [`reads_refused`], and the caller must report the state
    /// as unavailable, never as empty.
    ///
    /// One pass: the reader announces itself, loads the root, and copies
    /// the state and its records, none of which can be recycled until it is
    /// done.  No recorder can make it repeat anything.  When it finishes it
    /// helps reclaim at most one bounded batch of parked blocks.
    pub(crate) fn read(&self, arena: &Arena) -> Option<LedgerView> {
        let Some(_reading) = arena.announce() else {
            bump(&READS_REFUSED);
            return None;
        };
        #[cfg(test)]
        bump(&self.passes);
        let mut words = vec![0_u64; self.total];
        let mut retained = Vec::new();
        let root = self.cell.load(ORD) & INDEX_MASK;
        arena.tree_fill(root, self.top_span, 0, &mut words);
        for (group, (base, capacity)) in self.groups.iter().enumerate() {
            let held = words.get(base + 1..base + 1 + capacity).unwrap_or(&[]);
            for head in held.iter().filter_map(|word| word.checked_sub(1)) {
                let Some(record) = arena.load(head, || true) else {
                    continue;
                };
                retained.push(Retained {
                    group,
                    order: record.first().copied().unwrap_or(0),
                    record: WordReader {
                        words: record,
                        at: 1,
                    },
                });
            }
        }
        retained.sort_by_key(|retained| (retained.group, retained.order));
        words.truncate(self.counters);
        Some(LedgerView {
            counts: words,
            retained,
        })
    }
}

/// Encodes one record's fields as words.
pub(crate) struct WordWriter(Vec<u64>);

impl WordWriter {
    pub(crate) fn new() -> Self {
        Self(Vec::new())
    }

    pub(crate) fn u64(&mut self, value: u64) {
        self.0.push(value);
    }

    pub(crate) fn size(&mut self, value: usize) {
        self.0.push(value as u64);
    }

    pub(crate) fn flag(&mut self, value: bool) {
        self.0.push(u64::from(value));
    }

    pub(crate) fn opt_u64(&mut self, value: Option<u64>) {
        self.flag(value.is_some());
        self.0.push(value.unwrap_or(0));
    }

    pub(crate) fn uuid(&mut self, value: Uuid) {
        let (high, low) = value.as_u64_pair();
        self.0.push(high);
        self.0.push(low);
    }

    pub(crate) fn opt_uuid(&mut self, value: Option<Uuid>) {
        self.flag(value.is_some());
        self.uuid(value.unwrap_or_default());
    }

    pub(crate) fn text(&mut self, value: &str) {
        self.0.push(value.len() as u64);
        for chunk in value.as_bytes().chunks(8) {
            let mut bytes = [0_u8; 8];
            for (target, source) in bytes.iter_mut().zip(chunk) {
                *target = *source;
            }
            self.0.push(u64::from_le_bytes(bytes));
        }
    }

    pub(crate) fn opt_text(&mut self, value: Option<&str>) {
        self.flag(value.is_some());
        self.text(value.unwrap_or(""));
    }

    pub(crate) fn label<const N: usize>(&mut self, table: &LabelTable<N>, value: &'static str) {
        self.0.push(table.index(value));
    }

    pub(crate) fn opt_label<const N: usize>(
        &mut self,
        table: &LabelTable<N>,
        value: Option<&'static str>,
    ) {
        self.flag(value.is_some());
        self.0.push(value.map_or(0, |value| table.index(value)));
    }
}

/// Decodes one record's fields in the order they were written.
pub(crate) struct WordReader {
    words: Vec<u64>,
    at: usize,
}

impl WordReader {
    pub(crate) fn u64(&mut self) -> Option<u64> {
        let value = self.words.get(self.at).copied()?;
        self.at += 1;
        Some(value)
    }

    pub(crate) fn size(&mut self) -> Option<usize> {
        usize::try_from(self.u64()?).ok()
    }

    pub(crate) fn flag(&mut self) -> Option<bool> {
        Some(self.u64()? != 0)
    }

    pub(crate) fn opt_u64(&mut self) -> Option<Option<u64>> {
        let present = self.flag()?;
        let value = self.u64()?;
        Some(present.then_some(value))
    }

    pub(crate) fn uuid(&mut self) -> Option<Uuid> {
        let high = self.u64()?;
        let low = self.u64()?;
        Some(Uuid::from_u64_pair(high, low))
    }

    pub(crate) fn opt_uuid(&mut self) -> Option<Option<Uuid>> {
        let present = self.flag()?;
        let value = self.uuid()?;
        Some(present.then_some(value))
    }

    pub(crate) fn text(&mut self) -> Option<String> {
        let length = self.size()?;
        let mut bytes = Vec::with_capacity(length);
        for _ in 0..length.div_ceil(8) {
            bytes.extend_from_slice(&self.u64()?.to_le_bytes());
        }
        bytes.truncate(length);
        String::from_utf8(bytes).ok()
    }

    pub(crate) fn opt_text(&mut self) -> Option<Option<String>> {
        let present = self.flag()?;
        let value = self.text()?;
        Some(present.then_some(value))
    }

    pub(crate) fn label<const N: usize>(&mut self, table: &LabelTable<N>) -> Option<&'static str> {
        table.label(self.u64()?)
    }

    pub(crate) fn opt_label<const N: usize>(
        &mut self,
        table: &LabelTable<N>,
    ) -> Option<Option<&'static str>> {
        let present = self.flag()?;
        let index = self.u64()?;
        if present {
            table.label(index).map(Some)
        } else {
            Some(None)
        }
    }
}

/// The label reported for a static label that did not fit a table.
pub(crate) const OVERFLOW_LABEL: &str = "other";

/// A set-once table giving each distinct static label a small index.
///
/// The labels recorded by the relay are closed vocabularies, so the table
/// fills once and is then read-only.  A label beyond the capacity is
/// reported as [`OVERFLOW_LABEL`] and counted in [`Self::overflowed`]; a
/// debug build asserts instead, because it means the table is too small for
/// the vocabulary.
pub(crate) struct LabelTable<const N: usize> {
    labels: [OnceLock<&'static str>; N],
    overflowed: AtomicU64,
}

impl<const N: usize> LabelTable<N> {
    pub(crate) const fn new() -> Self {
        Self {
            labels: [const { OnceLock::new() }; N],
            overflowed: AtomicU64::new(0),
        }
    }

    /// The index of `label`, assigning the next free one on first use.
    pub(crate) fn index(&self, label: &'static str) -> u64 {
        match self.assign(label) {
            Some(index) => index,
            None => {
                debug_assert!(false, "label table of {N} entries is full: {label}");
                N as u64
            }
        }
    }

    fn assign(&self, label: &'static str) -> Option<u64> {
        for (index, entry) in self.labels.iter().enumerate() {
            if *entry.get_or_init(|| label) == label {
                return Some(index as u64);
            }
        }
        bump(&self.overflowed);
        None
    }

    /// The label an index names.
    pub(crate) fn label(&self, index: u64) -> Option<&'static str> {
        let index = usize::try_from(index).ok()?;
        if index == N {
            return Some(OVERFLOW_LABEL);
        }
        self.labels.get(index)?.get().copied()
    }

    /// One more than the largest index, counting the overflow index.
    pub(crate) const fn indices(&self) -> usize {
        N + 1
    }

    /// How many times a label did not fit and was reported as
    /// [`OVERFLOW_LABEL`].
    pub(crate) fn overflowed(&self) -> u64 {
        read(&self.overflowed)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    use super::*;

    /// A cap no test reaches, so a stress test measures the property it
    /// names and not the budget; chunks are still allocated only as used.
    const ROOMY: usize = 1 << 22;

    fn state_of(ledger: &Ledger, arena: &Arena) -> LedgerView {
        ledger.read(arena).expect("a reader cell is free")
    }

    fn record(order: u64, text: &str) -> WordWriter {
        let mut writer = WordWriter::new();
        writer.u64(order);
        writer.text(text);
        writer.opt_text(None);
        writer.opt_u64(Some(order));
        writer.uuid(Uuid::from_u128(u128::from(order)));
        writer
    }

    fn text_for(order: u64) -> String {
        format!("event-{order}-{}", "x".repeat((order % 90) as usize))
    }

    /// Every field must describe the order the record was written for.
    fn check(mut reader: WordReader) -> u64 {
        let order = reader.u64().expect("order decodes");
        assert_eq!(reader.text().as_deref(), Some(text_for(order).as_str()));
        assert_eq!(reader.opt_text(), Some(None));
        assert_eq!(reader.opt_u64(), Some(Some(order)));
        assert_eq!(reader.uuid(), Some(Uuid::from_u128(u128::from(order))));
        assert_eq!(reader.u64(), None);
        order
    }

    fn park(steps: &Arc<AtomicU64>, every: u64) -> CommitHook {
        let steps = Arc::clone(steps);
        Box::new(move |_step| {
            // Park a recorder between its steps: usually a yield, and every
            // so often long enough for many reads to pass.
            if steps.fetch_add(1, ORD).is_multiple_of(every) {
                std::thread::sleep(std::time::Duration::from_micros(300));
            } else {
                std::thread::yield_now();
            }
        })
    }

    #[test]
    fn locate_covers_the_index_space_without_gaps() {
        let mut expected = (0_usize, 0_usize);
        for index in 0..5_000_u64 {
            assert_eq!(locate(index), expected);
            expected.1 += 1;
            if expected.1 == CHUNK_NODES {
                expected = (expected.0 + 1, 0);
            }
        }
    }

    /// A pool hands out exactly as many nodes as its cap allows, a chunk at
    /// a time, and none after.
    #[test]
    fn a_pool_never_grows_past_its_cap() {
        let cap = CHUNK_NODES + 7;
        let pool = Pool::<WordBlock>::new(cap);
        let mut taken = Vec::new();
        assert!(pool.acquire_many(cap, &mut taken));
        assert_eq!(pool.acquire(), None);
        let mut more = Vec::new();
        assert!(!pool.acquire_many(1, &mut more));
        assert_eq!(pool.allocated(), cap as u64);
        assert!(taken.iter().all(|index| pool.node(*index).is_some()));
        assert!(pool.node(cap as u64).is_none());
        pool.release(taken[3]);
        assert_eq!(pool.acquire(), Some(taken[3]));
        assert_eq!(pool.allocated(), cap as u64);
    }

    /// With a reader holding back every unlinked block, a small arena
    /// reaches its cap: commits are then refused and counted, nothing is
    /// allocated past the cap, the state stays exactly the commits that
    /// were accepted, and recording resumes once the reader is gone.
    #[test]
    fn an_arena_at_its_cap_refuses_and_counts_commits() {
        const CAP: usize = 96;
        let arena = Arena::new(CAP);
        let ledger = Ledger::new(1, &[4]);
        let commit = |round: u64| {
            ledger.commit(
                &arena,
                None,
                &[0],
                vec![Entry {
                    place: Place::Push(0),
                    order: Order::Count(0),
                    record: record(round, &text_for(round)),
                }],
            )
        };
        let stalled = arena.announce().expect("a reader cell is free");
        let mut accepted = 0_u64;
        let mut refused = 0_u64;
        for round in 0..200 {
            match commit(round) {
                Some(committed) => {
                    accepted += 1;
                    assert_eq!(committed.counts, [accepted]);
                }
                None => refused += 1,
            }
        }
        assert!(accepted > 0 && refused > 0, "{accepted} {refused}");
        assert_eq!(arena.dropped(), refused);
        assert!(records_dropped() >= refused);
        assert!(arena.allocated() <= CAP as u64);
        let seen = state_of(&ledger, &arena);
        assert_eq!(seen.count(0), accepted);
        let orders: Vec<u64> = seen.retained.iter().map(|r| r.order).collect();
        let expected: Vec<u64> = (accepted.saturating_sub(3).max(1)..=accepted).collect();
        assert_eq!(orders, expected);
        drop(stalled);
        while arena.has_parked() {
            state_of(&ledger, &arena);
        }
        for round in 0..200 {
            assert!(commit(round).is_some());
        }
        assert_eq!(state_of(&ledger, &arena).count(0), accepted + 200);
        assert_eq!(arena.dropped(), refused);
        assert!(arena.allocated() <= CAP as u64);
    }

    /// With every reader cell taken a read is refused and counted -- it is
    /// not an empty state -- and succeeds again once a cell is free.
    #[test]
    fn a_read_is_refused_when_every_reader_cell_is_taken() {
        let arena = Arena::new(ROOMY);
        let ledger = Ledger::new(2, &[2]);
        assert!(ledger.commit(&arena, None, &[1], Vec::new()).is_some());
        let mut held = arena.occupy_readers();
        assert_eq!(held.len(), READER_CELLS);
        let before = reads_refused();
        assert!(ledger.read(&arena).is_none());
        assert!(reads_refused() > before);
        // Recording is unaffected.
        assert!(ledger.commit(&arena, None, &[1], Vec::new()).is_some());
        held.pop();
        assert_eq!(state_of(&ledger, &arena).counts, [0, 2]);
        drop(held);
        assert_eq!(arena.occupy_readers().len(), READER_CELLS);
    }

    #[test]
    fn nodes_are_taken_and_returned_in_batches() {
        let pool = Pool::<WordBlock>::new(ROOMY);
        let mut taken = Vec::new();
        assert!(pool.acquire_many(40, &mut taken));
        let mut distinct = taken.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), 40);
        pool.release_many(&taken);
        let mut again = Vec::new();
        assert!(pool.acquire_many(25, &mut again));
        assert!(pool.acquire_many(25, &mut again));
        let mut distinct = again.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), 50);
        // Forty were reused; ten are new.
        assert_eq!(pool.allocated(), 50);
    }

    #[test]
    fn a_slot_round_trips_a_record_across_blocks_and_recycles() {
        let arena = Arena::new(ROOMY);
        let slot = Slot::default();
        assert!(slot.read(&arena).is_none());
        for order in 0..2_000 {
            slot.set(&arena, record(order, &text_for(order)));
        }
        assert_eq!(slot.read(&arena).map(check), Some(1_999));
        assert!(arena.allocated() < 64, "{}", arena.allocated());
        slot.clear(&arena);
        assert!(slot.read(&arena).is_none());
    }

    #[test]
    fn a_ledger_counts_rings_and_keys_in_one_state() {
        let arena = Arena::new(ROOMY);
        let clock = AtomicU64::new(0);
        // 700 counters put the groups several tree levels down.
        let ledger = Ledger::new(700, &[3, 2]);
        let empty = state_of(&ledger, &arena);
        assert_eq!(empty.counts.len(), 700);
        assert!(empty.counts.iter().all(|count| *count == 0));
        assert!(empty.retained.is_empty());
        for round in 1..=6_u64 {
            let cell = 100 * (round as usize);
            let committed = ledger
                .commit(
                    &arena,
                    Some(&clock),
                    &[cell, 699],
                    vec![
                        Entry {
                            place: Place::Push(0),
                            order: Order::Sequence,
                            record: record(round, &text_for(round)),
                        },
                        Entry {
                            place: Place::Key(1, (round % 2) as usize),
                            order: Order::Count(699),
                            record: record(round, &text_for(round)),
                        },
                    ],
                )
                .expect("commit installs");
            assert_eq!(committed.sequence, round);
            assert_eq!(committed.counts, [1, round]);
        }
        let view = state_of(&ledger, &arena);
        assert_eq!(view.count(699), 6);
        assert_eq!(view.counts.iter().sum::<u64>(), 12);
        for round in 1..=6 {
            assert_eq!(view.count(100 * round), 1);
        }
        let kept: Vec<(usize, u64)> = view
            .retained
            .iter()
            .map(|retained| (retained.group, retained.order))
            .collect();
        // The ring keeps the three newest commits; each key its latest.
        assert_eq!(kept, [(0, 4), (0, 5), (0, 6), (1, 5), (1, 6)]);
        for retained in view.retained {
            let round = check(retained.record);
            assert_eq!(round, retained.order);
        }
        // Six commits of a 700-counter state reuse a few dozen blocks.
        assert!(arena.allocated() < 96, "{}", arena.allocated());
        assert_eq!(arena.dropped(), 0);
    }

    #[test]
    fn labels_are_indexed_by_content_and_overflow_is_counted() {
        let table = LabelTable::<2>::new();
        assert_eq!(table.index("fin"), 0);
        assert_eq!(table.index("reset"), 1);
        assert_eq!(table.index("fin"), 0);
        assert_eq!(table.overflowed(), 0);
        assert_eq!(table.assign("closed"), None);
        assert_eq!(table.overflowed(), 1);
        assert_eq!(table.label(1), Some("reset"));
        assert_eq!(table.label(2), Some(OVERFLOW_LABEL));
        assert_eq!(table.label(3), None);
        assert_eq!(table.indices(), 3);
    }

    /// Recorders on several threads, parked at every step of their commits,
    /// against a reader that samples continuously.  In every state the
    /// reader returns, the count is exactly the number of commits it
    /// reflects: the ring holds records `count - 2 ..= count` and nothing
    /// else, the breakdown sums to the total, and every record is whole.
    #[test]
    fn parked_recorders_never_expose_a_count_without_its_records() {
        const WRITERS: u64 = 4;
        const PER_WRITER: u64 = 3_000;
        let arena = Arc::new(Arena::new(ROOMY));
        let ledger = Arc::new(Ledger::new(3, &[3]));
        let steps = Arc::new(AtomicU64::new(0));
        ledger.park_commits(park(&steps, 97));
        let writers: Vec<_> = (0..WRITERS)
            .map(|writer| {
                let (arena, ledger) = (Arc::clone(&arena), Arc::clone(&ledger));
                std::thread::spawn(move || {
                    for _ in 0..PER_WRITER {
                        // Counter 0 is the total; 1 and 2 break it down.
                        let part = 1 + usize::from(writer % 2 == 1);
                        let committed = ledger.commit(
                            &arena,
                            None,
                            &[0, part],
                            vec![Entry {
                                place: Place::Push(0),
                                order: Order::Count(0),
                                record: WordWriter::new(),
                            }],
                        );
                        assert!(committed.is_some());
                    }
                })
            })
            .collect();
        let verify = |view: LedgerView| {
            let total = view.count(0);
            assert_eq!(view.count(1) + view.count(2), total);
            let orders: Vec<u64> = view.retained.iter().map(|r| r.order).collect();
            let expected: Vec<u64> = (total.saturating_sub(2).max(1)..=total).collect();
            assert_eq!(orders, expected, "count {total}");
            total
        };
        let mut last = 0;
        let mut samples = 0_u64;
        while writers.iter().any(|writer| !writer.is_finished()) {
            let total = verify(state_of(&ledger, &arena));
            assert!(total >= last, "count went backwards");
            last = total;
            samples += 1;
        }
        for writer in writers {
            writer.join().expect("recorder finishes");
        }
        assert!(samples > 0);
        assert_eq!(verify(state_of(&ledger, &arena)), WRITERS * PER_WRITER);
        // Storage followed the recorders in flight, not the event count.
        assert!(arena.allocated() < 4_096, "{}", arena.allocated());
    }

    /// Records with real content committed concurrently are always read
    /// whole, sequences follow commit order, and the ring keeps the newest.
    #[test]
    fn concurrent_commits_never_expose_a_torn_record() {
        const WRITERS: u64 = 4;
        const PER_WRITER: u64 = 5_000;
        let arena = Arc::new(Arena::new(ROOMY));
        let ledger = Arc::new(Ledger::new(1, &[5]));
        let writers: Vec<_> = (0..WRITERS)
            .map(|writer| {
                let (arena, ledger) = (Arc::clone(&arena), Arc::clone(&ledger));
                std::thread::spawn(move || {
                    for round in 0..PER_WRITER {
                        let label = writer * PER_WRITER + round;
                        ledger.commit(
                            &arena,
                            None,
                            &[0],
                            vec![Entry {
                                place: Place::Push(0),
                                order: Order::Count(0),
                                record: record(label, &text_for(label)),
                            }],
                        );
                    }
                })
            })
            .collect();
        let verify = |view: LedgerView| {
            let total = view.count(0);
            let orders: Vec<u64> = view.retained.iter().map(|r| r.order).collect();
            let expected: Vec<u64> = (total.saturating_sub(4).max(1)..=total).collect();
            assert_eq!(orders, expected);
            for retained in view.retained {
                check(retained.record);
            }
            total
        };
        while writers.iter().any(|writer| !writer.is_finished()) {
            verify(state_of(&ledger, &arena));
        }
        for writer in writers {
            writer.join().expect("recorder finishes");
        }
        assert_eq!(verify(state_of(&ledger, &arena)), WRITERS * PER_WRITER);
    }

    /// Recorders commit without pause for as long as two readers are
    /// reading.  Every read finishes in exactly one pass over one state --
    /// no recorder can make a reader repeat anything -- and every state is
    /// consistent.
    #[test]
    fn a_reader_under_continuous_commits_finishes_in_one_pass() {
        const READS: u64 = 20_000;
        let arena = Arc::new(Arena::new(ROOMY));
        let clock = Arc::new(AtomicU64::new(0));
        let ledger = Arc::new(Ledger::new(600, &[32, 11]));
        let stop = Arc::new(AtomicBool::new(false));
        let writers: Vec<_> = (0..4_usize)
            .map(|writer| {
                let (arena, ledger, clock, stop) = (
                    Arc::clone(&arena),
                    Arc::clone(&ledger),
                    Arc::clone(&clock),
                    Arc::clone(&stop),
                );
                std::thread::spawn(move || {
                    let mut round = writer;
                    let mut commits = 0_u64;
                    while !stop.load(ORD) {
                        round += 7;
                        let committed = ledger.commit(
                            &arena,
                            Some(&clock),
                            &[round % 600],
                            vec![
                                Entry {
                                    place: Place::Push(0),
                                    order: Order::Sequence,
                                    record: record(round as u64, &text_for(round as u64)),
                                },
                                Entry {
                                    place: Place::Key(1, round % 11),
                                    order: Order::Sequence,
                                    record: record(round as u64, &text_for(round as u64)),
                                },
                            ],
                        );
                        assert!(committed.is_some());
                        commits += 1;
                    }
                    commits
                })
            })
            .collect();
        let readers: Vec<_> = (0..2)
            .map(|_| {
                let (arena, ledger) = (Arc::clone(&arena), Arc::clone(&ledger));
                std::thread::spawn(move || {
                    let mut last = 0;
                    for _ in 0..READS {
                        let view = state_of(&ledger, &arena);
                        let total: u64 = view.counts.iter().sum();
                        assert!(total >= last);
                        last = total;
                        let ring: Vec<u64> = view
                            .retained
                            .iter()
                            .filter(|retained| retained.group == 0)
                            .map(|retained| retained.order)
                            .collect();
                        assert_eq!(ring.len() as u64, total.min(32));
                        assert!(ring.windows(2).all(|pair| pair[0] < pair[1]));
                        // The newest ring entry is some key's latest entry.
                        let newest = ring.last().copied();
                        let latest = view
                            .retained
                            .iter()
                            .filter(|retained| retained.group == 1)
                            .map(|retained| retained.order)
                            .max();
                        assert_eq!(newest, latest);
                        for retained in view.retained {
                            check(retained.record);
                        }
                    }
                })
            })
            .collect();
        for reader in readers {
            reader.join().expect("reader finishes");
        }
        // The recorders were still committing when the last read returned.
        assert!(writers.iter().all(|writer| !writer.is_finished()));
        stop.store(true, ORD);
        let commits: u64 = writers
            .into_iter()
            .map(|writer| writer.join().expect("recorder finishes"))
            .sum();
        assert!(commits > 0);
        assert_eq!(ledger.read_passes(), 2 * READS);
        let view = state_of(&ledger, &arena);
        assert_eq!(view.counts.iter().sum::<u64>(), commits);
        // Blocks unlinked while a reader was reading were parked, so the
        // high-water mark follows the commits made during the slowest read;
        // nothing stays parked once the readers are gone, and recording on
        // from here allocates nothing more.
        // Each finished read reclaims one bounded batch.
        let mut reads = 0_u64;
        while arena.has_parked() {
            state_of(&ledger, &arena);
            reads += 1;
            assert!(reads <= arena.allocated(), "parked blocks never drain");
        }
        let settled = arena.allocated();
        for round in 0..5_000_usize {
            let committed = ledger.commit(
                &arena,
                Some(&clock),
                &[round % 600],
                vec![Entry {
                    place: Place::Push(0),
                    order: Order::Sequence,
                    record: record(round as u64, &text_for(round as u64)),
                }],
            );
            assert!(committed.is_some());
            if round % 50 == 0 {
                state_of(&ledger, &arena);
            }
        }
        assert!(!arena.has_parked());
        assert_eq!(arena.allocated(), settled);
        assert_eq!(arena.dropped(), 0);
    }
}
