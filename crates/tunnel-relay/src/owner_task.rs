//! Lazily started owning tasks.
//!
//! Shared mutable state in this crate is owned by one task and reached over
//! a bounded command channel.  Several owners are constructed by
//! synchronous constructors that may run outside a Tokio runtime, so the
//! owning task is started by the first asynchronous caller instead.  The
//! task ends when the last handle is dropped and its command channel closes.

use std::{fmt, future::Future, sync::OnceLock};

use tokio::sync::{mpsc, oneshot};

/// The command channel of one owning task, started on first use.
pub(crate) struct OwnerTask<C> {
    sender: OnceLock<mpsc::Sender<C>>,
}

impl<C> fmt::Debug for OwnerTask<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnerTask")
            .field("started", &self.sender.get().is_some())
            .finish()
    }
}

impl<C: Send + 'static> OwnerTask<C> {
    pub(crate) const fn new() -> Self {
        Self {
            sender: OnceLock::new(),
        }
    }

    /// The command sender, starting the owning task with `run` if no caller
    /// has yet.  Must be called inside a Tokio runtime.  `capacity` bounds
    /// the queue; a sender waits while it is full.
    fn sender<F, Fut>(&self, capacity: usize, run: F) -> &mpsc::Sender<C>
    where
        F: FnOnce(mpsc::Receiver<C>) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.sender.get_or_init(|| {
            let (sender, receiver) = mpsc::channel(capacity);
            tokio::spawn(run(receiver));
            sender
        })
    }

    /// Queue one command that needs no answer.  `false` means the owning
    /// task is gone (its runtime shut down) and the command was dropped.
    pub(crate) async fn send<F, Fut>(&self, capacity: usize, run: F, command: C) -> bool
    where
        F: FnOnce(mpsc::Receiver<C>) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.sender(capacity, run).send(command).await.is_ok()
    }

    /// Queue one command and wait for the owner's answer.  `None` means the
    /// owning task is gone and nothing answered.
    pub(crate) async fn request<R, F, Fut>(
        &self,
        capacity: usize,
        run: F,
        command: impl FnOnce(oneshot::Sender<R>) -> C,
    ) -> Option<R>
    where
        F: FnOnce(mpsc::Receiver<C>) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let (reply, answer) = oneshot::channel();
        if !self.send(capacity, run, command(reply)).await {
            return None;
        }
        answer.await.ok()
    }
}
