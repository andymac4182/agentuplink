/** One monotonic budget for a public filesystem operation and all its children. */
import { performance } from 'node:perf_hooks';
import type { Limits } from './descriptor.ts';
import { FilesystemError } from './errors.ts';

export interface OperationOptions {
  signal?: AbortSignal | undefined;
  /** Milliseconds; defaults to the descriptor's operation bound, never above its maximum. */
  timeoutMs?: number | undefined;
}

// Trusted host bookkeeping must not read a script's patched global clock.
// Capturing only this function keeps just-bash's timing restriction intact;
// no extra defense-in-depth exclusion or clock handle is exposed to scripts.
const monotonicNow = performance.now.bind(performance);

type Cancellation = 'ABORTED' | 'DEADLINE_EXCEEDED';
const scopes = new WeakMap<AbortSignal, OperationDeadline>();

class OperationDeadline {
  readonly controller = new AbortController();
  readonly expiresAt: number;
  private readonly caller: AbortSignal | undefined;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private cause: Cancellation | undefined;
  private readonly onCallerAbort = (): void => { this.cancel('ABORTED'); };

  constructor(timeoutMs: number, caller: AbortSignal | undefined) {
    this.expiresAt = monotonicNow() + timeoutMs;
    this.caller = caller;
    scopes.set(this.controller.signal, this);
    if (caller?.aborted === true) {
      this.cancel('ABORTED');
    } else {
      caller?.addEventListener('abort', this.onCallerAbort, { once: true });
      this.timer = setTimeout(() => { this.cancel('DEADLINE_EXCEEDED'); }, timeoutMs);
      this.timer.unref?.();
    }
  }

  get cancellation(): Cancellation | undefined {
    // The event loop may deliver timers late. Application dispatch checks the
    // monotonic clock too. Once caller abort wins, a later deadline cannot
    // change the reason or defeat the original-reply-before-Rflush rule.
    if (this.cause === undefined && monotonicNow() >= this.expiresAt) {
      this.cancel('DEADLINE_EXCEEDED');
    }
    return this.cause;
  }

  private cancel(cause: Cancellation): void {
    if (this.cause !== undefined) return;
    this.cause = cause;
    this.dispose();
    this.controller.abort();
  }

  dispose(): void {
    clearTimeout(this.timer);
    this.caller?.removeEventListener('abort', this.onCallerAbort);
  }
}

export function operationCancellation(signal: AbortSignal | undefined): Cancellation | undefined {
  if (signal === undefined) return undefined;
  return scopes.get(signal)?.cancellation ?? (signal.aborted ? 'ABORTED' : undefined);
}

export function throwIfOperationCancelled(signal: AbortSignal | undefined, operation: string): void {
  const code = operationCancellation(signal);
  if (code !== undefined) {
    throw new FilesystemError({ code, operation, outcome: 'not_started', retryable: false });
  }
}

function enter<T extends OperationOptions>(options: T, limits: Limits, operation: string) {
  const timeoutMs = options.timeoutMs === undefined
    ? limits.defaultOperationTimeoutSeconds * 1000 : options.timeoutMs;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > limits.maxOperationTimeoutSeconds * 1000) {
    throw new FilesystemError({ code: 'EINVAL', operation, outcome: 'not_started', retryable: false });
  }
  const inherited = options.signal === undefined ? undefined : scopes.get(options.signal);
  const scope = inherited ?? new OperationDeadline(timeoutMs, options.signal);
  return {
    options: { ...options, signal: scope.controller.signal },
    dispose: (): void => { if (inherited === undefined) scope.dispose(); },
  };
}

export async function runOperation<T extends OperationOptions, R>(
  options: T, limits: Limits, operation: string,
  run: (options: T & { signal: AbortSignal }) => Promise<R>,
): Promise<R> {
  const entered = enter(options, limits, operation);
  try {
    throwIfOperationCancelled(entered.options.signal, operation);
    return await run(entered.options);
  } finally {
    entered.dispose();
  }
}

/** The budget starts on first next(), and includes pauses between subsequent next() calls. */
export async function* streamOperation<T extends OperationOptions, R>(
  options: T, limits: Limits, operation: string,
  run: (options: T & { signal: AbortSignal }) => AsyncGenerator<R>,
): AsyncGenerator<R> {
  const entered = enter(options, limits, operation);
  const signal = entered.options.signal;
  const iterator = run(entered.options);
  // Return the inner generator even while its consumer is paused at a yield;
  // its finally owns fid cleanup. If next() is pending, return queues behind
  // it, while the session flush/expiry settles the outstanding request.
  const onAbort = (): void => { void iterator.return(undefined).catch(() => {}); };
  signal.addEventListener('abort', onAbort, { once: true });
  try {
    for (;;) {
      throwIfOperationCancelled(signal, operation);
      const next = await iterator.next();
      if (next.done) return;
      yield next.value;
    }
  } finally {
    signal.removeEventListener('abort', onAbort);
    try { await waitForCleanup(iterator.return(undefined), signal); }
    finally { entered.dispose(); }
  }
}

/** Only caller-owned producer waits are raced; application requests keep their outcome accounting. */
export function waitForSource<T>(pending: PromiseLike<T>, signal: AbortSignal | undefined, operation: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void => {
      try { throwIfOperationCancelled(signal, operation); } catch (error) { reject(error); }
    };
    const remove = (): void => { signal?.removeEventListener('abort', onAbort); };
    // Always observe late rejection, including an already-cancelled source.
    Promise.resolve(pending).then((value) => { remove(); resolve(value); }, (error: unknown) => { remove(); reject(error); });
    signal?.addEventListener('abort', onAbort, { once: true });
    if (operationCancellation(signal) !== undefined) { remove(); onAbort(); }
  });
}

/** Cleanup keeps its own bounded request and ownership; cancellation only stops waiting for it. */
export function waitForCleanup(pending: PromiseLike<unknown>, signal: AbortSignal | undefined): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    const onAbort = (): void => { remove(); resolve(); };
    const remove = (): void => { signal?.removeEventListener('abort', onAbort); };
    Promise.resolve(pending).then(() => { remove(); resolve(); }, (error: unknown) => { remove(); reject(error); });
    signal?.addEventListener('abort', onAbort, { once: true });
    if (operationCancellation(signal) !== undefined) onAbort();
  });
}
