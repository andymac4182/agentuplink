/** C244 real-endpoint driver. Holds actual inbound replies in order; invents none. */
import { readFile } from 'node:fs/promises';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import {
  ConsumerSession, FilesystemError, attachSession, fetchDescriptor, upgrade,
  type BinaryTransport,
} from '../src/index.ts';
import type { Message } from '../src/ninep/messages.ts';
import { GRANT_REVISION_HEADER, SUBPROTOCOL } from '../src/descriptor.ts';
import { decodeExact } from '../src/ninep/codec.ts';
import { GETATTR_BASIC } from '../src/ninep/constants.ts';

const WAIT_MS = 10_000;
const OPERATION_MS = 2_000;
const MAX_EVENTS = 128;
const MAX_HELD_BYTES = 65_536;
type Case = 'walk' | 'clunk';
interface Plan { endpoint: string; token: string }
interface Wire { sequence: number; message: Message }
interface Failure { code: string; outcome: string; retryable: boolean }
type Outcome<T> = { ok: true; value: T } | { ok: false; failure: Failure };
let phase = 'startup';

function report(value: object): void { process.stdout.write(`${JSON.stringify(value)}\n`); }
function failure(error: unknown): Failure {
  return error instanceof FilesystemError
    ? { code: error.code, outcome: error.outcome, retryable: error.retryable }
    : { code: 'driver-error', outcome: 'unknown', retryable: false };
}
function observe<T>(promise: Promise<T>): Promise<Outcome<T>> {
  return promise.then((value): Outcome<T> => ({ ok: true, value }), (error: unknown): Outcome<T> => ({ ok: false, failure: failure(error) }));
}
async function bounded<T>(promise: Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([promise, new Promise<never>((_, reject) => {
      timer = setTimeout(() => { reject(new Error('driver-deadline')); }, WAIT_MS);
    })]);
  } finally { clearTimeout(timer); }
}
async function until<T>(read: () => T | undefined): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const stop = setTimeout(() => { clearTimeout(timer); reject(new Error('driver-observation-deadline')); }, WAIT_MS);
    const poll = (): void => {
      try {
        const value = read();
        if (value !== undefined) { clearTimeout(stop); resolve(value); return; }
        timer = setTimeout(poll, 5);
      } catch { clearTimeout(stop); reject(new Error('driver-observation')); }
    };
    poll();
  });
}

class OrderedWire {
  readonly sent: Wire[] = [];
  readonly received: Wire[] = [];
  readonly delivered: Wire[] = [];
  private counter = 0;
  private holdKind: 'Rwalk' | 'Rclunk' | undefined;
  private holding = false;
  private held: { bytes: Uint8Array; message: Message }[] = [];
  private heldBytes = 0;
  session: ConsumerSession | undefined;
  socket: BinaryTransport | undefined;
  fault: string | undefined;
  unexpectedCloses = 0;
  closing = false;

  tick(): number { this.counter += 1; return this.counter; }
  arm(kind: 'Rwalk' | 'Rclunk'): void { this.holdKind = kind; }
  note(events: Wire[], message: Message): void {
    if (events.length >= MAX_EVENTS) throw new Error('wire-event-bound');
    events.push({ sequence: this.tick(), message });
  }
  send(bytes: Uint8Array): void {
    this.note(this.sent, decodeExact(bytes));
    if (this.socket === undefined) throw new Error('socket-absent');
    this.socket.send(bytes);
  }
  receive(bytes: Uint8Array): void {
    try {
      const message = decodeExact(bytes);
      this.note(this.received, message);
      if (message.kind === this.holdKind) { this.holding = true; this.holdKind = undefined; }
      if (this.holding) {
        if (this.held.length >= 16 || this.heldBytes + bytes.byteLength > MAX_HELD_BYTES) throw new Error('hold-bound');
        this.held.push({ bytes: bytes.slice(), message });
        this.heldBytes += bytes.byteLength;
      } else {
        this.note(this.delivered, message);
        this.session?.onMessage(bytes);
      }
    } catch {
      this.fault = 'wire-observation';
      this.socket?.close(1002, 'fixture-bound');
    }
  }
  release(): void {
    this.holding = false;
    const held = this.held;
    this.held = [];
    this.heldBytes = 0;
    for (const { bytes, message } of held) {
      this.note(this.delivered, message);
      this.session?.onMessage(bytes);
    }
  }
  event(events: Wire[], kind: Message['kind'], tag?: number): Wire | undefined {
    if (this.fault !== undefined) throw new Error('wire-fault');
    return events.find((event) => event.message.kind === kind && (tag === undefined || event.message.tag === tag));
  }
}

async function connect(plan: Plan) {
  const descriptor = await fetchDescriptor({ endpoint: plan.endpoint, token: () => plan.token });
  const wire = new OrderedWire();
  const socket = await upgrade({
    url: new URL(plan.endpoint), subprotocol: SUBPROTOCOL,
    headers: { Authorization: `Bearer ${plan.token}`, [GRANT_REVISION_HEADER]: descriptor.grantRevision },
    maxMessageBytes: descriptor.limits.maxMessageBytes,
    timeoutMs: descriptor.limits.requestTimeoutSeconds * 1000,
    handlers: {
      onMessage: (bytes) => { wire.receive(bytes); },
      onClose: (info) => {
        if (!wire.closing) wire.unexpectedCloses += 1;
        wire.session?.onClose(info);
      },
    },
  });
  wire.socket = socket;
  const transport: BinaryTransport = {
    get isOpen() { return socket.isOpen; },
    send: (bytes) => { wire.send(bytes); },
    close: (code, reason) => { socket.close(code, reason); },
  };
  const session = new ConsumerSession(transport, {
    msize: descriptor.limits.maxMessageBytes, maxInflightRequests: descriptor.limits.maxInflightRequests,
    maxFids: descriptor.limits.maxFids, requestTimeoutMs: descriptor.limits.requestTimeoutSeconds * 1000,
  });
  wire.session = session;
  try {
    const remote = await attachSession(descriptor, transport, session);
    return { remote, session, wire, descriptor };
  } catch (error) { socket.close(1000, 'fixture-start'); throw error; }
}

async function heldCase(plan: Plan, kind: Case, command: () => Promise<string>) {
  phase = `held-${kind}`;
  const { remote, session, wire, descriptor } = await connect(plan);
  let parallel: ReturnType<typeof remote.readDirectory> | undefined;
  try {
    wire.arm(kind === 'walk' ? 'Rwalk' : 'Rclunk');
    const caller = observe(remote.stat('/held.bin', { timeoutMs: OPERATION_MS }));
    const original = await until(() => wire.event(wire.sent, 'Twalk'));
    if (original.message.kind !== 'Twalk') throw new Error('walk-absent');
    const fid = original.message.newfid;
    const clunk = kind === 'clunk' ? await until(() => wire.event(wire.sent, 'Tclunk')) : undefined;
    const heldTag = clunk?.message.tag ?? original.message.tag;
    const heldKind = kind === 'walk' ? 'Rwalk' : 'Rclunk';
    const held = await until(() => wire.event(wire.received, heldKind, heldTag));

    // Independent provider-state probe on the same real 9P connection. It is
    // also held in order and never fabricated or delivered ahead of the victim.
    const priorSends = wire.sent.length;
    const probe = observe(session.request({ kind: 'Tgetattr', tag: 0, fid, requestMask: BigInt(GETATTR_BASIC) }));
    const probeRequest = wire.sent[priorSends];
    if (probeRequest?.message.kind !== 'Tgetattr') throw new Error('probe-not-sent');
    const probeReply = await until(() => wire.received.find((event) => event.message.tag === probeRequest.message.tag));
    const providerProbeKind = probeReply.message.kind;
    const providerProbeSize = probeReply.message.kind === 'Rgetattr' ? Number(probeReply.message.size) : 0;
    const providerProbeErrno = probeReply.message.kind === 'Rlerror' ? probeReply.message.ecode : 0;
    const callerResult = await bounded(caller);
    const callerSettled = wire.tick();
    const reservedAfterCaller = session.openFids;
    const prematureClunks = kind === 'walk' ? wire.sent.filter((event) => event.message.kind === 'Tclunk' && event.message.fid === fid).length : 0;

    // Walk expiry sends its real Tflush. For applied clunk, explicitly cancel
    // its still-unconfirmed cleanup request after the operation stopped waiting.
    const cancellation = kind === 'clunk' ? observe(session.abort(heldTag)) : undefined;
    const flush = await until(() => wire.sent.find((event) => event.message.kind === 'Tflush' && event.message.oldtag === heldTag));
    const flushReply = await until(() => wire.event(wire.received, 'Rflush', flush.message.tag));
    parallel = remote.readDirectory('/parallel', { timeoutMs: WAIT_MS });
    const parallelResult = observe(parallel.next());
    const nextWalk = await until(() => wire.sent.find((event) => event.message.kind === 'Twalk' && event.sequence > callerSettled));
    if (nextWalk.message.kind !== 'Twalk') throw new Error('parallel-walk-absent');
    const parallelReply = await until(() => wire.received.find((event) => event.message.tag === nextWalk.message.tag));
    const reservedDuringHold = session.openFids;
    report({ event: 'held', kind, fid, heldTag, probeTag: probeRequest.message.tag,
      parallelFid: nextWalk.message.newfid, reservedAfterCaller, reservedDuringHold, prematureClunks,
      providerProbeKind, providerProbeSize, providerProbeErrno, probeReceived: probeReply.sequence,
      received: wire.received.length, delivered: wire.delivered.length });
    if (await command() !== 'release') throw new Error('release-command');
    wire.release();
    const probeResult = await bounded(probe);
    if (cancellation !== undefined) await bounded(cancellation);
    const page = await bounded(parallelResult);
    const cleanup = await until(() => wire.sent.find((event) => event.message.kind === 'Tclunk' && event.message.fid === fid));
    const cleanupReply = await until(() => wire.event(wire.delivered, 'Rclunk', cleanup.message.tag));
    await until(() => session.openFids === 1 ? true : undefined);
    const reuseAfter = wire.tick();
    const after = await bounded(remote.stat('/probe.bin', { timeoutMs: WAIT_MS }));
    const reusedWalk = wire.sent.find((event) => event.sequence > reuseAfter && event.message.kind === 'Twalk');
    if (reusedWalk?.message.kind !== 'Twalk') throw new Error('reuse-walk-absent');
    const originalDelivered = wire.event(wire.delivered, heldKind, heldTag);
    await bounded(parallel.return(undefined));
    parallel = undefined;
    const result = {
      kind, originalFid: fid, parallelFid: nextWalk.message.newfid, reusedFid: reusedWalk.message.newfid,
      originalTag: original.message.tag, heldTag, probeTag: probeRequest.message.tag, flushTag: flush.message.tag,
      originalSent: original.sequence, heldReceived: held.sequence, probeReceived: probeReply.sequence, callerSettled,
      parallelSent: nextWalk.sequence, heldDelivered: originalDelivered?.sequence ?? 0,
      cleanupSent: cleanup.sequence, cleanupDelivered: cleanupReply.sequence, reusedSent: reusedWalk.sequence,
      flushReceived: flushReply.sequence,
      reservedAfterCaller, reservedDuringHold, reservedAtEnd: session.openFids, prematureClunks,
      providerProbeKind, providerProbeSize, providerProbeErrno,
      probeSettled: probeResult.ok ? 'reply' : probeResult.failure.code,
      callerCode: callerResult.ok ? 'ok' : callerResult.failure.code,
      callerOutcome: callerResult.ok ? 'complete' : callerResult.failure.outcome,
      callerRetryable: callerResult.ok ? false : callerResult.failure.retryable,
      callerSize: callerResult.ok ? Number(callerResult.value.size) : 0,
      parallelWireReply: parallelReply.message.kind,
      parallelValid: page.ok && !page.value.done && page.value.value.name === 'entry.bin' && page.value.value.kind === 'file',
      reuseSize: Number(after.size), state: remote.state, unexpectedCloses: wire.unexpectedCloses,
      requestTimeoutMs: descriptor.limits.requestTimeoutSeconds * 1000, operationTimeoutMs: OPERATION_MS,
      deliveryOrderPreserved: wire.delivered.every((event, index) => event.message.tag === wire.received[index]?.message.tag && event.message.kind === wire.received[index]?.message.kind),
    };
    report({ event: 'case', result });
  } finally {
    wire.release();
    if (parallel !== undefined) await bounded(parallel.return(undefined)).catch(() => {});
    wire.closing = true;
    await bounded(remote.close());
  }
}

async function refusalCase(plan: Plan): Promise<void> {
  phase = 'definite-refusal';
  const { remote, session, wire } = await connect(plan);
  try {
    const abort = new AbortController();
    abort.abort();
    const before = wire.sent.length;
    const aborted = await observe(remote.stat('/held.bin', { signal: abort.signal }));
    const preabortSent = wire.sent.length - before;
    const refused = await observe(remote.stat('/missing.bin'));
    const first = wire.event(wire.sent, 'Twalk');
    const clunksAfterRefusal = wire.sent.filter((event) => event.message.kind === 'Tclunk').length;
    const next = await remote.stat('/probe.bin');
    const walks = wire.sent.filter((event) => event.message.kind === 'Twalk');
    const second = walks[1];
    report({ event: 'refusal', result: { code: refused.ok ? 'ok' : refused.failure.code,
      outcome: refused.ok ? 'complete' : refused.failure.outcome, clunksAfterRefusal,
      firstFid: first?.message.kind === 'Twalk' ? first.message.newfid : 0,
      secondFid: second?.message.kind === 'Twalk' ? second.message.newfid : 0,
      probeSize: Number(next.size), state: remote.state, reservedAtEnd: session.openFids,
      preabortCode: aborted.ok ? 'ok' : aborted.failure.code, preabortSent,
      unexpectedCloses: wire.unexpectedCloses } });
  } finally { wire.closing = true; await bounded(remote.close()); }
}

async function main(): Promise<void> {
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED !== undefined) throw new Error('unsafe-tls-setting');
  const path = process.argv[2];
  if (path === undefined) throw new Error('plan-absent');
  const plan = JSON.parse(await readFile(path, 'utf8')) as Plan;
  const input = createInterface({ input: process.stdin });
  const lines = input[Symbol.asyncIterator]();
  const command = async (): Promise<string> => {
    const value = await bounded(lines.next());
    if (value.done) throw new Error('command-eof');
    return value.value;
  };
  try {
    report({ event: 'ready', node: process.version,
      module: fileURLToPath(import.meta.resolve('../src/index.ts')) });
    await heldCase(plan, 'walk', command);
    await heldCase(plan, 'clunk', command);
    await refusalCase(plan);
    phase = 'report';
    report({ event: 'done', cases: 3 });
    if (await command() !== 'exit') throw new Error('exit-command');
    report({ event: 'exiting' });
  } finally { input.close(); }
}

await main().catch(() => {
  report({ event: 'failure', phase });
  process.exitCode = 1;
});
