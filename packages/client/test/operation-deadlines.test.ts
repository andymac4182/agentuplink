/** Shared-client deadline evidence against a loopback mock 9P peer, not a relay. */
import { strict as assert } from 'node:assert';
import { setTimeout as delay } from 'node:timers/promises';
import { it, type TestContext } from 'node:test';

import { connectFilesystem } from '../src/filesystem.ts';
import { FilesystemError, type Outcome } from '../src/errors.ts';
import type { Limits } from '../src/descriptor.ts';
import type { Message } from '../src/ninep/messages.ts';
import { descriptorFixture } from './harness/descriptor.ts';
import { startEndpoint, type ServerConnection } from './harness/endpoint.ts';
import { FakeProvider } from './harness/provider.ts';

type ReplyPolicy = (request: Message, reply: Message) => number | 'hold';

async function connect(
  t: TestContext,
  seed: Record<string, string | Uint8Array> = {},
  policy: ReplyPolicy = () => 0,
  limits: Partial<Limits> = {},
) {
  const provider = new FakeProvider(seed);
  const timers = new Map<number, ReturnType<typeof setTimeout>>();
  const descriptor = descriptorFixture({ limits: {
    ...descriptorFixture().limits, maxMessageBytes: 256, requestTimeoutSeconds: 1,
    defaultOperationTimeoutSeconds: 1, maxOperationTimeoutSeconds: 2, ...limits,
  } });
  const endpoint = await startEndpoint({ descriptor, onRequest: (request, connection) => {
    if (request.kind === 'Tflush') {
      clearTimeout(timers.get(request.oldtag));
      timers.delete(request.oldtag);
    }
    provider.handle(request, { ...connection, send: (reply: Message) => {
      const wait = policy(request, reply);
      if (wait === 'hold') return;
      if (wait === 0) { connection.send(reply); return; }
      timers.set(request.tag, setTimeout(() => {
        timers.delete(request.tag);
        connection.send(reply);
      }, wait));
    } } as ServerConnection);
  } }, descriptor.limits.maxMessageBytes);
  const remote = await connectFilesystem({
    endpoint: endpoint.url, token: () => 'synthetic-consumer-token', allowInsecureLoopback: true,
  });
  const connection = endpoint.connections[0]!;
  t.after(async () => {
    for (const timer of timers.values()) clearTimeout(timer);
    await remote.close();
    await endpoint.close();
  });
  return { remote, provider, connection };
}

function failure(code: string, outcome: Outcome, bytes?: number) {
  return (error: unknown): boolean => {
    assert.ok(error instanceof FilesystemError);
    assert.equal(error.code, code);
    assert.equal(error.outcome, outcome);
    if (bytes !== undefined) assert.equal(error.bytesAcknowledged, bytes);
    assert.equal(error.retryable, false);
    return true;
  };
}

async function until(check: () => boolean): Promise<void> {
  const end = performance.now() + 2000;
  while (!check()) {
    assert.ok(performance.now() < end, 'expected wire event before test guard');
    await delay(5);
  }
}

it('validates operation timeout before dispatch, including the descriptor ceiling', async (t) => {
  const { remote, connection } = await connect(t, { file: 'hello' });
  const before = connection.received.length;
  for (const raw of [0, -1, NaN, Infinity, 1.5, 2001, null, false, '150']) {
    const timeoutMs = raw as unknown as number;
    await assert.rejects(remote.stat('/file', { timeoutMs }), failure('EINVAL', 'not_started'));
  }
  assert.equal(connection.received.length, before);
});

it('bounds aggregate timely reads by the explicit operation timeout', async (t) => {
  const { remote, connection } = await connect(t, { file: new Uint8Array(2000) },
    (request) => request.kind === 'Tread' ? 100 : 0);
  await assert.rejects(remote.readFile('/file', { timeoutMs: 350 }),
    failure('DEADLINE_EXCEEDED', 'failed'));
  const reads = connection.received.filter((m) => m.kind === 'Tread').length;
  assert.ok(reads > 1 && reads < 9, `partial read sequence: ${reads}`);
  assert.equal(remote.budget.outstanding, 0);
  assert.equal((await remote.stat('/file')).size, 2000n);
});

it('uses the descriptor default when timeoutMs is omitted', async (t) => {
  const { remote, connection } = await connect(t, { file: new Uint8Array(3000) },
    (request) => request.kind === 'Tread' ? 150 : 0);
  await assert.rejects(remote.readFile('/file'), failure('DEADLINE_EXCEEDED', 'failed'));
  assert.ok(connection.received.filter((m) => m.kind === 'Tread').length < 13);
});

it('copy shares one budget between its lazy source and destination', async (t) => {
  const { remote, provider, connection } = await connect(t, { source: new Uint8Array(2000).fill(7) },
    (request) => request.kind === 'Tread' ? 180 : request.kind === 'Twrite' ? 10 : 0);
  await assert.rejects(remote.copy('/source', '/destination', { timeoutMs: 450 }),
    failure('DEADLINE_EXCEEDED', 'partial', 490));
  assert.equal(provider.read('/destination')?.byteLength, 490);
  const writes = connection.received.filter((m) => m.kind === 'Twrite').length;
  await delay(200);
  assert.equal(connection.received.filter((m) => m.kind === 'Twrite').length, writes);
});

it('nested recursive removal cannot restart the operation budget per child', async (t) => {
  const { remote, provider, connection } = await connect(t,
    { 'tree/a/one': '1', 'tree/b/two': '2', 'tree/c/three': '3' },
    (request) => request.kind === 'Tgetattr' ? 100 : 0);
  await assert.rejects(remote.remove('/tree', { recursive: true, timeoutMs: 450 }),
    failure('DEADLINE_EXCEEDED', 'partial'));
  assert.equal(provider.has('/tree/a'), false);
  assert.equal(provider.has('/tree/c/three'), true);
  const before = connection.received.filter((m) => m.kind === 'Tunlinkat').length;
  await delay(200);
  assert.equal(connection.received.filter((m) => m.kind === 'Tunlinkat').length, before);
});

for (const acknowledged of [false, true]) {
  it(`bounds stalled upload next and return, preserving ${acknowledged ? 'acknowledged bytes' : 'create effect'}`, async (t) => {
    const { remote, provider, connection } = await connect(t);
    let release!: (value: IteratorResult<Uint8Array>) => void;
    const stalled = new Promise<IteratorResult<Uint8Array>>((resolve) => { release = resolve; });
    let first = acknowledged;
    let returned = 0;
    const chunks: AsyncIterable<Uint8Array> = { [Symbol.asyncIterator]: () => ({
      next: () => {
        if (first) { first = false; return Promise.resolve({ done: false, value: new Uint8Array([1, 2, 3]) }); }
        return stalled;
      },
      return: () => { returned += 1; return new Promise(() => {}); },
    }) };
    // The guard makes the pre-fix hang a bounded, visible failure.
    const pending = remote.writeStream('/upload', chunks, { timeoutMs: 250 });
    let guard: ReturnType<typeof setTimeout> | undefined;
    try {
      await assert.rejects(Promise.race([pending, new Promise((_, reject) => {
        guard = setTimeout(() => reject(new Error('operation escaped its deadline')), 1000);
      })]), failure('DEADLINE_EXCEEDED', 'partial', acknowledged ? 3 : 0));
      assert.equal(returned, 1);
      release({ done: false, value: new Uint8Array([9]) });
      await delay(80);
      assert.equal(connection.received.filter((m) => m.kind === 'Twrite').length, acknowledged ? 1 : 0);
      assert.equal(provider.read('/upload')?.byteLength, acknowledged ? 3 : 0);
      assert.equal((await remote.stat('/upload')).size, acknowledged ? 3n : 0n);
    } finally {
      clearTimeout(guard);
      release({ done: true, value: undefined });
      void pending.catch(() => {});
    }
  });
}

it('a dispatched write with a lost acknowledgement stays unknown and is never replayed', async (t) => {
  const { remote, provider, connection } = await connect(t, {},
    (request) => request.kind === 'Twrite' ? 'hold' : 0);
  const started = performance.now();
  await assert.rejects(remote.writeFile('/file', new Uint8Array([4, 5]), { timeoutMs: 250 }),
    failure('DEADLINE_EXCEEDED', 'unknown', 0));
  assert.ok(performance.now() - started < 700, 'operation deadline precedes request deadline');
  assert.deepEqual(provider.read('/file'), new Uint8Array([4, 5]));
  assert.equal(connection.received.filter((m) => m.kind === 'Twrite').length, 1);
  assert.equal(remote.state, 'ready');
});

it('caller abort wins a later operation deadline while the flush is pending', async (t) => {
  const { remote, connection } = await connect(t, {},
    (request) => request.kind === 'Twrite' ? 'hold' : request.kind === 'Tflush' ? 300 : 0);
  const controller = new AbortController();
  const pending = remote.writeFile('/file', new Uint8Array([4]), { signal: controller.signal, timeoutMs: 150 });
  const check = assert.rejects(pending, failure('ABORTED', 'unknown', 0));
  await until(() => connection.received.some((m) => m.kind === 'Twrite'));
  controller.abort();
  await check;
  assert.equal(connection.received.filter((m) => m.kind === 'Tflush').length, 1);
});

it('early return disposes the iterator deadline and keeps the session reusable', async (t) => {
  const { remote, connection } = await connect(t, { file: new Uint8Array(500) });
  const stream = remote.readStream('/file', { timeoutMs: 150 });
  assert.equal((await stream.next()).done, false);
  await stream.return(undefined);
  const clunks = connection.received.filter((m) => m.kind === 'Tclunk').length;
  await delay(200);
  assert.equal(connection.received.filter((m) => m.kind === 'Tclunk').length, clunks);
  assert.equal(connection.received.filter((m) => m.kind === 'Tflush').length, 0);
  assert.equal((await remote.readFile('/file')).byteLength, 500);
});

it('a paused lazy iterator closes its fid on expiry without waiting for another next', async (t) => {
  const { remote, connection } = await connect(t, { file: new Uint8Array(500) });
  const stream = remote.readStream('/file', { timeoutMs: 150 });
  assert.equal((await stream.next()).done, false);
  await delay(250);
  assert.equal(connection.received.filter((m) => m.kind === 'Tclunk').length, 1);
  await assert.rejects(stream.next(), failure('DEADLINE_EXCEEDED', 'not_started'));
  assert.equal(connection.received.filter((m) => m.kind === 'Tread').length, 1);
  assert.equal((await remote.stat('/file')).size, 500n);
});

it('timeout reports promptly but cleanup retains its fid until the clunk reply', async (t) => {
  const { remote, connection } = await connect(t, { file: new Uint8Array(500) },
    (request) => request.kind === 'Tread' ? 'hold' : request.kind === 'Tclunk' ? 500 : 0);
  const started = performance.now();
  await assert.rejects(remote.readFile('/file', { timeoutMs: 150 }),
    failure('DEADLINE_EXCEEDED', 'failed'));
  assert.ok(performance.now() - started < 450, 'does not wait for delayed cleanup');
  await until(() => connection.received.some((m) => m.kind === 'Tclunk'));
  const previous = connection.received.find((m) => m.kind === 'Tclunk');
  assert.ok(previous?.kind === 'Tclunk');
  const stat = remote.stat('/file');
  await until(() => connection.received.filter((m) => m.kind === 'Twalk').length === 2);
  const walks = connection.received.filter((m) => m.kind === 'Twalk');
  assert.ok(walks[1]?.kind === 'Twalk');
  assert.notEqual(walks[1].newfid, previous.fid, 'no early fid reuse');
  assert.equal((await stat).size, 500n);
});

it('checks monotonic time before dispatch even when the deadline timer has not run', async (t) => {
  const { remote, provider, connection } = await connect(t);
  const chunks: Iterable<Uint8Array> = { *[Symbol.iterator]() {
    // Block this test process's event loop as a synchronous caller source can.
    // The timer cannot run; the monotonic request/source boundary must refuse.
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 200);
    yield new Uint8Array([9]);
  } };
  await assert.rejects(remote.writeStream('/file', chunks, { timeoutMs: 150 }),
    failure('DEADLINE_EXCEEDED', 'partial', 0));
  assert.equal(connection.received.filter((m) => m.kind === 'Twrite').length, 0);
  assert.equal(provider.read('/file')?.byteLength, 0);
});

it('caller abort bounds a stalled upload source and preserves the create effect', async (t) => {
  const { remote, connection } = await connect(t);
  const controller = new AbortController();
  let requested = false;
  let returned = false;
  const chunks: AsyncIterable<Uint8Array> = { [Symbol.asyncIterator]: () => ({
    next: () => { requested = true; return new Promise(() => {}); },
    return: () => { returned = true; return new Promise(() => {}); },
  }) };
  const pending = remote.writeStream('/file', chunks, { timeoutMs: 500, signal: controller.signal });
  const checked = assert.rejects(pending, failure('ABORTED', 'partial', 0));
  await until(() => requested);
  controller.abort();
  await checked;
  assert.equal(returned, true);
  assert.equal(connection.received.filter((m) => m.kind === 'Twrite').length, 0);
});

it('independent operations sharing a caller signal retain independent budgets', async (t) => {
  const { remote } = await connect(t, { file: 'hello' },
    (request) => request.kind === 'Tgetattr' ? 300 : 0);
  const controller = new AbortController();
  const short = assert.rejects(remote.stat('/file', { timeoutMs: 150, signal: controller.signal }),
    failure('DEADLINE_EXCEEDED', 'failed'));
  const long = remote.stat('/file', { timeoutMs: 700, signal: controller.signal });
  await short;
  assert.equal(controller.signal.aborted, false);
  assert.equal((await long).size, 5n);
});

it('the descriptor maximum is accepted, and can extend the default operation budget', async (t) => {
  const { remote } = await connect(t, { file: new Uint8Array(1000) },
    (request) => request.kind === 'Tread' ? 200 : 0);
  assert.equal((await remote.readFile('/file', { timeoutMs: 2000 })).byteLength, 1000);
});

it('a paused directory iterator also expires and clunks exactly once', async (t) => {
  const { remote, connection } = await connect(t, { one: '1', two: '2' });
  const directory = remote.readDirectory('/', { timeoutMs: 150 });
  assert.equal((await directory.next()).done, false);
  await until(() => connection.received.some((m) => m.kind === 'Tclunk'));
  await assert.rejects(directory.next(), failure('DEADLINE_EXCEEDED', 'not_started'));
  assert.equal(connection.received.filter((m) => m.kind === 'Tclunk').length, 1);
  assert.equal(connection.received.filter((m) => m.kind === 'Treaddir').length, 1);
});

it('an original mutation reply before Rflush still wins with an operation deadline', async (t) => {
  const provider = new FakeProvider();
  let held: Message | undefined;
  const endpoint = await startEndpoint({ descriptor: descriptorFixture(), onRequest: (request, connection) => {
    if (request.kind === 'Tmkdir') { held = request; return; }
    if (request.kind === 'Tflush' && held !== undefined) {
      provider.handle(held, connection);
      held = undefined;
    }
    provider.handle(request, connection);
  } });
  const remote = await connectFilesystem({ endpoint: endpoint.url, token: () => 'synthetic-consumer-token', allowInsecureLoopback: true });
  t.after(async () => { await remote.close(); await endpoint.close(); });
  const controller = new AbortController();
  const made = remote.mkdir('/directory', { timeoutMs: 1000, signal: controller.signal });
  await until(() => held !== undefined);
  controller.abort();
  assert.equal(await made, 1);
  assert.equal(provider.has('/directory'), true);
  assert.equal(remote.state, 'ready');
});

it('an unanswered walk keeps its fid until flush settlement and subsequent clunk', async (t) => {
  let first = true;
  let flush: Message | undefined;
  const { remote, connection } = await connect(t, { file: 'hello' }, (request, reply) => {
    if (request.kind === 'Twalk' && first) { first = false; return 'hold'; }
    if (request.kind === 'Tflush') { flush = reply; return 'hold'; }
    if (request.kind === 'Tclunk') return 300;
    return 0;
  });
  await assert.rejects(remote.stat('/file', { timeoutMs: 150 }), failure('DEADLINE_EXCEEDED', 'failed'));
  await until(() => flush !== undefined);
  const original = connection.received.find((m) => m.kind === 'Twalk');
  assert.ok(original?.kind === 'Twalk');
  assert.equal(connection.received.filter((m) => m.kind === 'Tclunk').length, 0,
    'clunk must not race a walk that can still bind its fid');
  const second = remote.stat('/file', { timeoutMs: 1000 });
  await until(() => connection.received.filter((m) => m.kind === 'Twalk').length === 2);
  const next = connection.received.filter((m) => m.kind === 'Twalk')[1];
  assert.ok(next?.kind === 'Twalk');
  assert.notEqual(next.newfid, original.newfid, 'unacknowledged binding still owns its number');
  connection.send(flush!);
  await until(() => connection.received.some((m) => m.kind === 'Tclunk' && m.fid === original.newfid));
  assert.equal((await second).size, 5n);
  await delay(350);
  assert.equal((await remote.stat('/file')).size, 5n);
  const latest = connection.received.filter((m) => m.kind === 'Twalk').at(-1);
  assert.ok(latest?.kind === 'Twalk');
  assert.equal(latest.newfid, original.newfid, 'confirmed clunk makes the number reusable');
  assert.equal(remote.state, 'ready');
});

it('an unacknowledged clunk cannot make its fid reusable merely by timing out and flushing', async (t) => {
  let holdClunk = true;
  const { remote, connection } = await connect(t, { file: 'hello' },
    (request) => request.kind === 'Tclunk' && holdClunk ? 'hold' : 0);
  // The stat itself is known complete. Only cleanup is unacknowledged.
  assert.equal((await remote.stat('/file', { timeoutMs: 150 })).size, 5n);
  await until(() => connection.received.some((m) => m.kind === 'Tflush'));
  holdClunk = false;
  assert.equal((await remote.stat('/file')).size, 5n);
  const walks = connection.received.filter((m) => m.kind === 'Twalk');
  assert.ok(walks[0]?.kind === 'Twalk' && walks[1]?.kind === 'Twalk');
  assert.notEqual(walks[0].newfid, walks[1].newfid, 'flush is not proof Tclunk ran');
  assert.equal(remote.state, 'ready');
});

it('a definitely refused walk releases its fid without unnecessary clunk', async (t) => {
  const { remote, connection } = await connect(t, { file: 'hello' }, () => 0, { maxFids: 1 });
  await assert.rejects(remote.stat('/missing'), failure('ENOENT', 'not_started'));
  assert.equal(connection.received.filter((m) => m.kind === 'Tclunk').length, 0);
  assert.equal((await remote.stat('/file')).size, 5n);
  const walks = connection.received.filter((m) => m.kind === 'Twalk');
  assert.ok(walks[0]?.kind === 'Twalk' && walks[1]?.kind === 'Twalk');
  assert.equal(walks[0].newfid, walks[1].newfid);
});

it('a late original walk reply permits cleanup when the tag quota prevented flushing', async (t) => {
  let originalReply: Message | undefined;
  let first = true;
  const { remote, connection } = await connect(t, { file: 'hello' }, (request, reply) => {
    if (request.kind === 'Twalk' && first) { first = false; originalReply = reply; return 'hold'; }
    return 0;
  }, { maxInflightRequests: 1 });
  await assert.rejects(remote.stat('/file', { timeoutMs: 150 }), failure('DEADLINE_EXCEEDED', 'failed'));
  assert.equal(connection.received.filter((m) => m.kind === 'Tflush').length, 0);
  assert.equal(connection.received.filter((m) => m.kind === 'Tclunk').length, 0);
  assert.ok(originalReply !== undefined);
  connection.send(originalReply);
  await until(() => connection.received.some((m) => m.kind === 'Tclunk'));
  // Receipt proves the peer processed the clunk; allow its reply across the socket.
  await delay(10);
  assert.equal((await remote.stat('/file')).size, 5n);
  const walks = connection.received.filter((m) => m.kind === 'Twalk');
  assert.ok(walks[0]?.kind === 'Twalk' && walks[1]?.kind === 'Twalk');
  assert.equal(walks[0].newfid, walks[1].newfid);
});

it('caller-aborted walk waits for Rflush before cleanup and preserves a parallel operation', async (t) => {
  let first = true;
  const { remote, connection } = await connect(t, { file: 'hello' }, (request) => {
    if (request.kind === 'Twalk' && first) { first = false; return 'hold'; }
    return request.kind === 'Tflush' ? 200 : 0;
  });
  const controller = new AbortController();
  const checked = assert.rejects(remote.stat('/file', { signal: controller.signal, timeoutMs: 1000 }),
    failure('ABORTED', 'failed'));
  await until(() => connection.received.some((m) => m.kind === 'Twalk'));
  controller.abort();
  assert.equal((await remote.stat('/file')).size, 5n);
  const walks = connection.received.filter((m) => m.kind === 'Twalk');
  assert.ok(walks[0]?.kind === 'Twalk' && walks[1]?.kind === 'Twalk');
  assert.notEqual(walks[0].newfid, walks[1].newfid);
  assert.equal(connection.received.filter((m) => m.kind === 'Tclunk' && m.fid === walks[0]!.newfid).length, 0);
  await checked;
  await until(() => connection.received.some((m) => m.kind === 'Tclunk' && m.fid === walks[0]!.newfid));
  assert.equal(remote.state, 'ready');
});

it('an already-aborted walk consumes no fid or tag quota', async (t) => {
  const { remote, connection } = await connect(t, { file: 'hello' }, () => 0, { maxFids: 1, maxInflightRequests: 1 });
  const controller = new AbortController();
  controller.abort();
  const before = connection.received.length;
  await assert.rejects(remote.stat('/file', { signal: controller.signal }), failure('ABORTED', 'not_started'));
  assert.equal(connection.received.length, before);
  assert.equal((await remote.stat('/file')).size, 5n);
});

it('a mismatched late reply cannot certify that an unanswered walk settled', async (t) => {
  const { remote, connection } = await connect(t, { file: 'hello' },
    (request) => request.kind === 'Twalk' || request.kind === 'Tflush' ? 'hold' : 0);
  await assert.rejects(remote.stat('/file', { timeoutMs: 150 }), failure('DEADLINE_EXCEEDED', 'failed'));
  const walk = connection.received.find((m) => m.kind === 'Twalk');
  assert.ok(walk?.kind === 'Twalk');
  connection.send({ kind: 'Rclunk', tag: walk.tag });
  await until(() => remote.state === 'closed');
  assert.equal(connection.received.filter((m) => m.kind === 'Tclunk').length, 0);
  await assert.rejects(remote.stat('/file'), failure('PROTOCOL_VIOLATION', 'not_started'));
});
