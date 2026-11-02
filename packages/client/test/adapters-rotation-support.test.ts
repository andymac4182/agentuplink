import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { RendezvousSession, fixtureText } from '../e2e/adapters-rotation-support.ts';
import { decodeExact } from '../src/ninep/codec.ts';
import type { Message } from '../src/ninep/messages.ts';

function fixture(): { session: RendezvousSession; sent: Message[] } {
  const sent: Message[] = [];
  let session: RendezvousSession;
  session = new RendezvousSession({
    isOpen: true,
    send(bytes) {
      const message = decodeExact(bytes);
      sent.push(message);
      session.sent(message);
    },
    close() {},
  }, { msize: 65_536, maxInflightRequests: 16, maxFids: 16, requestTimeoutMs: 1000 });
  return { session, sent };
}

test('rotation rendezvous is undispatched until released, and observes actual tags', async () => {
  const { session, sent } = fixture();
  const reached = session.arm('Twrite');
  const request = session.request({ kind: 'Twrite', tag: 0, fid: 2, offset: 0n, data: new Uint8Array([7]) });
  await reached;
  assert.equal(sent.length, 0);
  assert.equal(session.probe.sent, 0);
  session.release();
  await new Promise<void>((resolve) => { setImmediate(resolve); });
  assert.equal(sent.length, 1);
  assert.equal(session.probe.sent, 1);
  assert.equal(session.probe.writtenBytes, 1);
  const message = sent[0];
  assert.ok(message !== undefined);
  const reply: Message = { kind: 'Rwrite', tag: message.tag, count: 1 };
  session.received(reply);
  session.onMessage((await import('../src/ninep/codec.ts')).encode(reply));
  assert.equal((await request).kind, 'Rwrite');
  assert.equal(session.probe.replies, 1);
  session.close();
});

test('an aborted parked operation cannot dispatch when subsequently released', async () => {
  const { session, sent } = fixture();
  const controller = new AbortController();
  const reached = session.arm('Tread');
  const request = session.request({ kind: 'Tread', tag: 0, fid: 2, offset: 0n, count: 10 }, { signal: controller.signal });
  await reached;
  controller.abort(new Error('synthetic-abort'));
  await assert.rejects(request, /synthetic-abort/u);
  session.release();
  await new Promise<void>((resolve) => { setImmediate(resolve); });
  assert.equal(sent.length, 0);
  assert.equal(session.probe.sent, 0);
  session.close();
});

test('host fixtures are distinct exact 4096-byte ASCII images', () => {
  const cases = ['files', 'mastra', 'ai', 'bash'].flatMap((adapter) =>
    ['read', 'write', 'revoked'].map((operation) => fixtureText(adapter, operation)));
  assert.equal(new Set(cases).size, 12);
  for (const image of cases) assert.equal(Buffer.byteLength(image), 4096);
});
