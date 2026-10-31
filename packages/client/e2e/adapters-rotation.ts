/** M4-68 driver. Rust owns the clock, carrier fault, host oracle and verdict. */
import { readFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { setImmediate, setInterval, clearInterval } from 'node:timers';
import { fetchDescriptor, attachSession, GRANT_REVISION_HEADER, SUBPROTOCOL } from '../src/index.ts';
import type { RemoteFilesystem, BinaryTransport } from '../src/index.ts';
import { upgrade } from '../src/websocket.ts';
import { decodeExact } from '../src/ninep/codec.ts';
import { RendezvousSession } from './adapters-rotation-support.ts';
import { binding, type Adapter, type Binding, type Role, type WriteResult } from './adapters-rotation-frameworks.ts';

interface Plan { adapter: Adapter; endpoint: string; token: string }
interface Live { remote: RemoteFilesystem; session: RendezvousSession; native: Binding; closeCode: number | undefined }
interface Jobs { read: Promise<boolean> | undefined; write: Promise<WriteResult> }

function emit(event: string, data: Record<string, unknown> = {}): void {
  process.stdout.write(`${JSON.stringify({ event, ...data })}\n`);
}

function planFrom(path: string): Plan {
  const value: unknown = JSON.parse(readFileSync(path, 'utf8'));
  if (typeof value !== 'object' || value === null || !('adapter' in value) ||
      !('endpoint' in value) || !('token' in value) || typeof value.endpoint !== 'string' ||
      typeof value.token !== 'string' || !['files', 'mastra', 'ai', 'bash'].includes(String(value.adapter))) {
    throw new Error('invalid-plan');
  }
  if (new URL(value.endpoint).protocol !== 'https:') throw new Error('insecure-plan');
  return { adapter: value.adapter as Adapter, endpoint: value.endpoint, token: value.token };
}

async function connect(plan: Plan, role: Role): Promise<Live> {
  const descriptor = await fetchDescriptor({ endpoint: plan.endpoint, token: () => plan.token });
  let session: RendezvousSession | undefined;
  let live: Live | undefined;
  let closeCode: number | undefined;
  const socket = await upgrade({
    url: new URL(plan.endpoint), subprotocol: SUBPROTOCOL,
    headers: { Authorization: `Bearer ${plan.token}`, [GRANT_REVISION_HEADER]: descriptor.grantRevision },
    maxMessageBytes: descriptor.limits.maxMessageBytes, allowInsecureLoopback: false,
    timeoutMs: descriptor.limits.requestTimeoutSeconds * 1000,
    handlers: {
      onMessage(bytes) {
        session?.received(decodeExact(bytes));
        session?.onMessage(bytes);
      },
      onClose(info) {
        closeCode = info.code;
        if (live !== undefined) live.closeCode = info.code;
        session?.onClose(info);
      },
    },
  });
  const transport: BinaryTransport = {
    get isOpen() { return socket.isOpen; },
    send(bytes) {
      socket.send(bytes);
      session?.sent(decodeExact(bytes));
    },
    close(code, reason) { socket.close(code, reason); },
  };
  session = new RendezvousSession(transport, {
    msize: descriptor.limits.maxMessageBytes, maxFids: descriptor.limits.maxFids,
    maxInflightRequests: descriptor.limits.maxInflightRequests,
    requestTimeoutMs: descriptor.limits.requestTimeoutSeconds * 1000,
  });
  const remote = await attachSession(descriptor, transport, session);
  const native = binding(plan.adapter, role, remote);
  live = { remote, session, native, closeCode };
  await native.prepare();
  return live;
}

async function bounded<T>(promise: Promise<T>, label: string, ms = 30_000): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([promise, new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => { reject(new Error(label)); }, ms);
    })]);
  } finally { if (timer !== undefined) clearTimeout(timer); }
}

function versions(): Record<string, string> {
  return Object.fromEntries(['files-sdk', '@mastra/core', 'ai', 'just-bash', '@ai-sdk/provider'].map((name) => {
    const manifest: unknown = JSON.parse(readFileSync(new URL(`../node_modules/${name}/package.json`, import.meta.url), 'utf8'));
    if (typeof manifest !== 'object' || manifest === null || !('version' in manifest) || typeof manifest.version !== 'string') {
      throw new Error('invalid-framework-manifest');
    }
    return [name, manifest.version];
  }));
}

async function main(): Promise<void> {
  if (process.env.NODE_TLS_REJECT_UNAUTHORIZED !== undefined) throw new Error('tls-override-refused');
  const path = process.argv[2];
  if (path === undefined) throw new Error('missing-plan');
  const plan = planFrom(path);
  // Framework diagnostics can contain tool arguments. The bounded protocol
  // below is the sole stdout writer, and no framework payload is logged.
  console.log = console.info = console.warn = console.debug = console.error = () => {};
  const clients = new Map<Role, Live>();
  let jobs: Jobs | undefined;
  let active: Role[] = [];
  const selected = (role: Role): Live => {
    const value = clients.get(role);
    if (value === undefined) throw new Error('missing-client');
    return value;
  };
  const probes = (): Record<string, unknown> => Object.fromEntries(active.map((role) => [role, {
    ...selected(role).session.probe, closeCode: selected(role).closeCode,
  }]));
  const commands = createInterface({ input: process.stdin, crlfDelay: Infinity });
  const heartbeat = setInterval(() => { emit('heartbeat'); }, 10_000);
  try {
    emit('ready', { adapter: plan.adapter, versions: versions(), node: process.version });
    for await (const command of commands) {
      if (command.length > 64) throw new Error('oversized-command');
      if (command === 'open_read' || command === 'open_write' || command === 'open_revoked') {
        const role: Role = command === 'open_read' ? 'read' : command === 'open_write' ? 'write' : 'revoked';
        if (clients.has(role)) throw new Error('duplicate-client');
        clients.set(role, await bounded(connect(plan, role), 'connect-deadline'));
        emit('opened', { role, probe: selected(role).session.probe });
      } else if (command === 'canary') {
        await bounded(Promise.all([...clients.values()].map(async (live) => await live.remote.stat('/'))), 'canary-deadline');
        emit('canary');
      } else if (command === 'arm_rotation' || command === 'arm_revocation') {
        const revoke = command === 'arm_revocation';
        const writer = selected(revoke ? 'revoked' : 'write');
        active = revoke ? ['revoked'] : ['read', 'write'];
        const arrived = [writer.session.arm('Twrite')];
        if (!revoke) arrived.push(selected('read').session.arm('Tread'));
        const write = writer.native.write();
        const read = revoke ? undefined : selected('read').native.read();
        // Catch early failures immediately; no unhandled rejected promise may
        // masquerade as a driver silently waiting at a barrier it never reached.
        void write.catch(() => {});
        void read?.catch(() => {});
        jobs = { read, write };
        const premature = Promise.all([write, ...(read === undefined ? [] : [read])]).then(() => {
          throw new Error('operation-ended-before-rendezvous');
        });
        await bounded(Promise.race([Promise.all(arrived), premature]), 'staging-deadline', 5_000);
        emit('armed', { probes: probes() });
      } else if (command === 'release') {
        for (const role of active) selected(role).session.release();
        await bounded((async () => {
          while (active.some((role) => selected(role).session.probe.sent !== 1)) {
            await new Promise<void>((resolve) => { setImmediate(resolve); });
          }
        })(), 'dispatch-deadline', 2_000);
        emit('sent', { probes: probes() });
      } else if (command === 'status') {
        emit('status', { probes: probes() });
      } else if (command === 'finish_rotation') {
        if (jobs?.read === undefined) throw new Error('missing-rotation-jobs');
        const [readMatches, write] = await bounded(Promise.all([jobs.read, jobs.write]), 'completion-deadline');
        const referenceSurvived = await bounded(selected('read').native.read(), 'post-rotation-read-deadline');
        await bounded(selected('write').remote.stat('/'), 'post-rotation-stat-deadline');
        emit('rotation_result', { readMatches, write, referenceSurvived, probes: probes() });
      } else if (command === 'close_rotation') {
        for (const role of ['read', 'write'] as const) {
          const live = selected(role);
          live.native.close();
          live.remote.close();
          clients.delete(role);
        }
        active = [];
        jobs = undefined;
        emit('closed');
      } else if (command === 'finish_revocation') {
        if (jobs === undefined) throw new Error('missing-revocation-jobs');
        const write = await bounded(jobs.write, 'revocation-deadline', 20_000);
        emit('revocation_result', { write, probes: probes() });
      } else if (command === 'exit') {
        emit('exiting');
        return;
      } else throw new Error('unknown-command');
    }
    throw new Error('command-pipe-ended');
  } finally {
    clearInterval(heartbeat);
    commands.close();
    for (const live of clients.values()) {
      live.native.close();
      live.remote.close();
    }
  }
}

try { await main(); } catch (error) {
  // Only our closed driver labels are emitted; arbitrary framework errors can
  // carry paths or token-bearing URLs and must not enter a public gate log.
  emit('failed', { type: error instanceof Error ? error.constructor.name : 'unknown' });
  process.exitCode = 1;
}
