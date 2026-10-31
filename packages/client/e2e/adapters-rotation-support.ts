/** Test-only pre-dispatch rendezvous. No bytes are parked in a transport. */
import { ConsumerSession } from '../src/session.ts';
import type { Message, MessageOf } from '../src/ninep/messages.ts';

export interface Probe {
  armed: boolean;
  sent: number;
  replies: number;
  tag: number | undefined;
  fid: number | undefined;
  offset: string | undefined;
  count: number;
  attaches: number;
  writes: number;
  writtenBytes: number;
}

interface Hold {
  kind: 'Tread' | 'Twrite';
  arrived: () => void;
  released: Promise<void>;
  release: () => void;
  selected: Message | undefined;
}

export class RendezvousSession extends ConsumerSession {
  readonly probe: Probe = {
    armed: false, sent: 0, replies: 0, tag: undefined, fid: undefined,
    offset: undefined, count: 0, attaches: 0, writes: 0, writtenBytes: 0,
  };
  private hold: Hold | undefined;
  private targetTagReused = false;

  arm(kind: Hold['kind']): Promise<void> {
    if (this.hold !== undefined) throw new Error('rendezvous-already-armed');
    let arrived!: () => void;
    const arrival = new Promise<void>((resolve) => { arrived = resolve; });
    let release!: () => void;
    const released = new Promise<void>((resolve) => { release = resolve; });
    this.hold = { kind, arrived, released, release, selected: undefined };
    return arrival;
  }

  release(): void {
    if (this.hold?.selected === undefined) throw new Error('rendezvous-not-reached');
    this.hold.release();
  }

  /** Called only AFTER the real socket accepted the bytes without throwing. */
  sent(message: Message): void {
    if (this.probe.tag !== undefined && message.tag === this.probe.tag) this.targetTagReused = true;
    if (message.kind === 'Tattach') this.probe.attaches += 1;
    if (message.kind === 'Twrite') {
      this.probe.writes += 1;
      this.probe.writtenBytes += message.data.byteLength;
    }
    const selected = this.hold?.selected;
    if (selected === undefined || this.probe.tag !== undefined || message.kind !== selected.kind) return;
    if (message.kind !== 'Tread' && message.kind !== 'Twrite') return;
    this.probe.sent += 1;
    this.probe.tag = message.tag;
    this.probe.fid = message.fid;
    this.probe.offset = String(message.offset);
    this.probe.count = message.kind === 'Tread' ? message.count : message.data.byteLength;
  }

  received(message: Message): void {
    if (!this.targetTagReused && this.probe.tag !== undefined && message.tag === this.probe.tag) this.probe.replies += 1;
  }

  override async request<K extends Message['kind']>(
    message: MessageOf<K>, options: { signal?: AbortSignal | undefined } = {},
  ): Promise<Message> {
    const hold = this.hold;
    if (hold !== undefined && hold.selected === undefined && message.kind === hold.kind) {
      hold.selected = message;
      this.probe.armed = true;
      hold.arrived();
      // A gate failure or cancelled operation cannot strand a parked producer.
      // No tag/request timer/dispatched flag exists until super.request below.
      await waitForRelease(hold.released, options.signal);
    }
    return await super.request(message, options);
  }
}

async function waitForRelease(released: Promise<void>, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted === true) throw signal.reason;
  let abort!: () => void;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const cancelled = new Promise<never>((_resolve, reject) => {
    abort = () => { reject(signal?.reason ?? new Error('rendezvous-aborted')); };
    signal?.addEventListener('abort', abort, { once: true });
    timer = setTimeout(() => { reject(new Error('rendezvous-deadline')); }, 20_000);
  });
  try {
    await Promise.race([released, cancelled]);
    signal?.throwIfAborted();
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    signal?.removeEventListener('abort', abort);
  }
}

/** ASCII data shared with the host oracle; framework payloads never enter logs. */
export function fixtureText(adapter: string, operation: string): string {
  const prefix = `${adapter}:${operation}:`;
  return prefix + '0123456789abcdef'.repeat(256).slice(0, 4096 - prefix.length);
}
