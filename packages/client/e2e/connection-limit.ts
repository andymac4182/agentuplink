/**
 * The M6-C200 driver: this package's client against a **real relay listener**
 * at its connection limit.
 *
 * Not part of `npm test`. It is a child process of the Rust harness command
 * `verify-m6-ts-connection-limit`
 * (`crates/tunnel-test-harness/src/ts_connection_limit.rs`), which serves the
 * relay's own listener (`tunnel_transport::serve_with_listener_options`, the
 * accept path `tunnel-relay` runs) with a one-connection limit, holds that one
 * connection, and then runs this script. Every judgement is the harness's: this
 * prints one `report` line of closed codes and integers and nothing else on
 * stdout.
 *
 * argv[2] is the endpoint URL and argv[3] the mode: `limit` reports the
 * descriptor GET's and the upgrade's errors; `control` reports only the
 * descriptor GET's, for the run after the held connection is released, where
 * the same URL, trust and client must reach the router instead.
 */

import { fileURLToPath } from 'node:url';

import {
  FilesystemError,
  SUBPROTOCOL,
  UpgradeRejected,
  fetchDescriptor,
  upgrade,
  upgradeRejectionError,
} from '../src/index.ts';

interface Observed {
  code: string;
  retryAfterMs: number | null;
  retryable: boolean;
  outcome: string;
}

function observe(error: unknown): Observed {
  if (!(error instanceof FilesystemError)) {
    // A bare exception is a finding in itself; its text is not printed.
    return { code: 'NOT_A_FILESYSTEM_ERROR', retryAfterMs: null, retryable: false, outcome: 'none' };
  }
  return {
    code: error.code,
    retryAfterMs: error.retryAfterMs ?? null,
    retryable: error.retryable,
    outcome: error.outcome,
  };
}

// Synthetic: the listener refuses before any handler could read it.
const token = (): string => 'synthetic-m6-c200-token';

async function descriptorStage(endpoint: string): Promise<Observed> {
  try {
    await fetchDescriptor({ endpoint, token });
    return { code: 'ADMITTED', retryAfterMs: null, retryable: false, outcome: 'none' };
  } catch (error) {
    return observe(error);
  }
}

async function upgradeStage(endpoint: string): Promise<Observed> {
  try {
    const transport = await upgrade({
      url: new URL(endpoint),
      subprotocol: SUBPROTOCOL,
      headers: { Authorization: `Bearer ${token()}` },
      maxMessageBytes: 65536,
      allowInsecureLoopback: false,
      timeoutMs: 10_000,
      handlers: { onMessage: () => {}, onClose: () => {} },
    });
    transport.close(1000, 'unexpected');
    return { code: 'ADMITTED', retryAfterMs: null, retryable: false, outcome: 'none' };
  } catch (error) {
    // The client's own mapping of a refused upgrade, as `connectFilesystem`
    // applies it.
    return observe(error instanceof UpgradeRejected ? upgradeRejectionError(error) : error);
  }
}

async function main(): Promise<void> {
  const [endpoint, mode] = process.argv.slice(2);
  if (endpoint === undefined || (mode !== 'limit' && mode !== 'control')) {
    process.exitCode = 2;
    return;
  }
  const report: Record<string, unknown> = {
    event: 'report',
    mode,
    clientModule: fileURLToPath(new URL('../src/index.ts', import.meta.url)),
    descriptor: await descriptorStage(endpoint),
  };
  if (mode === 'limit') {
    report['upgrade'] = await upgradeStage(endpoint);
  }
  process.stdout.write(`${JSON.stringify(report)}\n`);
}

await main();
