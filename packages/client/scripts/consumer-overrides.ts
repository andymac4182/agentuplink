/**
 * C252: exercise npm's actual consumer resolver with a packed local client.
 * This explicit gate needs registry access; offline unit/peer tests do not.
 * No package scripts execute and neither consumer installs node_modules.
 */
import { strict as assert } from 'node:assert';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

interface Lock {
  packages: Record<string, { version?: string }>;
}

const source = fileURLToPath(new URL('..', import.meta.url));
const npm = process.env.npm_execpath;
assert.ok(npm, 'invoke this gate through npm run test:consumer-overrides');
const parent = process.env.TUNNEL_CONSUMER_GATE_DIR ?? tmpdir();
const work = mkdtempSync(join(parent, 'agentuplink-consumer-overrides-'));
const keep = process.env.TUNNEL_CONSUMER_GATE_KEEP === '1';

function command(args: string[], cwd: string): string {
  // Inherit proxies, CA trust, authentication and runtime guards unchanged.
  return execFileSync(process.execPath, [npm!, ...args], {
    cwd, encoding: 'utf8', timeout: 60_000, maxBuffer: 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

function digest(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

try {
  const manifest = JSON.parse(readFileSync(join(source, 'package.json'), 'utf8'));
  assert.deepEqual(manifest.overrides['just-bash'], { minimatch: '11.0.1' });
  assert.equal(manifest.peerDependencies['just-bash'], '3.4.2');
  const packed: { filename: string }[] = JSON.parse(command([
    'pack', '--ignore-scripts', '--json', '--pack-destination', work,
  ], source));
  assert.equal(packed.length, 1);
  const item = packed[0];
  assert.ok(item);
  const archive = resolve(work, item.filename);
  assert.equal(archive, join(work, 'agent-tunnel-client-0.0.0.tgz'));
  const observations = [];
  for (const rootOverride of [false, true]) {
    const consumer = join(work, rootOverride ? 'with-root-override' : 'without-root-override');
    mkdirSync(consumer);
    writeFileSync(join(consumer, 'package.json'), JSON.stringify({
      name: rootOverride ? 'consumer-fixed' : 'consumer-negative-control',
      version: '0.0.0', private: true,
      dependencies: {
        '@agent-tunnel/client': `file:${archive}`,
        'just-bash': '3.4.2',
      },
      ...(rootOverride ? { overrides: { 'just-bash': { minimatch: '11.0.1' } } } : {}),
    }, null, 2) + '\n');
    command([
      'install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund',
    ], consumer);
    const lockPath = join(consumer, 'package-lock.json');
    const lock: Lock = JSON.parse(readFileSync(lockPath, 'utf8'));
    assert.equal(lock.packages['node_modules/just-bash']?.version, '3.4.2');
    const matcher = lock.packages['node_modules/just-bash/node_modules/minimatch']
      ?? lock.packages['node_modules/minimatch'];
    assert.ok(matcher?.version);
    if (rootOverride) assert.equal(matcher.version, '11.0.1');
    else assert.match(matcher.version, /^10\./u, 'the packaged override must not masquerade as consumer protection');
    observations.push({
      rootOverride, matcher: matcher.version, lockSha256: digest(lockPath),
    });
  }
  process.stdout.write(JSON.stringify({
    gate: 'consumer-root-overrides', passed: true,
    archiveSha256: digest(archive), observations,
    ...(keep ? { artifacts: work } : {}),
  }) + '\n');
} finally {
  if (!keep) rmSync(work, { recursive: true, force: true });
}
