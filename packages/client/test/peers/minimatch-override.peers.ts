/**
 * C252: the actual matcher resolved by just-bash, its preprocessing bounds,
 * and native shell behavior under the scoped consumer-root override.
 * The advisory requires optimizationLevel >= 2; just-bash's ordinary matcher
 * call supplies no such option. The bounded dependency control below is not
 * a claim that our remote Bash default reproduced an exploit.
 */
import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { after, describe, it } from 'node:test';
import { Bash } from 'just-bash';

import { REQUIRED_DEFENSE_EXCLUSIONS, TunnelJustBashFilesystem } from '../../src/adapters/just-bash.ts';
import { closeAll, wire } from '../adapters/wiring.ts';

after(closeAll);

const require = createRequire(import.meta.url);
const bashRequire = createRequire(require.resolve('just-bash'));
const matcherPath = bashRequire.resolve('minimatch');
const matcher: typeof import('minimatch') = bashRequire('minimatch');

// The original eight-block input produces only 256 patterns, so even the
// negative control is small. A separate process, heap cap and hard timeout
// keep a future regression from hanging the complete peer suite. The result
// asserts the denial bound directly; a fast run alone is not a passing oracle.
const boundedProbe = `
  const { Minimatch } = require(process.argv[1]);
  const mode = process.argv[2];
  if (mode === 'split') {
    const pattern = Array(8).fill('**/../a/b').join('/');
    const mm = new Minimatch(pattern, { optimizationLevel: 2, braceExpandMax: 64 });
    process.stdout.write(JSON.stringify({ patterns: mm.set.length }));
  } else if (mode === 'dedupe') {
    const mm = new Minimatch('{x,*}/{0..599}', { optimizationLevel: 2 });
    process.stdout.write(JSON.stringify({
      patterns: mm.set.length,
      literal: mm.match('x/5'),
      wildcard: mm.match('y/599'),
      hidden: mm.match('.y/5'),
    }));
  } else { throw new Error('unknown synthetic probe'); }
`;

function probe(mode: 'split' | 'dedupe'): unknown {
  const child = spawnSync(process.execPath, [
    '--max-old-space-size=128', '--input-type=commonjs', '-e', boundedProbe, matcherPath, mode,
  ], { encoding: 'utf8', timeout: 6000, killSignal: 'SIGKILL', maxBuffer: 16_384 });
  assert.equal(child.error, undefined, 'bounded matcher subprocess must complete');
  assert.equal(child.signal, null, 'bounded matcher subprocess must not be killed');
  assert.equal(child.status, 0, child.stderr);
  return JSON.parse(child.stdout);
}

describe('just-bash minimatch override', () => {
  it('resolves the fixed matcher from just-bash and declares the consuming-root override', () => {
    const manifest = JSON.parse(readFileSync(bashRequire.resolve('minimatch/package.json'), 'utf8'));
    assert.equal(manifest.version, '11.0.1');
    const root = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8'));
    assert.deepEqual(root.overrides['just-bash'], { minimatch: '11.0.1' });
    assert.equal(root.peerDependencies['just-bash'], '3.4.2');
    assert.equal(root.devDependencies['just-bash'], '3.4.2');
    assert.equal(typeof matcher.minimatch, 'function');
  });

  it('caps advisory split amplification at the explicit pattern bound', () => {
    assert.deepEqual(probe('split'), { patterns: 64 });
  });

  it('avoids quadratic large-set deduplication while preserving matches', () => {
    assert.deepEqual(probe('dedupe'), {
      patterns: 1200, literal: true, wildcard: true, hidden: false,
    });
  });

  it('retains below-bound parent/globstar matching and ordinary glob options', () => {
    const mm = new matcher.Minimatch('**/../a/b/**/../c/d', { optimizationLevel: 2 });
    assert.equal(mm.set.length, 4);
    assert.equal(mm.match('../a/b/../c/d'), true);
    assert.equal(mm.match('x/a/b/y/c/d'), true);
    assert.equal(mm.match('x/a/b/y/c/other'), false);
    assert.equal(matcher.minimatch('nested/a.txt', '**/*.{txt,md}'), true);
    assert.equal(matcher.minimatch('nested/a.bin', '**/*.{txt,md}'), false);
    assert.equal(matcher.minimatch('.hidden.txt', '*.txt'), false);
    assert.equal(matcher.minimatch('.hidden.txt', '*.txt', { dot: true }), true);
    assert.equal(matcher.minimatch('A.TXT', '*.txt', { nocase: true }), true);
  });

  it('runs quoted globs through the real Bash ls matcher', async () => {
    const bash = new Bash({
      files: { '/docs/a.txt': 'a', '/docs/b.md': 'b', '/docs/.hidden.txt': 'hidden' },
      cwd: '/docs',
      defenseInDepth: { excludeViolationTypes: [...REQUIRED_DEFENSE_EXCLUSIONS] },
    });
    const text = await bash.exec("ls '*.txt'");
    assert.equal(text.exitCode, 0, text.stderr);
    assert.equal(text.stdout, 'a.txt\n');
    const brace = await bash.exec("ls '*.{txt,md}'");
    assert.equal(brace.exitCode, 0, brace.stderr);
    assert.deepEqual(brace.stdout.trim().split(/\s+/u).sort(), ['a.txt', 'b.md']);
    const absent = await bash.exec("ls '*.absent'");
    assert.equal(absent.exitCode, 2);
    assert.equal(absent.stdout, '');
  });

  it('keeps real Bash directory glob reads over the tunnel adapter', async () => {
    const wired = await wire({ 'a.txt': 'a', 'b.txt': 'b', 'skip.md': 'other' });
    const fs = new TunnelJustBashFilesystem({ remote: wired.remote });
    const bash = new Bash({
      fs, cwd: '/',
      defenseInDepth: { excludeViolationTypes: [...REQUIRED_DEFENSE_EXCLUSIONS] },
    });
    const result = await bash.exec("printf '%s\\n' *.txt");
    assert.equal(result.exitCode, 0, result.stderr);
    assert.deepEqual(result.stdout.trim().split('\n').sort(), ['a.txt', 'b.txt']);
    assert.ok(wired.connection.received.some((message) => message.kind === 'Treaddir'));
    assert.equal(wired.connection.received.some((message) => message.kind === 'Twrite'), false);
    assert.deepEqual(fs.drainOperationFailures(), { entries: [], dropped: 0 });
  });
});
