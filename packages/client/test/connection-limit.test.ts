/**
 * M6-C200: a relay listener at its connection limit answers `503
 * CONNECTION_LIMIT` with a retry hint, and this client must surface both.
 *
 * Before the fix the refusal reached a caller as `BACKEND_UNAVAILABLE` with no
 * hint, so a caller retrying a fresh connect had nothing to wait on. The Rust
 * `connect` reads the hint as: the body's `retry_after_ms`, else the
 * `Retry-After` header in seconds, else 1 s, capped at 300 s
 * (`connection_limit_retry_after_ms` in `crates/tunnel-client/src/lib.rs`).
 * This client reads it the same way.
 *
 * The body below is byte for byte the relay listener's `CONNECTION_LIMIT_BODY`
 * (`crates/tunnel-transport/src/server.rs`), sent with the listener's
 * `Retry-After: 1`. A loopback endpoint cannot prove a real listener answers
 * that; the harness gate `verify-m6-ts-connection-limit` drives this client
 * against a real over-limit listener for that.
 */

import { strict as assert } from 'node:assert';
import { after, describe, it } from 'node:test';

import * as client from '../src/index.ts';
import { connectFilesystem, fetchDescriptor } from '../src/filesystem.ts';
import { FilesystemError } from '../src/errors.ts';
import { descriptorFixture } from './harness/descriptor.ts';
import { startEndpoint, type Endpoint, type Failure } from './harness/endpoint.ts';

const RELAY_BODY =
  '{"code":"CONNECTION_LIMIT","execution":"not_dispatched",' +
  '"message":"relay listener connection limit reached",' +
  '"retryable":true,"retry_after_ms":1000}';

const open: Endpoint[] = [];
after(async () => {
  for (const endpoint of open) {
    await endpoint.close();
  }
});

const token = (): string => 'synthetic-consumer-token';

async function descriptorRefusal(failure: Failure): Promise<FilesystemError> {
  const endpoint = await startEndpoint({ descriptorFailure: failure });
  open.push(endpoint);
  try {
    await fetchDescriptor({ endpoint: endpoint.url, token, allowInsecureLoopback: true });
  } catch (error) {
    assert.ok(error instanceof FilesystemError, 'a FilesystemError');
    return error;
  }
  assert.fail('the descriptor fetch was not refused');
}

async function upgradeRefusal(failure: Failure): Promise<FilesystemError> {
  const endpoint = await startEndpoint({ descriptor: descriptorFixture(), upgradeFailure: failure });
  open.push(endpoint);
  try {
    await connectFilesystem({ endpoint: endpoint.url, token, allowInsecureLoopback: true });
  } catch (error) {
    assert.ok(error instanceof FilesystemError, 'a FilesystemError');
    return error;
  }
  assert.fail('the upgrade was not refused');
}

function hintOf(error: FilesystemError): unknown {
  return (error as unknown as { retryAfterMs?: unknown }).retryAfterMs;
}

describe('a relay listener at its connection limit (M6-C200)', () => {
  const relay: Failure = { status: 503, rawBody: RELAY_BODY, headers: { 'Retry-After': '1' } };

  for (const [stage, refuse] of [
    ['the descriptor GET', descriptorRefusal],
    ['the upgrade', upgradeRefusal],
  ] as const) {
    it(`is CONNECTION_LIMIT with its retry hint at ${stage}`, async () => {
      const error = await refuse(relay);
      assert.equal(error.code, 'CONNECTION_LIMIT');
      assert.equal(hintOf(error), 1000);
      assert.equal(error.retryable, true);
      assert.equal(error.outcome, 'not_started');
      // The message stays code and operation only.
      assert.doesNotMatch(error.message, /limit reached|1000|retry/i);
    });
  }

  const precedence: [string, Failure, number][] = [
    [
      'the body hint wins over the header',
      { status: 503, rawBody: '{"code":"CONNECTION_LIMIT","retry_after_ms":2500}', headers: { 'Retry-After': '7' } },
      2500,
    ],
    [
      'the header is read when the body has no hint',
      { status: 503, rawBody: '{"code":"CONNECTION_LIMIT"}', headers: { 'Retry-After': '7' } },
      7000,
    ],
    [
      'the header alone identifies the refusal when no body arrived',
      { status: 503, rawBody: '', headers: { 'Retry-After': '3' } },
      3000,
    ],
    ['the default is one second', { status: 503, rawBody: '{"code":"CONNECTION_LIMIT"}' }, 1000],
    [
      'a negative body hint is not a hint',
      { status: 503, rawBody: '{"code":"CONNECTION_LIMIT","retry_after_ms":-5}', headers: { 'Retry-After': '2' } },
      2000,
    ],
    [
      'a fractional body hint is not a hint',
      { status: 503, rawBody: '{"code":"CONNECTION_LIMIT","retry_after_ms":2.5}', headers: { 'Retry-After': '2' } },
      2000,
    ],
    [
      'an HTTP-date header is not read',
      { status: 503, rawBody: '{"code":"CONNECTION_LIMIT"}', headers: { 'Retry-After': 'Wed, 21 Oct 2026 07:28:00 GMT' } },
      1000,
    ],
    [
      'a huge body hint is capped at 300 s',
      { status: 503, rawBody: '{"code":"CONNECTION_LIMIT","retry_after_ms":10000000}' },
      300_000,
    ],
    [
      'a huge header hint is capped at 300 s',
      { status: 503, rawBody: '', headers: { 'Retry-After': '86400' } },
      300_000,
    ],
  ];
  for (const [name, failure, expected] of precedence) {
    it(name, async () => {
      for (const refuse of [descriptorRefusal, upgradeRefusal]) {
        const error = await refuse(failure);
        assert.equal(error.code, 'CONNECTION_LIMIT');
        assert.equal(hintOf(error), expected);
        assert.equal(error.retryable, true);
      }
    });
  }

  const others: [string, Failure, string][] = [
    [
      'another 503 code keeps its own code and carries no hint, even with Retry-After',
      {
        status: 503,
        body: { error: { code: 'ROTATION_FREEZE', message: 'diagnostic', requestId: 'r' } },
        headers: { 'Retry-After': '1' },
      },
      'ROTATION_FREEZE',
    ],
    [
      'a flat body naming another code is that other refusal',
      { status: 503, rawBody: '{"code":"BACKEND_UNAVAILABLE"}', headers: { 'Retry-After': '1' } },
      'BACKEND_UNAVAILABLE',
    ],
    [
      'a 503 with neither a body code nor a readable Retry-After is not a connection limit',
      { status: 503, rawBody: 'a proxy wrote this' },
      'BACKEND_UNAVAILABLE',
    ],
    [
      'a CONNECTION_LIMIT body on another status is not this refusal',
      { status: 429, rawBody: RELAY_BODY, headers: { 'Retry-After': '1' } },
      'RESOURCE_EXHAUSTED',
    ],
  ];
  for (const [name, failure, expected] of others) {
    it(name, async () => {
      for (const refuse of [descriptorRefusal, upgradeRefusal]) {
        const error = await refuse(failure);
        assert.equal(error.code, expected);
        assert.equal(hintOf(error), undefined);
      }
    });
  }

  it('exports the default and the cap a caller retry loop needs', () => {
    const exported = client as unknown as Record<string, unknown>;
    assert.equal(exported['DEFAULT_CONNECTION_LIMIT_RETRY_AFTER_MS'], 1000);
    assert.equal(exported['MAX_HONOURED_RETRY_AFTER_MS'], 300_000);
  });
});
