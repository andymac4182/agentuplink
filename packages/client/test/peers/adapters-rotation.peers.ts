/** Driver preflight only: installed frameworks against the loopback provider,
 * not evidence about relay rotation or authoritative grant revocation. */
import { strict as assert } from 'node:assert';
import { after, test } from 'node:test';
import { binding, type Adapter } from '../../e2e/adapters-rotation-frameworks.ts';
import { fixtureText } from '../../e2e/adapters-rotation-support.ts';
import { wire, waitFor, closeAll } from '../adapters/wiring.ts';

after(closeAll);

for (const adapter of ['files', 'mastra', 'ai', 'bash'] satisfies Adapter[]) {
  test(`${adapter} rotation driver uses real framework read/write calls`, async () => {
    const wired = await wire({ [`${adapter}/read.txt`]: fixtureText(adapter, 'read'), 'ai/read/.keep': '', 'ai/write/.keep': '' });
    const read = binding(adapter, 'read', wired.remote);
    const write = binding(adapter, 'write', wired.remote);
    try {
      await read.prepare();
      assert.equal(await read.read(), true);
      assert.equal((await write.write()).success, true);
      assert.equal(await read.read(), true);
    } finally { read.close(); write.close(); wired.remote.close(); }
  });

  test(`${adapter} rotation driver observes the native unknown outcome without replay`, async () => {
    const wired = await wire({ [`${adapter}/.keep`]: '', 'ai/revoked/.keep': '' }, {}, (provider) => {
      provider.swallow.add('Twrite');
    });
    const write = binding(adapter, 'revoked', wired.remote);
    try {
      const pending = write.write();
      await waitFor(() => wired.connection.received.some((message) => message.kind === 'Twrite'));
      wired.connection.close(1008, 'AUTH_EXPIRED');
      const result = await pending;
      assert.equal(result.success, false);
      assert.equal(result.nativeFailure, true);
      assert.equal(result.unknown, true);
      assert.equal(result.noRetry, true);
      assert.equal(result.nativeAmbiguityVisible, true);
      assert.equal(wired.connection.received.filter((message) => message.kind === 'Twrite').length, 1);
      if (adapter === 'ai') assert.equal(result.incompleteUploads, 1);
    } finally { write.close(); wired.remote.close(); }
  });
}
