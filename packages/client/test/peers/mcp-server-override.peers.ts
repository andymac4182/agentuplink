/**
 * The scoped Mastra override changes its installed MCP server SDK, not the
 * filesystem adapter. Exercise the actual replacement SDK in addition to the
 * unchanged Mastra Agent contract in contract.peers.ts. Mastra core imports
 * this SDK only for ElicitRequest/ElicitResult/ServerContext types; its own
 * MCPServerBase is abstract, not an HTTP server implementation.
 */
import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { describe, it } from 'node:test';
import {
  createMcpHandler,
  McpServer,
  requireBearerAuth,
  type AuthInfo,
  type ElicitRequest,
  type ElicitResult,
  type ServerContext,
} from '@modelcontextprotocol/server';
import type { MCPServerContext } from '@mastra/core/tools';

const endpoint = 'https://synthetic-mcp.example.test/mcp';

// Compile the precise upstream type members Mastra core references, without
// assertions substituting our own interface for the installed declarations.
type MastraContextParts = Pick<MCPServerContext, 'signal' | 'requestId' | 'authInfo' | 'sendNotification' | 'sendRequest' | '_meta'>;
function mastraContextParts(context: ServerContext): MastraContextParts {
  return {
    signal: context.mcpReq.signal,
    requestId: context.mcpReq.id,
    authInfo: context.http?.authInfo,
    sendNotification: context.mcpReq.notify,
    sendRequest: context.mcpReq.send,
    _meta: context.mcpReq._meta,
  };
}
type MastraElicitation = (request: ElicitRequest['params']) => Promise<ElicitResult>;
const elicitation: MastraElicitation = async () => ({ action: 'decline' });

function request(method: string, params: Record<string, unknown>, token = 'synthetic-a'): Request {
  return new Request(endpoint, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      'mcp-protocol-version': '2025-11-25',
      authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
}

async function result(response: Response): Promise<Record<string, unknown>> {
  assert.equal(response.status, 200);
  const body = await response.text();
  const json = response.headers.get('content-type')?.startsWith('text/event-stream')
    ? body.split('\n').find((line) => line.startsWith('data: '))?.slice(6)
    : body;
  assert.ok(json, 'the server returned a JSON-RPC response');
  const message = JSON.parse(json);
  assert.equal(message.id, 1);
  assert.equal(message.error, undefined);
  return message.result;
}

function fixture() {
  let instances = 0;
  let calls = 0;
  const handler = createMcpHandler(({ authInfo }) => {
    instances += 1;
    const server = new McpServer({ name: 'override-smoke', version: '0.0.0' });
    server.registerTool('principal', { description: 'Return synthetic caller identity' }, async () => {
      calls += 1;
      await new Promise((resolve) => setImmediate(resolve));
      return { content: [{ type: 'text', text: authInfo?.clientId ?? 'missing' }] };
    });
    return server;
  }, { maxRequestBodySize: 1024 });
  const gate = requireBearerAuth({
    expectedResource: new URL(endpoint),
    requiredScopes: ['mcp'],
    verifier: {
      async verifyAccessToken(token): Promise<AuthInfo> {
        return {
          token,
          clientId: token,
          scopes: ['mcp'],
          expiresAt: Math.floor(Date.now() / 1000) + 60,
          resource: new URL(token === 'wrong-audience' ? 'https://other.example.test/mcp' : endpoint),
        };
      },
    },
  });
  return {
    handler,
    instances: () => instances,
    calls: () => calls,
    async fetch(req: Request): Promise<Response> {
      const auth = await gate(req);
      return auth instanceof Response ? auth : handler.fetch(req, { authInfo: auth });
    },
  };
}

describe('Mastra MCP server SDK override', () => {
  it('resolves the fixed SDK from Mastra and retains its referenced context types', async () => {
    const require = createRequire(import.meta.url);
    const mastraRequire = createRequire(require.resolve('@mastra/core'));
    const manifest = JSON.parse(readFileSync(resolve(dirname(mastraRequire.resolve('@modelcontextprotocol/server')), '../package.json'), 'utf8'));
    assert.equal(manifest.version, '2.3.0');
    assert.equal(typeof mastraContextParts, 'function');
    assert.deepEqual(await elicitation({ message: 'synthetic', requestedSchema: { type: 'object', properties: {} } }), { action: 'decline' });
  });

  it('initializes, lists tools and executes overlapping calls without mixing principals', async () => {
    const f = fixture();
    try {
      const initialized = await result(await f.fetch(request('initialize', {
        protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'override-smoke', version: '0.0.0' },
      })));
      assert.equal(initialized.protocolVersion, '2025-11-25');
      const listed = await result(await f.fetch(request('tools/list', {})));
      assert.deepEqual((listed.tools as { name: string }[]).map((tool) => tool.name), ['principal']);
      const [a, b] = await Promise.all(['synthetic-a', 'synthetic-b'].map(async (token) =>
        result(await f.fetch(request('tools/call', { name: 'principal', arguments: {} }, token)))));
      assert.ok(a && b);
      assert.deepEqual(a.content, [{ type: 'text', text: 'synthetic-a' }]);
      assert.deepEqual(b.content, [{ type: 'text', text: 'synthetic-b' }]);
      assert.equal(f.calls(), 2);
      assert.equal(f.instances(), 4);
    } finally { await f.handler.close(); }
  });

  it('rejects a token for another audience before constructing or calling a server', async () => {
    const f = fixture();
    try {
      const response = await f.fetch(request('tools/call', { name: 'principal', arguments: {} }, 'wrong-audience'));
      assert.equal(response.status, 401);
      assert.match(response.headers.get('www-authenticate') ?? '', /invalid_token/u);
      assert.equal(f.instances(), 0);
      assert.equal(f.calls(), 0);
    } finally { await f.handler.close(); }
  });

  it('bounds the HTTP body before constructing or calling a server', async () => {
    const f = fixture();
    try {
      const response = await f.fetch(request('tools/call', { name: 'principal', arguments: { excess: 'x'.repeat(1024) } }));
      assert.equal(response.status, 413);
      assert.equal(f.instances(), 0);
      assert.equal(f.calls(), 0);
    } finally { await f.handler.close(); }
  });
});
