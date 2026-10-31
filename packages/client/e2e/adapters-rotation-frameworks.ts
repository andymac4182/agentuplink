/** Installed framework calls used by the real-relay rotation gate. */
import { Files, FilesError } from 'files-sdk';
import { Workspace } from '@mastra/core/workspace';
import * as workspaceModule from '@mastra/core/workspace';
import { Agent } from '@mastra/core/agent';
import { Bash } from 'just-bash';
import { uploadFile } from 'ai';
import type { RemoteFilesystem } from '../src/filesystem.ts';
import { FilesystemError } from '../src/errors.ts';
import { createFilesAdapter } from '../src/adapters/files-sdk.ts';
import { TunnelMastraFilesystem } from '../src/adapters/mastra.ts';
import { TunnelJustBashFilesystem, REQUIRED_DEFENSE_EXCLUSIONS } from '../src/adapters/just-bash.ts';
import { createFilesApi } from '../src/adapters/ai-sdk.ts';
import { scriptedModel } from '../demo/scripted-model.ts';
import { fixtureText } from './adapters-rotation-support.ts';

export type Adapter = 'files' | 'mastra' | 'ai' | 'bash';
export type Role = 'read' | 'write' | 'revoked';
export interface WriteResult {
  success: boolean;
  nativeFailure: boolean;
  unknown: boolean;
  noRetry: boolean;
  nativeAmbiguityVisible: boolean;
  incompleteUploads: number;
}
export interface Binding {
  prepare(): Promise<void>;
  read(): Promise<boolean>;
  write(): Promise<WriteResult>;
  close(): void;
}

const SUCCESS: WriteResult = {
  success: true, nativeFailure: false, unknown: false, noRetry: false,
  nativeAmbiguityVisible: false, incompleteUploads: 0,
};

function underlying(error: unknown): FilesystemError | undefined {
  let current = error;
  for (let depth = 0; depth < 5; depth += 1) {
    if (current instanceof FilesystemError) return current;
    current = current instanceof Error ? current.cause : undefined;
  }
  return undefined;
}

function failed(error: unknown, nativeAmbiguityVisible: boolean): WriteResult {
  const cause = underlying(error);
  return {
    success: false, nativeFailure: true, unknown: cause?.outcome === 'unknown',
    noRetry: cause?.retryable === false, nativeAmbiguityVisible, incompleteUploads: 0,
  };
}

/** Observes the exact error thrown to Mastra; does not replace or transform it. */
class ObservedMastraFilesystem extends TunnelMastraFilesystem {
  failure: unknown;
  override async writeFile(...args: Parameters<TunnelMastraFilesystem['writeFile']>): Promise<void> {
    try {
      await super.writeFile(...args);
    } catch (error) {
      this.failure = error;
      throw error;
    }
  }
}

export function binding(adapter: Adapter, role: Role, remote: RemoteFilesystem): Binding {
  const path = `/${adapter}/${role}.txt`;
  const expectedRead = fixtureText(adapter, 'read');
  const writeText = fixtureText(adapter, role);
  switch (adapter) {
    case 'files': {
      // Zero retries would make the ambiguous-mutation retry assertion vacuous.
      const files = new Files({ adapter: createFilesAdapter({ remote, FilesError }), retries: 5 });
      return {
        async prepare() {},
        async read() { return await (await files.download(`${adapter}/read.txt`)).text() === expectedRead; },
        async write() {
          try {
            await files.upload(path.slice(1), writeText);
            return SUCCESS;
          } catch (error) {
            const result = failed(error, error instanceof FilesError && underlying(error)?.outcome === 'unknown');
            result.noRetry &&= error instanceof FilesError && error.permanent === true;
            return result;
          }
        },
        close() {},
      };
    }
    case 'mastra': {
      const filesystem = new ObservedMastraFilesystem({ remote, errors: workspaceModule });
      const workspace = new Workspace({ filesystem });
      const call = async (toolName: string, input: Record<string, unknown>): Promise<string> => {
        const { model } = scriptedModel([{ toolName, input }]);
        const agent = new Agent({
          id: `rotation-${role}`, name: `rotation-${role}`,
          instructions: 'Perform exactly the supplied filesystem tool call.', model, workspace,
        });
        const result = await agent.generate('Perform the supplied operation.', { maxSteps: 2 });
        // Mastra excludes failed tools from toolResults. Its public content
        // carries those as tool-result/output:error-text, including [unknown].
        return JSON.stringify(result.steps.flatMap((step) => step.content.flatMap((part) =>
          part.type === 'tool-result' ? [part.output] : [])));
      };
      return {
        async prepare() {},
        async read() {
          return (await call('mastra_workspace_read_file', { path: '/mastra/read.txt' })).includes(expectedRead);
        },
        async write() {
          try {
            const rendered = await call('mastra_workspace_write_file', { path, content: writeText });
            if (filesystem.failure !== undefined) {
              // The inner error alone is insufficient: its ambiguity must also
              // survive the real tool loop that the application consumes.
              return failed(filesystem.failure, /TUNNEL_UNKNOWN|unknown/u.test(rendered));
            }
            if (!rendered.includes('Wrote 4096 bytes')) throw new Error('mastra-no-write-result');
            return SUCCESS;
          } catch (error) {
            return failed(error, underlying(error)?.outcome === 'unknown');
          }
        },
        close() {},
      };
    }
    case 'ai': {
      const api = createFilesApi({ remote, uploadDirectory: `/ai/${role}` });
      let reference: Awaited<ReturnType<typeof uploadFile>>['providerReference'] | undefined;
      return {
        async prepare() {
          if (role === 'read') {
            reference = (await uploadFile({ api, data: new TextEncoder().encode(expectedRead), mediaType: 'text/plain' })).providerReference;
          }
        },
        async read() {
          if (reference === undefined) throw new Error('ai-missing-read-reference');
          const downloaded = await api.downloadFile?.({ file: reference });
          if (!(downloaded?.content instanceof ReadableStream)) throw new Error('ai-missing-download');
          return await new Response(downloaded.content).text() === expectedRead;
        },
        async write() {
          try {
            await uploadFile({ api, data: new TextEncoder().encode(writeText), mediaType: 'text/plain' });
            return SUCCESS;
          } catch (error) {
            const result = failed(error, error instanceof FilesystemError && error.outcome === 'unknown');
            result.incompleteUploads = api.incompleteUploads().length;
            return result;
          }
        },
        close() { api.close(); },
      };
    }
    case 'bash': {
      const filesystem = new TunnelJustBashFilesystem({ remote });
      const bash = new Bash({ fs: filesystem, cwd: '/', defenseInDepth: { excludeViolationTypes: [...REQUIRED_DEFENSE_EXCLUSIONS] } });
      return {
        async prepare() {},
        async read() {
          const result = await bash.exec('cat /bash/read.txt');
          return result.exitCode === 0 && result.stdout === expectedRead;
        },
        async write() {
          let failure: unknown;
          let success = false;
          try {
            // fixtureText contains only fixed ASCII characters, no shell syntax.
            success = (await bash.exec(`printf '%s' '${writeText}' > ${path}`)).exitCode === 0;
          } catch (error) { failure = error; }
          const ledger = filesystem.drainOperationFailures();
          if (success && ledger.entries.length === 0 && ledger.dropped === 0) return SUCCESS;
          const entry = ledger.entries[0];
          const unknown = ledger.dropped === 0 && ledger.entries.length === 1 && entry?.outcome === 'unknown';
          return {
            ...failed(failure, unknown), unknown, noRetry: unknown,
            nativeFailure: !success, nativeAmbiguityVisible: unknown,
          };
        },
        close() {},
      };
    }
  }
}
