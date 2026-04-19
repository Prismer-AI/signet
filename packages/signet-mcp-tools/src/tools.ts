/**
 * Signet MCP tools — server factory.
 *
 * Extracted from server.ts so tests can create a server instance
 * without triggering stdio transport side-effects.
 */
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import {
  generateKeypair,
  sign,
  verifyAny,
  contentHash,
  type SignetAction,
} from '@signet-auth/core';

export function createSignetToolsServer(): Server {
  const server = new Server(
    { name: 'signet-mcp-tools', version: '0.9.1' },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: 'signet_generate_keypair',
        description: 'Create a fresh Ed25519 identity for demos, tests, or agent bootstrapping. Returns JSON with {public_key, note}. The secret key is intentionally not returned by this MCP tool, so use Signet CLI or your own secure key storage for long-lived identities.',
        inputSchema: { type: 'object' as const, properties: {} },
      },
      {
        name: 'signet_sign',
        description: 'Create a Signet receipt for a tool call before execution. The secret key is read from the SIGNET_SECRET_KEY environment variable (never passed as an argument). Returns the full signed receipt JSON.',
        inputSchema: {
          type: 'object' as const,
          properties: {
            tool: { type: 'string', description: 'Name of the tool or action being attested, for example github_create_issue or file_write.' },
            params: { description: 'Exact JSON arguments to bind into the receipt. Changing this JSON later will change the params hash and invalidate verification expectations.' },
            signer_name: { type: 'string', description: 'Stable signer or agent name that will appear in the receipt, such as ci-agent or research-bot.' },
            signer_owner: { type: 'string', description: 'Optional human, team, or org that owns the signer identity.' },
            target: { type: 'string', description: 'Optional target URI for the system where the action will run, such as mcp://github.local.' },
          },
          required: ['tool', 'signer_name'],
        },
      },
      {
        name: 'signet_verify',
        description: 'Verify that a receipt was signed by the expected public key. Use this to validate receipts from agents, logs, tests, or exchanged MCP metadata. Returns JSON {valid: boolean}. This checks signature validity against the supplied key; it does not enforce freshness, authorization, or policy decisions.',
        inputSchema: {
          type: 'object' as const,
          properties: {
            receipt_json: { type: 'string', description: 'Serialized receipt JSON to verify. This should be the full receipt object as a string.' },
            public_key: { type: 'string', description: 'Expected signer public key, either bare base64 or ed25519:base64.' },
          },
          required: ['receipt_json', 'public_key'],
        },
      },
      {
        name: 'signet_content_hash',
        description: 'Compute a deterministic SHA-256 hash over canonical JSON using RFC 8785 JCS. Use this when you need a stable digest for receipt params, audit records, or comparing semantically identical JSON with different formatting or key order. Returns JSON {hash: string}.',
        inputSchema: {
          type: 'object' as const,
          properties: {
            content: { description: 'Any JSON value to hash: object, array, string, number, boolean, or null.' },
          },
          required: ['content'],
        },
      },
    ],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    try {
      switch (name) {
        case 'signet_generate_keypair': {
          const kp = generateKeypair();
          // Only return public key — secret key management via CLI/env
          return {
            content: [{ type: 'text', text: JSON.stringify({ public_key: kp.publicKey, note: 'This is an ephemeral keypair for demos/tests. The secret key was not returned for security. For persistent identities, use: signet identity generate --name <name>' }) }],
          };
        }

        case 'signet_sign': {
          const secretKey = process.env.SIGNET_SECRET_KEY;
          if (!secretKey) {
            return {
              content: [{ type: 'text', text: 'Error: SIGNET_SECRET_KEY environment variable is not set. Set it before starting the server.' }],
              isError: true,
            };
          }
          if (!args?.tool || !args?.signer_name) {
            return {
              content: [{ type: 'text', text: 'Error: tool and signer_name are required.' }],
              isError: true,
            };
          }
          const action: SignetAction = {
            tool: args.tool as string,
            params: args?.params ?? {},
            params_hash: '',
            target: (args?.target as string) ?? '',
            transport: 'mcp',
          };
          const receipt = sign(
            secretKey,
            action,
            args.signer_name as string,
            (args?.signer_owner as string) ?? '',
          );
          return {
            content: [{ type: 'text', text: JSON.stringify(receipt) }],
          };
        }

        case 'signet_verify': {
          if (!args?.receipt_json || !args?.public_key) {
            return {
              content: [{ type: 'text', text: 'Error: receipt_json and public_key are required.' }],
              isError: true,
            };
          }
          const valid = verifyAny(args.receipt_json as string, args.public_key as string);
          return {
            content: [{ type: 'text', text: JSON.stringify({ valid }) }],
          };
        }

        case 'signet_content_hash': {
          const hash = contentHash(args?.content);
          return {
            content: [{ type: 'text', text: JSON.stringify({ hash }) }],
          };
        }

        default:
          return {
            content: [{ type: 'text', text: `Unknown tool: ${name}` }],
            isError: true,
          };
      }
    } catch (err) {
      return {
        content: [{ type: 'text', text: `Error: ${err instanceof Error ? err.message : String(err)}` }],
        isError: true,
      };
    }
  });

  return server;
}
