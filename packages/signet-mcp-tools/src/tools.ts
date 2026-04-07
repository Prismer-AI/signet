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
    { name: 'signet-mcp-tools', version: '0.4.0' },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
      {
        name: 'signet_generate_keypair',
        description: 'Generate a new Ed25519 keypair. Returns only the public key. Use Signet CLI to manage secret keys securely.',
        inputSchema: { type: 'object' as const, properties: {} },
      },
      {
        name: 'signet_sign',
        description: 'Sign an action (tool call) with an Ed25519 key, producing a cryptographic receipt. Uses SIGNET_SECRET_KEY env var if set, otherwise requires secret_key argument.',
        inputSchema: {
          type: 'object' as const,
          properties: {
            secret_key: { type: 'string', description: 'Base64 secret key (optional if SIGNET_SECRET_KEY env is set)' },
            tool: { type: 'string', description: 'Tool name being called' },
            params: { description: 'Tool parameters (any JSON value)' },
            signer_name: { type: 'string', description: 'Agent name' },
            signer_owner: { type: 'string', description: 'Agent owner (optional)' },
            target: { type: 'string', description: 'Target MCP server URI' },
          },
          required: ['tool', 'signer_name'],
        },
      },
      {
        name: 'signet_verify',
        description: 'Verify a Signet receipt signature. Returns {valid: true/false}. Accepts both bare base64 and ed25519:-prefixed public keys.',
        inputSchema: {
          type: 'object' as const,
          properties: {
            receipt_json: { type: 'string', description: 'Receipt JSON string' },
            public_key: { type: 'string', description: 'Public key (base64 or ed25519:base64)' },
          },
          required: ['receipt_json', 'public_key'],
        },
      },
      {
        name: 'signet_content_hash',
        description: 'Compute SHA-256 hash of canonical JSON (RFC 8785 JCS). Accepts any JSON value.',
        inputSchema: {
          type: 'object' as const,
          properties: {
            content: { description: 'JSON content to hash (object, array, string, number, boolean, or null)' },
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
            content: [{ type: 'text', text: JSON.stringify({ public_key: kp.publicKey, note: 'Secret key generated but not returned. Use Signet CLI for key management.' }) }],
          };
        }

        case 'signet_sign': {
          const secretKey = (args?.secret_key as string) ?? process.env.SIGNET_SECRET_KEY;
          if (!secretKey) {
            return {
              content: [{ type: 'text', text: 'Error: no secret key. Set SIGNET_SECRET_KEY env var or pass secret_key argument.' }],
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
