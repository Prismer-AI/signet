#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
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

const server = new Server(
  { name: 'signet-mcp-tools', version: '0.4.0' },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'signet_generate_keypair',
      description: 'Generate a new Ed25519 keypair for agent signing',
      inputSchema: { type: 'object', properties: {} },
    },
    {
      name: 'signet_sign',
      description: 'Sign an action (tool call) with an Ed25519 key, producing a cryptographic receipt',
      inputSchema: {
        type: 'object',
        properties: {
          secret_key: { type: 'string', description: 'Base64 secret key (from generate_keypair)' },
          tool: { type: 'string', description: 'Tool name being called' },
          params: { type: 'object', description: 'Tool parameters' },
          signer_name: { type: 'string', description: 'Agent name' },
          target: { type: 'string', description: 'Target MCP server URI' },
        },
        required: ['secret_key', 'tool', 'signer_name'],
      },
    },
    {
      name: 'signet_verify',
      description: 'Verify a Signet receipt signature. Returns true if valid, false if tampered.',
      inputSchema: {
        type: 'object',
        properties: {
          receipt_json: { type: 'string', description: 'Receipt JSON string' },
          public_key: { type: 'string', description: 'Base64 public key of the signer' },
        },
        required: ['receipt_json', 'public_key'],
      },
    },
    {
      name: 'signet_content_hash',
      description: 'Compute SHA-256 hash of canonical JSON (RFC 8785 JCS). Used for response binding.',
      inputSchema: {
        type: 'object',
        properties: {
          content: { type: 'object', description: 'JSON content to hash' },
        },
        required: ['content'],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  switch (name) {
    case 'signet_generate_keypair': {
      const kp = generateKeypair();
      return {
        content: [{ type: 'text', text: JSON.stringify({ secret_key: kp.secretKey, public_key: kp.publicKey }) }],
      };
    }

    case 'signet_sign': {
      const action: SignetAction = {
        tool: (args?.tool as string) ?? 'unknown',
        params: args?.params ?? {},
        params_hash: '',
        target: (args?.target as string) ?? '',
        transport: 'mcp',
      };
      const receipt = sign(
        args?.secret_key as string,
        action,
        (args?.signer_name as string) ?? 'unknown',
        (args?.signer_owner as string) ?? '',
      );
      return {
        content: [{ type: 'text', text: JSON.stringify(receipt) }],
      };
    }

    case 'signet_verify': {
      const valid = verifyAny(args?.receipt_json as string, args?.public_key as string);
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
});

const transport = new StdioServerTransport();
await server.connect(transport);
