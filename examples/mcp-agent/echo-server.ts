import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { generateKeypair } from '@signet-auth/core';
import { verifyRequest, signResponse } from '@signet-auth/mcp-server';

// Generate server identity (in production, load from keystore)
const serverKp = generateKeypair();
console.error(`[signet] Server public key: ${serverKp.publicKey}`);

const VERIFY_OPTS = { requireSignature: false };

const server = new Server(
  { name: 'echo-server', version: '1.0.0' },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: 'echo',
      description: 'Echoes back the input',
      inputSchema: {
        type: 'object' as const,
        properties: { message: { type: 'string' } },
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  // 1. Verify agent signature
  const verified = verifyRequest(request, VERIFY_OPTS);
  if (verified.ok) {
    console.error(`[signet] Verified agent: ${verified.signerName}`);
  } else if (verified.error !== 'unsigned request') {
    console.error(`[signet] Warning: ${verified.error}`);
  }

  // 2. Execute tool call
  const result = {
    content: [
      {
        type: 'text' as const,
        text: JSON.stringify(request.params.arguments ?? {}),
      },
    ],
  };

  // 3. Co-sign response if agent signed the request (even if untrusted)
  const hasSigmet = (request.params as any)?._meta?._signet;
  if (hasSigmet) {
    try {
      const bilateral = signResponse(request, result, {
        serverKey: serverKp.secretKey,
        serverName: 'echo-server',
      });
      console.error(`[signet] Bilateral receipt: ${bilateral.id}`);
      return { ...result, _meta: { _signet_bilateral: bilateral } };
    } catch (err) {
      console.error(`[signet] Co-sign failed: ${err}`);
    }
  }

  return result;
});

const transport = new StdioServerTransport();
await server.connect(transport);
