import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { verifyRequest } from '@signet-auth/mcp-server';

// In production, load trusted keys from config or environment.
// For this demo, we accept any valid signature (requireSignature: false).
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
  // Verify the agent's signature (log-only mode for this example)
  const verified = verifyRequest(request, VERIFY_OPTS);
  if (verified.ok) {
    console.error(`[signet] Verified: ${verified.signerName} (${verified.signerPubkey})`);
  } else if (verified.error !== 'unsigned request') {
    console.error(`[signet] Warning: ${verified.error}`);
  }

  return {
    content: [
      {
        type: 'text' as const,
        text: JSON.stringify(request.params.arguments ?? {}),
      },
    ],
  };
});

const transport = new StdioServerTransport();
await server.connect(transport);
