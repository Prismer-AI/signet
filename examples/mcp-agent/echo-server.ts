import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

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

server.setRequestHandler(CallToolRequestSchema, async (request) => ({
  content: [
    {
      type: 'text' as const,
      text: JSON.stringify(request.params.arguments ?? {}),
    },
  ],
}));

const transport = new StdioServerTransport();
await server.connect(transport);
