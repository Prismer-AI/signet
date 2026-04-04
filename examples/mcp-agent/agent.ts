import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { generateKeypair } from '@signet-auth/core';
import { SigningTransport } from '@signet-auth/mcp';

// Generate agent identity
const { secretKey, publicKey } = generateKeypair();
console.log('Agent public key:', publicKey);

// Create signed transport wrapping stdio
const inner = new StdioClientTransport({
  command: 'npx',
  args: ['tsx', 'echo-server.ts'],
});

const transport = new SigningTransport(inner as any, secretKey, 'demo-agent', 'demo-owner', {
  target: 'mcp://echo-server',
  transport: 'stdio',
  onDispatch: (receipt) => {
    console.log(`[dispatch] ${receipt.id} | tool: ${receipt.action.tool}`);
  },
  onReceipt: (compound) => {
    console.log(`[compound] ${compound.id} | response hash: ${compound.response.content_hash.slice(0, 20)}...`);
  },
  onBilateral: (bilateral) => {
    console.log(`[bilateral] ${bilateral.id} | server: ${bilateral.server.name} | agent: ${bilateral.agent_receipt.signer.name}`);
  },
});

// Connect client
const client = new Client(
  { name: 'demo-agent', version: '1.0.0' },
  { capabilities: {} },
);
await client.connect(transport as any);

// List tools
const tools = await client.listTools();
console.log('Available tools:', tools.tools.map((t) => t.name).join(', '));

// Call echo tool
const result = await client.callTool({
  name: 'echo',
  arguments: { message: 'Hello from Signet!' },
});
console.log('Response:', JSON.stringify(result.content));

// Cleanup
await client.close();
console.log('\nDone. Agent signed request, server co-signed response. Full bilateral flow.');
