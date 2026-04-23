import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { generateKeypair } from '@signet-auth/core';
import { verifyRequest, signResponse } from '@signet-auth/mcp-server';

function stripEd25519Prefix(publicKey: string): string {
  return publicKey.startsWith('ed25519:')
    ? publicKey.slice('ed25519:'.length)
    : publicKey;
}

// Generate server identity (in production, load from keystore)
const configuredServerSecretKey = process.env.SIGNET_SERVER_SECRET_KEY;
const configuredServerPublicKey = process.env.SIGNET_SERVER_PUBLIC_KEY;
const generatedServerKp = generateKeypair();
const serverKp = configuredServerSecretKey
  ? {
      secretKey: configuredServerSecretKey,
      publicKey: configuredServerPublicKey
        ? stripEd25519Prefix(configuredServerPublicKey)
        : generatedServerKp.publicKey,
    }
  : generatedServerKp;
console.error(`[signet] Server public key: ${configuredServerPublicKey ?? `ed25519:${serverKp.publicKey}`}`);

const trustedKeys = (process.env.SIGNET_TRUSTED_KEYS ?? '')
  .split(',')
  .map((value) => value.trim())
  .filter(Boolean);

const VERIFY_OPTS = {
  requireSignature: true,
  trustedKeys,
};

const server = new Server(
  { name: 'echo-server', version: '1.0.0' },
  { capabilities: { tools: {} } },
);

if (!trustedKeys.length) {
  console.error('[signet] No SIGNET_TRUSTED_KEYS configured; signed requests will not be treated as trusted.');
}

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
  if (verified.ok && verified.trusted) {
    console.error(`[signet] Verified agent: ${verified.signerName}`);
  } else if (!verified.ok) {
    console.error(`[signet] Warning: ${verified.error}`);
    return {
      content: [{ type: 'text' as const, text: verified.error ?? 'verification failed' }],
      isError: true,
    };
  } else {
    console.error('[signet] Warning: request signature verified, but signer is not trusted');
    return {
      content: [{ type: 'text' as const, text: 'untrusted signer' }],
      isError: true,
    };
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

  // 3. Co-sign only after a trusted verification pass.
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

  return result;
});

const transport = new StdioServerTransport();
await server.connect(transport);
