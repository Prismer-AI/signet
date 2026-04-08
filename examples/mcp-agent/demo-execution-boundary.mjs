import { generateKeypair, sign } from '@signet-auth/core';
import { verifyRequest } from '@signet-auth/mcp-server';

const TOOL = 'delete_prod_env';
const TARGET = 'mcp://infra.prod';
const REQUEST_ARGS = {
  environment: 'prod',
  requested_by: 'demo-runner',
  confirm: true,
};

const kp = generateKeypair();
const trustedKey = `ed25519:${kp.publicKey}`;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function makeAction(tool, args, target = TARGET) {
  return {
    tool,
    params: args,
    params_hash: '',
    target,
    transport: 'stdio',
  };
}

function signedRequest(tool = TOOL, args = REQUEST_ARGS, target = TARGET) {
  const receipt = sign(kp.secretKey, makeAction(tool, args, target), 'demo-agent', 'signet-demo');
  return {
    params: {
      name: tool,
      arguments: args,
      _meta: { _signet: receipt },
    },
  };
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function formatCaseLabel(label, width = 22) {
  return label.padEnd(width, ' ');
}

function printHeader() {
  console.log('=== Signet Execution-Boundary Demo ===');
  console.log(`Dangerous tool: ${TOOL}`);
  console.log('Server policy: reject requests before execution unless verification succeeds.');
  console.log('');
}

function printResult(index, total, label, result, toolName) {
  const status = result.ok ? 'ALLOWED ' : 'REJECTED';
  const detail = result.ok
    ? `signer=${result.signerName}`
    : result.error ?? 'verification failed';

  console.log(`[${index}/${total}] ${formatCaseLabel(label)} -> ${status} ${detail}`);
  if (result.ok) {
    console.log(`       EXECUTE  ${toolName} (simulated)`);
  } else {
    console.log('       BLOCKED  before execution');
  }
}

async function main() {
  printHeader();

  const total = 5;

  {
    const request = {
      params: {
        name: TOOL,
        arguments: REQUEST_ARGS,
      },
    };
    const result = verifyRequest(request, {
      requireSignature: true,
      trustedKeys: [trustedKey],
      expectedTarget: TARGET,
    });
    printResult(1, total, 'unsigned request', result, TOOL);
  }

  {
    const request = signedRequest();
    request.params.arguments = {
      ...REQUEST_ARGS,
      confirm: false,
    };
    const result = verifyRequest(request, {
      trustedKeys: [trustedKey],
      expectedTarget: TARGET,
    });
    printResult(2, total, 'tampered arguments', result, TOOL);
  }

  {
    const request = signedRequest();
    const result = verifyRequest(request, {
      trustedKeys: [trustedKey],
      expectedTarget: 'mcp://infra.staging',
    });
    printResult(3, total, 'wrong target', result, TOOL);
  }

  {
    const request = signedRequest();
    await sleep(10);
    const result = verifyRequest(request, {
      trustedKeys: [trustedKey],
      expectedTarget: TARGET,
      maxAge: 0,
    });
    printResult(4, total, 'expired receipt', result, TOOL);
  }

  {
    const request = signedRequest();
    const result = verifyRequest(request, {
      trustedKeys: [trustedKey],
      expectedTarget: TARGET,
    });
    printResult(5, total, 'valid signed request', result, TOOL);
  }

  console.log('');
  console.log('Only verified requests reach the execution boundary.');
  console.log('Signet turns tool calls from trust-me-bro metadata into verifiable requests.');
}

await main();
