import { generateKeypair, sign } from '@signet-auth/core';
import { verifyRequest } from '@signet-auth/mcp-server';

const TOOL = 'delete_prod_env';
const TARGET = 'mcp://prod';
const REQUEST_ARGS = {
  environment: 'prod',
  requested_by: 'demo-runner',
  confirm: true,
};

// ANSI color helpers
const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const CYAN = '\x1b[36m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const RESET = '\x1b[0m';

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

function printHeader() {
  console.log(`${CYAN}${BOLD}╔══════════════════════════════════════════════════════╗${RESET}`);
  console.log(`${CYAN}${BOLD}║   Signet Execution Boundary — Reject Bad Requests   ║${RESET}`);
  console.log(`${CYAN}${BOLD}╚══════════════════════════════════════════════════════╝${RESET}`);
  console.log(`${DIM}Dangerous tool: ${RESET}${YELLOW}${TOOL}${RESET}`);
  console.log(`${DIM}Server policy: reject requests before execution unless verification succeeds.${RESET}`);
  console.log('');
}

function printResult(index, total, label, result, toolName) {
  const paddedLabel = label.padEnd(22, ' ');

  if (result.ok) {
    const detail = `signer=${result.signerName}`;
    console.log(`[${index}/${total}] ${paddedLabel} -> ${GREEN}${BOLD}✅ ALLOWED ${RESET} ${GREEN}${detail}${RESET}`);
    console.log(`       ${GREEN}${BOLD}EXECUTE${RESET}  ${GREEN}${toolName}${RESET} ${DIM}(simulated)${RESET}`);
  } else {
    const detail = result.error ?? 'verification failed';
    console.log(`[${index}/${total}] ${paddedLabel} -> ${RED}${BOLD}❌ REJECTED${RESET} ${DIM}${detail}${RESET}`);
    console.log(`       ${RED}BLOCKED${RESET}  ${DIM}before execution${RESET}`);
  }
}

async function main() {
  printHeader();

  const total = 5;

  // 1. Unsigned request
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

  // 2. Tampered arguments
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

  // 3. Wrong target
  {
    const request = signedRequest();
    const result = verifyRequest(request, {
      trustedKeys: [trustedKey],
      expectedTarget: 'mcp://staging',
    });
    printResult(3, total, 'wrong target', result, TOOL);
  }

  // 4. Expired receipt
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

  // 5. Valid signed request
  {
    const request = signedRequest();
    const result = verifyRequest(request, {
      trustedKeys: [trustedKey],
      expectedTarget: TARGET,
    });
    printResult(5, total, 'valid signed request', result, TOOL);
  }

  console.log('');
  console.log(`${BOLD}Only verified requests reach the execution boundary.${RESET}`);
  console.log(`${GREEN}${BOLD}✓${RESET} Unsigned, tampered, stale, or mis-targeted calls ${RED}never run${RESET}.`);
}

await main();
