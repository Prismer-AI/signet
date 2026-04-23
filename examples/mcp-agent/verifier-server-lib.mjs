import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { verifyAny } from '@signet-auth/core';
import { verifyRequest } from '@signet-auth/mcp-server';

const DEFAULT_MAX_AGE = 300;
const DEFAULT_REQUIRE_SIGNATURE = true;
const DEFAULT_REQUIRE_TRUSTED_SIGNER = true;
const TRUST_ANCHOR_REQUIRED_ERROR = 'trusted signer required but no trusted keys are configured';
const SIGNATURE_ONLY_STATUS = 'signature-only';
const TRUSTED_STATUS = 'trusted';

export function loadVerifyOptions(env = process.env) {
  return {
    trustedKeys: splitCsv(env.SIGNET_TRUSTED_KEYS),
    requireSignature: parseBoolean(env.SIGNET_REQUIRE_SIGNATURE, DEFAULT_REQUIRE_SIGNATURE),
    requireTrustedSigner: parseBoolean(
      env.SIGNET_REQUIRE_TRUSTED_SIGNER,
      DEFAULT_REQUIRE_TRUSTED_SIGNER,
    ),
    maxAge: parseInteger(env.SIGNET_MAX_AGE, DEFAULT_MAX_AGE),
    ...(env.SIGNET_EXPECTED_TARGET ? { expectedTarget: env.SIGNET_EXPECTED_TARGET } : {}),
  };
}

export const TOOLS = [
  {
    name: 'inspect_current_request',
    description: 'Verify the current MCP tool call using Signet request receipts in params._meta._signet.',
    inputSchema: {
      type: 'object',
      properties: {
        note: {
          type: 'string',
          description: 'Optional note echoed back in the inspection response.',
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'verify_receipt',
    description: 'Verify a Signet receipt JSON payload against an Ed25519 public key.',
    inputSchema: {
      type: 'object',
      properties: {
        receiptJson: {
          type: 'string',
          description: 'Raw JSON string for a Signet v1 or v2 receipt.',
        },
        publicKey: {
          type: 'string',
          description: 'Base64 Ed25519 public key, with or without the ed25519: prefix.',
        },
      },
      required: ['receiptJson', 'publicKey'],
      additionalProperties: false,
    },
  },
  {
    name: 'verify_request_payload',
    description: 'Verify a synthetic MCP tools/call params object that includes params._meta._signet.',
    inputSchema: {
      type: 'object',
      properties: {
        request: {
          type: 'object',
          description: 'MCP CallTool params object, for example {name, arguments, _meta:{_signet}}.',
          additionalProperties: true,
        },
        trustedKeys: {
          type: 'array',
          description: 'Optional ed25519:<base64> trusted keys that override server defaults.',
          items: { type: 'string' },
        },
        requireSignature: {
          type: 'boolean',
          description: 'Whether to reject requests that do not include _meta._signet.',
        },
        requireTrustedSigner: {
          type: 'boolean',
          description: 'Whether valid signatures must also match a configured trusted key.',
        },
        maxAge: {
          type: 'integer',
          description: 'Maximum receipt age in seconds.',
        },
        expectedTarget: {
          type: 'string',
          description: 'Optional expected receipt.action.target value.',
        },
      },
      required: ['request'],
      additionalProperties: false,
    },
  },
];

export function createVerifierServer(verifyOptions = loadVerifyOptions()) {
  const server = new Server(
    { name: 'signet-verifier', version: '0.1.0' },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOLS,
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const name = request.params.name;
    const args = normalizeObject(request.params.arguments, 'arguments');

    try {
      switch (name) {
        case 'inspect_current_request':
          return jsonResult(inspectCurrentRequest(request, verifyOptions, args.note));
        case 'verify_receipt':
          return jsonResult(verifyReceiptPayload(args));
        case 'verify_request_payload':
          return jsonResult(verifySyntheticRequestPayload(args, verifyOptions));
        default:
          return jsonResult({ error: `Unknown tool: ${String(name)}` }, true);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return jsonResult({ error: message }, true);
    }
  });

  return server;
}

export function inspectCurrentRequest(request, verifyOptions, note) {
  const params = request.params ?? {};
  const hasReceipt = hasSignetReceipt(params);
  const verification = enforceVerifyPolicy(verifyRequest(request, verifyOptions), verifyOptions);

  return {
    server: {
      name: 'signet-verifier',
      requireSignature: verifyOptions.requireSignature ?? DEFAULT_REQUIRE_SIGNATURE,
      requireTrustedSigner: verifyOptions.requireTrustedSigner ?? DEFAULT_REQUIRE_TRUSTED_SIGNER,
      trustedKeyCount: verifyOptions.trustedKeys?.length ?? 0,
      maxAge: verifyOptions.maxAge ?? DEFAULT_MAX_AGE,
      expectedTarget: verifyOptions.expectedTarget ?? null,
    },
    request: {
      tool: params.name ?? null,
      hasReceipt,
      arguments: params.arguments ?? {},
      note: typeof note === 'string' ? note : null,
    },
    verification: {
      ok: verification.ok,
      signerName: verification.signerName ?? null,
      signerPubkey: verification.signerPubkey ?? null,
      trusted: verification.trusted ?? false,
      error: verification.error ?? null,
      status: deriveVerificationStatus(verification, hasReceipt),
    },
  };
}

export function verifyReceiptPayload(args) {
  const receiptJson = expectString(args.receiptJson, 'receiptJson');
  const rawPublicKey = expectString(args.publicKey, 'publicKey');
  const publicKey = stripEd25519Prefix(rawPublicKey);

  return {
    ok: verifyAny(receiptJson, publicKey),
    publicKeyFormat: rawPublicKey.startsWith('ed25519:') ? 'prefixed' : 'bare',
  };
}

export function verifySyntheticRequestPayload(args, defaultOptions) {
  const request = normalizeObject(args.request, 'request');
  const toolName = expectString(request.name, 'request.name');
  const params = {
    name: toolName,
    arguments: request.arguments ?? {},
    _meta: request._meta ?? {},
  };

  const options = {
    ...defaultOptions,
    ...(Array.isArray(args.trustedKeys) ? { trustedKeys: args.trustedKeys.map(String) } : {}),
    ...(typeof args.requireSignature === 'boolean' ? { requireSignature: args.requireSignature } : {}),
    ...(typeof args.requireTrustedSigner === 'boolean'
      ? { requireTrustedSigner: args.requireTrustedSigner }
      : {}),
    ...(typeof args.maxAge === 'number' ? { maxAge: args.maxAge } : {}),
    ...(typeof args.expectedTarget === 'string' ? { expectedTarget: args.expectedTarget } : {}),
  };

  const result = enforceVerifyPolicy(verifyRequest({ params }, options), options);

  return {
    request: {
      tool: params.name ?? null,
      hasReceipt: hasSignetReceipt(params),
    },
    verification: {
      ok: result.ok,
      signerName: result.signerName ?? null,
      signerPubkey: result.signerPubkey ?? null,
      trusted: result.trusted ?? false,
      error: result.error ?? null,
      status: deriveVerificationStatus(result, hasSignetReceipt(params)),
    },
    options: {
      requireSignature: options.requireSignature ?? DEFAULT_REQUIRE_SIGNATURE,
      requireTrustedSigner: options.requireTrustedSigner ?? DEFAULT_REQUIRE_TRUSTED_SIGNER,
      trustedKeyCount: options.trustedKeys?.length ?? 0,
      maxAge: options.maxAge ?? DEFAULT_MAX_AGE,
      expectedTarget: options.expectedTarget ?? null,
    },
  };
}

function jsonResult(payload, isError = false) {
  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(payload, null, 2),
      },
    ],
    ...(isError ? { isError: true } : {}),
  };
}

function hasSignetReceipt(params) {
  return Boolean(params?._meta?._signet);
}

function enforceVerifyPolicy(result, verifyOptions) {
  const requireTrustedSigner =
    verifyOptions.requireTrustedSigner ?? DEFAULT_REQUIRE_TRUSTED_SIGNER;
  if (!result.ok || !requireTrustedSigner || !result.hasReceipt || result.trusted) {
    return result;
  }

  if ((verifyOptions.trustedKeys?.length ?? 0) === 0) {
    return {
      ...result,
      ok: false,
      error: TRUST_ANCHOR_REQUIRED_ERROR,
      trusted: false,
    };
  }

  return {
    ...result,
    ok: false,
    error: result.error ?? 'signer is not trusted',
    trusted: false,
  };
}

function deriveVerificationStatus(result, hasReceipt) {
  if (result.ok && hasReceipt && result.trusted) return TRUSTED_STATUS;
  if (result.ok && hasReceipt) return SIGNATURE_ONLY_STATUS;
  if (okForUnsignedRequest(result, hasReceipt)) return 'unsigned-allowed';
  if (result.error === TRUST_ANCHOR_REQUIRED_ERROR) return 'trust-not-configured';
  if (typeof result.error === 'string' && result.error.startsWith('untrusted signer:')) {
    return 'untrusted-signer';
  }
  if (hasReceipt) return 'rejected';
  return 'unsigned-rejected';
}

function okForUnsignedRequest(result, hasReceipt) {
  return result.ok && !hasReceipt;
}

function splitCsv(value) {
  if (!value) return [];
  return value
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function parseBoolean(value, fallback) {
  if (value === undefined) return fallback;
  const normalized = String(value).trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
  return fallback;
}

function parseInteger(value, fallback) {
  if (value === undefined) return fallback;
  const parsed = Number.parseInt(String(value), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function normalizeObject(value, fieldName) {
  if (value === undefined) return {};
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return value;
  }
  throw new Error(`${fieldName} must be an object`);
}

function expectString(value, fieldName) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${fieldName} must be a non-empty string`);
  }
  return value;
}

function stripEd25519Prefix(publicKey) {
  return publicKey.startsWith('ed25519:')
    ? publicKey.slice('ed25519:'.length)
    : publicKey;
}
