import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createVerifierServer, loadVerifyOptions } from './verifier-server-lib.mjs';

const verifyOptions = loadVerifyOptions();
if ((verifyOptions.requireTrustedSigner ?? true) && (verifyOptions.trustedKeys?.length ?? 0) === 0) {
  console.error(
    '[signet] No SIGNET_TRUSTED_KEYS configured; signed requests will be rejected until trust anchors are set. ' +
    'Set SIGNET_REQUIRE_TRUSTED_SIGNER=false only for signature-only demos.',
  );
}
const server = createVerifierServer(verifyOptions);
const transport = new StdioServerTransport();

await server.connect(transport);
