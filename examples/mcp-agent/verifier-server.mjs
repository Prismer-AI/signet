import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createVerifierServer, loadVerifyOptions } from './verifier-server-lib.mjs';

const verifyOptions = loadVerifyOptions();
const server = createVerifierServer(verifyOptions);
const transport = new StdioServerTransport();

await server.connect(transport);
