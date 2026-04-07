#!/usr/bin/env node
/**
 * @signet-auth/mcp-tools — Standalone MCP server exposing Signet crypto tools.
 *
 * Security note: signet_sign requires a secret key as input. This is inherent
 * to the signing operation. In production, use SIGNET_SECRET_KEY env var instead
 * of passing keys through tool arguments. The generate_keypair tool only returns
 * the public key — secret keys should be managed via the Signet CLI keystore.
 */
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createSignetToolsServer } from './tools.js';

const server = createSignetToolsServer();
const transport = new StdioServerTransport();
await server.connect(transport);
