#!/usr/bin/env node
/**
 * @signet-auth/mcp-tools — Standalone MCP server exposing Signet crypto tools.
 *
 * signet_sign reads the secret key from the SIGNET_SECRET_KEY environment
 * variable. Keys are never accepted as tool arguments.
 */
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createSignetToolsServer } from './tools.js';

const server = createSignetToolsServer();
const transport = new StdioServerTransport();
await server.connect(transport);
