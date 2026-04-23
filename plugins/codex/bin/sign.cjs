#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

function writeStderr(stderr, message) {
  stderr.write(message);
}

function processInput(raw, env = process.env, stderr = process.stderr) {
  const signetDir = env.SIGNET_HOME
    || path.join(os.homedir(), '.signet');
  const keyPath = path.join(signetDir, 'keys', 'codex-agent.key');

  if (!raw || !raw.trim()) return;

  // Parse stdin JSON
  let input;
  try {
    input = JSON.parse(raw);
  } catch {
    writeStderr(stderr, 'signet: failed to parse stdin JSON\n');
    return;
  }

  const toolName = input.tool_name || 'unknown';
  const toolInput = input.tool_input || {};
  const sessionId = input.session_id ?? null;
  const toolUseId = input.tool_use_id ?? null;
  const toolResponse = input.tool_response;

  // Load WASM wrapper (lazy)
  const signet = require('../lib/signet.cjs');
  const audit = require('../lib/audit.cjs');

  // Load or create key
  let key;
  try {
    key = signet.loadOrCreateKey(keyPath);
  } catch (err) {
    writeStderr(stderr, 'signet: ' + err.message + '\n');
    return;
  }

  // Sign the action
  const action = {
    tool: toolName,
    params: toolInput,
    params_hash: signet.contentHash(toolInput),
    target: 'codex://local',
    transport: 'stdio',
  };
  if (sessionId !== null) action.session = sessionId;
  if (toolUseId !== null) action.call_id = toolUseId;
  if (toolResponse !== undefined) {
    action.response_hash = signet.contentHash(toolResponse);
  }

  let receipt;
  try {
    receipt = signet.sign(key.secretKey, action, 'codex-agent');
  } catch (err) {
    writeStderr(stderr, 'signet: signing failed: ' + err.message + '\n');
    return;
  }

  // Append to audit log
  const MAX_META_SIZE = 64 * 1024;
  const meta = {};
  if (toolResponse !== undefined) {
    const responseStr = JSON.stringify(toolResponse);
    if (responseStr.length <= MAX_META_SIZE) {
      meta.tool_response = toolResponse;
    } else {
      meta.tool_response_truncated = true;
      meta.tool_response_size = responseStr.length;
    }
  }
  if (input.cwd) meta.cwd = input.cwd;
  if (input.transcript_path) meta.transcript_path = input.transcript_path;
  try {
    audit.append(signetDir, receipt, Object.keys(meta).length > 0 ? meta : null);
  } catch (err) {
    writeStderr(stderr, 'signet: audit append failed: ' + err.message + '\n');
  }
}

function main() {
  let raw;
  try {
    raw = fs.readFileSync(0, 'utf8');
  } catch {
    return;
  }
  processInput(raw);
}

if (require.main === module) {
  try {
    main();
  } catch (err) {
    writeStderr(process.stderr, 'signet: unexpected error: ' + err.message + '\n');
  }
}

module.exports = { main, processInput };
