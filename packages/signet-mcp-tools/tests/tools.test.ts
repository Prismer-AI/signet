import { describe, it } from 'node:test';
import assert from 'node:assert';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { generateKeypair } from '@signet-auth/core';
import { createSignetToolsServer } from '../src/tools.js';

async function createClient(): Promise<Client> {
  const server = createSignetToolsServer();
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: 'test-client', version: '1.0.0' });
  await client.connect(clientTransport);
  return client;
}

describe('@signet-auth/mcp-tools', () => {
  it('lists all 4 tools', async () => {
    const client = await createClient();
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name).sort();
    assert.deepStrictEqual(names, [
      'signet_content_hash',
      'signet_generate_keypair',
      'signet_sign',
      'signet_verify',
    ]);
  });

  it('signet_generate_keypair returns public_key', async () => {
    const client = await createClient();
    const result = await client.callTool({ name: 'signet_generate_keypair', arguments: {} });
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    const parsed = JSON.parse(text);
    assert(parsed.public_key, 'should return public_key');
    assert(typeof parsed.public_key === 'string');
    assert(parsed.note.includes('not returned'), 'should note that secret key is not returned');
  });

  it('signet_sign produces valid receipt', async () => {
    const client = await createClient();
    const kp = generateKeypair();
    const result = await client.callTool({
      name: 'signet_sign',
      arguments: {
        secret_key: kp.secretKey,
        tool: 'echo',
        params: { message: 'hello' },
        signer_name: 'test-agent',
        signer_owner: 'test-owner',
        target: 'mcp://test',
      },
    });
    assert(!result.isError, `Expected success, got error: ${JSON.stringify(result.content)}`);
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    const receipt = JSON.parse(text);
    assert.strictEqual(receipt.v, 1);
    assert(receipt.id.startsWith('rec_'));
    assert(receipt.sig.startsWith('ed25519:'));
    assert.strictEqual(receipt.action.tool, 'echo');
    assert.strictEqual(receipt.signer.name, 'test-agent');
    assert(receipt.action.params_hash.startsWith('sha256:'));
  });

  it('signet_sign without key returns error', async () => {
    const client = await createClient();
    const result = await client.callTool({
      name: 'signet_sign',
      arguments: { tool: 'echo', signer_name: 'agent' },
    });
    assert.strictEqual(result.isError, true);
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    assert(text.includes('no secret key'));
  });

  it('signet_sign without required fields returns error', async () => {
    const client = await createClient();
    const kp = generateKeypair();
    const result = await client.callTool({
      name: 'signet_sign',
      arguments: { secret_key: kp.secretKey },
    });
    assert.strictEqual(result.isError, true);
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    assert(text.includes('required'));
  });

  it('signet_verify with valid receipt returns valid: true', async () => {
    const client = await createClient();
    const kp = generateKeypair();

    // Sign first
    const signResult = await client.callTool({
      name: 'signet_sign',
      arguments: {
        secret_key: kp.secretKey,
        tool: 'echo',
        params: { msg: 'test' },
        signer_name: 'agent',
      },
    });
    const receiptJson = (signResult.content as Array<{ type: string; text: string }>)[0].text;

    // Verify
    const verifyResult = await client.callTool({
      name: 'signet_verify',
      arguments: { receipt_json: receiptJson, public_key: kp.publicKey },
    });
    const text = (verifyResult.content as Array<{ type: string; text: string }>)[0].text;
    assert.deepStrictEqual(JSON.parse(text), { valid: true });
  });

  it('signet_verify with wrong key returns valid: false', async () => {
    const client = await createClient();
    const kp1 = generateKeypair();
    const kp2 = generateKeypair();

    const signResult = await client.callTool({
      name: 'signet_sign',
      arguments: {
        secret_key: kp1.secretKey,
        tool: 'echo',
        params: {},
        signer_name: 'agent',
      },
    });
    const receiptJson = (signResult.content as Array<{ type: string; text: string }>)[0].text;

    const verifyResult = await client.callTool({
      name: 'signet_verify',
      arguments: { receipt_json: receiptJson, public_key: kp2.publicKey },
    });
    const text = (verifyResult.content as Array<{ type: string; text: string }>)[0].text;
    assert.deepStrictEqual(JSON.parse(text), { valid: false });
  });

  it('signet_verify accepts ed25519:-prefixed public key', async () => {
    const client = await createClient();
    const kp = generateKeypair();

    const signResult = await client.callTool({
      name: 'signet_sign',
      arguments: {
        secret_key: kp.secretKey,
        tool: 'echo',
        params: {},
        signer_name: 'agent',
      },
    });
    const receiptJson = (signResult.content as Array<{ type: string; text: string }>)[0].text;

    const verifyResult = await client.callTool({
      name: 'signet_verify',
      arguments: { receipt_json: receiptJson, public_key: `ed25519:${kp.publicKey}` },
    });
    const text = (verifyResult.content as Array<{ type: string; text: string }>)[0].text;
    assert.deepStrictEqual(JSON.parse(text), { valid: true });
  });

  it('signet_content_hash returns sha256 hash', async () => {
    const client = await createClient();
    const result = await client.callTool({
      name: 'signet_content_hash',
      arguments: { content: { hello: 'world' } },
    });
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    const parsed = JSON.parse(text);
    assert(parsed.hash.startsWith('sha256:'), `Expected sha256: prefix, got: ${parsed.hash}`);
  });

  it('signet_content_hash is deterministic', async () => {
    const client = await createClient();
    const content = { b: 2, a: 1 };

    const r1 = await client.callTool({ name: 'signet_content_hash', arguments: { content } });
    const r2 = await client.callTool({ name: 'signet_content_hash', arguments: { content } });

    const h1 = JSON.parse((r1.content as Array<{ type: string; text: string }>)[0].text).hash;
    const h2 = JSON.parse((r2.content as Array<{ type: string; text: string }>)[0].text).hash;
    assert.strictEqual(h1, h2);
  });

  it('signet_content_hash canonicalizes key order', async () => {
    const client = await createClient();

    const r1 = await client.callTool({ name: 'signet_content_hash', arguments: { content: { a: 1, b: 2 } } });
    const r2 = await client.callTool({ name: 'signet_content_hash', arguments: { content: { b: 2, a: 1 } } });

    const h1 = JSON.parse((r1.content as Array<{ type: string; text: string }>)[0].text).hash;
    const h2 = JSON.parse((r2.content as Array<{ type: string; text: string }>)[0].text).hash;
    assert.strictEqual(h1, h2, 'hash should be the same regardless of key order (JCS canonicalization)');
  });

  it('unknown tool returns error', async () => {
    const client = await createClient();
    const result = await client.callTool({ name: 'nonexistent_tool', arguments: {} });
    assert.strictEqual(result.isError, true);
    const text = (result.content as Array<{ type: string; text: string }>)[0].text;
    assert(text.includes('Unknown tool'));
  });

  it('sign → verify full roundtrip via MCP', async () => {
    const client = await createClient();
    const kp = generateKeypair();

    // Generate, sign, verify — all through the MCP server
    const signResult = await client.callTool({
      name: 'signet_sign',
      arguments: {
        secret_key: kp.secretKey,
        tool: 'github_create_issue',
        params: { title: 'fix bug', body: 'details' },
        signer_name: 'ci-agent',
        signer_owner: 'acme-corp',
        target: 'mcp://github.local',
      },
    });
    assert(!signResult.isError);
    const receiptJson = (signResult.content as Array<{ type: string; text: string }>)[0].text;
    const receipt = JSON.parse(receiptJson);

    // Verify with the signer's pubkey from the receipt itself
    const verifyResult = await client.callTool({
      name: 'signet_verify',
      arguments: { receipt_json: receiptJson, public_key: receipt.signer.pubkey },
    });
    const verified = JSON.parse((verifyResult.content as Array<{ type: string; text: string }>)[0].text);
    assert.strictEqual(verified.valid, true);

    // Also hash the params and compare with receipt
    const hashResult = await client.callTool({
      name: 'signet_content_hash',
      arguments: { content: { title: 'fix bug', body: 'details' } },
    });
    const hash = JSON.parse((hashResult.content as Array<{ type: string; text: string }>)[0].text).hash;
    assert.strictEqual(receipt.action.params_hash, hash, 'params_hash should match content_hash of params');
  });
});
