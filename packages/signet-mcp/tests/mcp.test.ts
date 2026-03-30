import { describe, it } from 'node:test';
import assert from 'node:assert';
import { generateKeypair, type SignetReceipt } from '@signet-auth/core';
import { SigningTransport, type Transport, type JSONRPCMessage } from '../src/index.js';

// Mock transport that records sent messages
class MockTransport implements Transport {
  sent: JSONRPCMessage[] = [];
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage, extra?: unknown) => void;
  sessionId?: string;

  async start() {}
  async close() {}
  async send(message: JSONRPCMessage) {
    this.sent.push(JSON.parse(JSON.stringify(message)));
  }
}

describe('@signet-auth/mcp SigningTransport', () => {
  const kp = generateKeypair();

  function createTransport() {
    const mock = new MockTransport();
    const signing = new SigningTransport(mock, kp.secretKey, 'test-agent', 'owner', {
      target: 'mcp://test-server',
      transport: 'stdio',
    });
    return { mock, signing };
  }

  function toolCallMessage(name: string, args: Record<string, unknown>): JSONRPCMessage {
    return {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name, arguments: args },
    };
  }

  it('signs tool call messages', async () => {
    const { mock, signing } = createTransport();
    await signing.send(toolCallMessage('echo', { message: 'hello' }));

    assert.strictEqual(mock.sent.length, 1);
    const sent = mock.sent[0] as any;
    assert(sent.params._meta._signet, '_signet should be injected');
    assert(sent.params._meta._signet.sig.startsWith('ed25519:'));
    assert(sent.params._meta._signet.id.startsWith('rec_'));
  });

  it('passes through non-tool-call messages', async () => {
    const { mock, signing } = createTransport();
    const listMsg: JSONRPCMessage = { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} };
    await signing.send(listMsg);

    assert.strictEqual(mock.sent.length, 1);
    const sent = mock.sent[0] as any;
    assert.strictEqual(sent.params._meta, undefined);
  });

  it('receipt has correct tool name', async () => {
    const { mock, signing } = createTransport();
    await signing.send(toolCallMessage('github_create_issue', { title: 'bug' }));

    const signet = (mock.sent[0] as any).params._meta._signet;
    assert.strictEqual(signet.action.tool, 'github_create_issue');
  });

  it('receipt params are null (hash-only)', async () => {
    const { mock, signing } = createTransport();
    await signing.send(toolCallMessage('echo', { data: 'secret' }));

    const signet = (mock.sent[0] as any).params._meta._signet;
    assert.strictEqual(signet.action.params, null);
    assert(signet.action.params_hash.startsWith('sha256:'));
  });

  it('onSign callback fires with receipt', async () => {
    const mock = new MockTransport();
    let callbackReceipt: SignetReceipt | null = null;
    const signing = new SigningTransport(mock, kp.secretKey, 'test-agent', 'owner', {
      onSign: (r) => { callbackReceipt = r; },
    });
    await signing.send(toolCallMessage('test', {}));

    assert(callbackReceipt !== null, 'callback should have been called');
    const r = callbackReceipt as SignetReceipt;
    assert(r.id.startsWith('rec_'));
    assert.strictEqual(r.signer.name, 'test-agent');
  });
});
