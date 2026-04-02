import { describe, it } from 'node:test';
import assert from 'node:assert';
import { generateKeypair, type CompoundReceipt } from '@signet-auth/core';
import { SigningTransport, type Transport, type JSONRPCMessage } from '../src/index.js';

// Mock transport that records sent messages and supports simulating responses
class MockTransport implements Transport {
  sent: JSONRPCMessage[] = [];
  private messageHandler?: (msg: JSONRPCMessage, extra?: unknown) => void;

  onclose?: () => void;
  onerror?: (error: Error) => void;

  // Capture the onmessage handler set by SigningTransport
  set onmessage(handler: ((msg: JSONRPCMessage, extra?: unknown) => void) | undefined) {
    this.messageHandler = handler;
  }
  get onmessage() { return this.messageHandler; }

  async start() {}
  async close() {}
  async send(message: JSONRPCMessage) {
    this.sent.push(JSON.parse(JSON.stringify(message)));
  }

  // Simulate a response from the server
  simulateResponse(id: string | number, result: unknown) {
    this.messageHandler?.({ jsonrpc: '2.0', id, result } as JSONRPCMessage, undefined);
  }
  simulateError(id: string | number, error: unknown) {
    this.messageHandler?.({ jsonrpc: '2.0', id, error } as JSONRPCMessage, undefined);
  }
}

describe('@signet-auth/mcp SigningTransport v2', () => {
  const kp = generateKeypair();

  function createTransport(opts?: { responseTimeout?: number; onReceipt?: (r: CompoundReceipt) => void }) {
    const mock = new MockTransport();
    const signing = new SigningTransport(mock, kp.secretKey, 'test-agent', 'owner', {
      target: 'mcp://test-server',
      transport: 'stdio',
      ...opts,
    });
    return { mock, signing };
  }

  function toolCallMessage(id: string | number, name: string, args: Record<string, unknown>): JSONRPCMessage {
    return {
      jsonrpc: '2.0',
      id,
      method: 'tools/call',
      params: { name, arguments: args },
    };
  }

  it('signs compound receipt on response', async () => {
    let receipt: CompoundReceipt | null = null;
    const { mock, signing } = createTransport({ onReceipt: (r) => { receipt = r; } });

    await signing.send(toolCallMessage(1, 'echo', { message: 'hello' }));
    mock.simulateResponse(1, { content: [{ type: 'text', text: 'hello' }] });

    assert(receipt !== null, 'onReceipt should have been called');
    const r = receipt as CompoundReceipt;
    assert.strictEqual(r.v, 2);
    assert(r.id.startsWith('rec_'));
    assert(r.sig.startsWith('ed25519:'));
    assert.strictEqual(r.signer.name, 'test-agent');
    assert.strictEqual(r.action.tool, 'echo');
  });

  it('compound receipt has response hash', async () => {
    let receipt: CompoundReceipt | null = null;
    const { mock, signing } = createTransport({ onReceipt: (r) => { receipt = r; } });

    await signing.send(toolCallMessage(2, 'search', { query: 'test' }));
    mock.simulateResponse(2, { content: [{ type: 'text', text: 'results' }] });

    assert(receipt !== null);
    assert((receipt as CompoundReceipt).response.content_hash.startsWith('sha256:'));
  });

  it('produces compound receipt on error response', async () => {
    let receipt: CompoundReceipt | null = null;
    const { mock, signing } = createTransport({ onReceipt: (r) => { receipt = r; } });

    await signing.send(toolCallMessage(3, 'fail_tool', {}));
    mock.simulateError(3, { code: -32000, message: 'tool failed' });

    assert(receipt !== null, 'onReceipt should fire even on error responses');
    const r = receipt as CompoundReceipt;
    assert.strictEqual(r.v, 2);
    assert(r.response.content_hash.startsWith('sha256:'));
  });

  it('passes through non-tool-call messages unchanged', async () => {
    let receipt: CompoundReceipt | null = null;
    const { mock, signing } = createTransport({ onReceipt: (r) => { receipt = r; } });

    const listMsg: JSONRPCMessage = { jsonrpc: '2.0', id: 4, method: 'tools/list', params: {} };
    await signing.send(listMsg);

    assert.strictEqual(mock.sent.length, 1);
    const sent = mock.sent[0] as unknown as Record<string, unknown>;
    // No _meta injection in v2
    const params = sent['params'] as Record<string, unknown> | undefined;
    assert.strictEqual(params?._meta, undefined);

    // Simulate a response — should not produce a receipt since it wasn't a tool call
    mock.simulateResponse(4, {});
    assert.strictEqual(receipt, null, 'no receipt for non-tool-call responses');
  });

  it('does not fire onReceipt after timeout', async () => {
    let receiptCount = 0;
    const { mock, signing } = createTransport({
      responseTimeout: 50,
      onReceipt: () => { receiptCount++; },
    });

    await signing.send(toolCallMessage(5, 'slow_tool', {}));

    // Wait longer than timeout before simulating response
    await new Promise<void>((resolve) => setTimeout(resolve, 100));
    mock.simulateResponse(5, { content: [] });

    assert.strictEqual(receiptCount, 0, 'no receipt after timeout');
  });

  it('close clears pending requests — no receipt after close', async () => {
    let receiptCount = 0;
    const { mock, signing } = createTransport({
      onReceipt: () => { receiptCount++; },
    });

    await signing.send(toolCallMessage(6, 'some_tool', {}));
    await signing.close();
    mock.simulateResponse(6, { content: [] });

    assert.strictEqual(receiptCount, 0, 'no receipt after close clears pending');
  });
});
