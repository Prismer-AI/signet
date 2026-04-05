import { describe, it } from 'node:test';
import assert from 'node:assert';
import { generateKeypair, sign, signBilateral, verifyAny, type BilateralReceipt, type CompoundReceipt, type SignetAction } from '@signet-auth/core';
import { SigningTransport, type Transport, type JSONRPCMessage, type SignetReceipt } from '../src/index.js';

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
  simulateResponseWithMeta(id: string | number, result: Record<string, unknown>, meta: Record<string, unknown>) {
    const msg = { jsonrpc: '2.0' as const, id, result: { ...result, _meta: meta } };
    this.messageHandler?.(msg, undefined);
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

  it('injects _meta._signet dispatch receipt into tool call message', async () => {
    const { mock, signing } = createTransport();

    await signing.send(toolCallMessage(7, 'echo', { message: 'hello' }));

    assert.strictEqual(mock.sent.length, 1);
    const params = mock.sent[0].params as Record<string, unknown>;
    const meta = params._meta as Record<string, unknown> | undefined;
    assert(meta !== undefined, '_meta should be present');
    const signet = meta._signet as SignetReceipt | undefined;
    assert(signet !== undefined, '_meta._signet should be present');
    assert(signet.sig.startsWith('ed25519:'), 'sig should start with ed25519:');
    assert.strictEqual(signet.v, 1);
  });

  it('fires onDispatch callback at send time', async () => {
    let dispatched: SignetReceipt | null = null;
    const mock = new MockTransport();
    const signing = new SigningTransport(mock, kp.secretKey, 'test-agent', 'owner', {
      target: 'mcp://test-server',
      transport: 'stdio',
      onDispatch: (r) => { dispatched = r; },
    });

    await signing.send(toolCallMessage(8, 'echo', { message: 'hello' }));

    assert(dispatched !== null, 'onDispatch should have been called');
    assert.strictEqual((dispatched as SignetReceipt).v, 1);
    assert((dispatched as SignetReceipt).sig.startsWith('ed25519:'));
  });

  it('dispatch receipt is verifiable with correct key', async () => {
    const { mock, signing } = createTransport();

    await signing.send(toolCallMessage(9, 'echo', { message: 'hello' }));

    const params = mock.sent[0].params as Record<string, unknown>;
    const meta = params._meta as Record<string, unknown>;
    const signet = meta._signet as SignetReceipt;

    const valid = verifyAny(JSON.stringify(signet), kp.publicKey);
    assert(valid, 'dispatch receipt should verify with the signer public key');
  });
});

describe('@signet-auth/mcp SigningTransport v3 bilateral extraction', () => {
  const agentKp = generateKeypair();
  const serverKp = generateKeypair();

  function makeAction(tool: string, args: Record<string, unknown>): SignetAction {
    return {
      tool,
      params: args,
      params_hash: '',
      target: 'mcp://test-server',
      transport: 'stdio',
    };
  }

  function buildBilateralResponse(responseContent: Record<string, unknown>): { result: Record<string, unknown>; bilateral: BilateralReceipt } {
    // Sign agent dispatch receipt
    const action = makeAction('echo', { message: 'hello' });
    const agentReceipt = sign(agentKp.secretKey, action, 'test-agent', 'owner');

    // Sign bilateral receipt with server key over the response content
    const tsResponse = new Date().toISOString();
    const bilateral = signBilateral(
      serverKp.secretKey,
      JSON.stringify(agentReceipt),
      responseContent,
      'test-server',
      tsResponse,
    );

    // The actual result includes both the content and the bilateral receipt in _meta
    const result = { ...responseContent, _meta: { _signet_bilateral: bilateral } };
    return { result, bilateral };
  }

  it('test_bilateral_extracted_from_response — server sends response with _signet_bilateral → onBilateral fires', async () => {
    let bilateralReceived: BilateralReceipt | null = null;
    const mock = new MockTransport();
    const signing = new SigningTransport(mock, agentKp.secretKey, 'test-agent', 'owner', {
      target: 'mcp://test-server',
      transport: 'stdio',
      trustedServerKeys: [`ed25519:${serverKp.publicKey}`],
      onBilateral: (r) => { bilateralReceived = r; },
    });

    await signing.send({ jsonrpc: '2.0', id: 10, method: 'tools/call', params: { name: 'echo', arguments: { message: 'hello' } } });

    const responseContent = { content: [{ type: 'text', text: 'world' }] };
    const { result } = buildBilateralResponse(responseContent);
    mock.simulateResponseWithMeta(10, responseContent, { _signet_bilateral: (result._meta as any)._signet_bilateral });

    assert(bilateralReceived !== null, 'onBilateral should have been called');
    assert.strictEqual((bilateralReceived as BilateralReceipt).v, 3);
    assert((bilateralReceived as BilateralReceipt).sig.startsWith('ed25519:'));
  });

  it('test_no_bilateral_on_plain_response — normal response → onBilateral not called', async () => {
    let bilateralReceived: BilateralReceipt | null = null;
    const mock = new MockTransport();
    const signing = new SigningTransport(mock, agentKp.secretKey, 'test-agent', 'owner', {
      target: 'mcp://test-server',
      transport: 'stdio',
      onBilateral: (r) => { bilateralReceived = r; },
    });

    await signing.send({ jsonrpc: '2.0', id: 11, method: 'tools/call', params: { name: 'echo', arguments: { message: 'hello' } } });
    mock.simulateResponse(11, { content: [{ type: 'text', text: 'world' }] });

    assert.strictEqual(bilateralReceived, null, 'onBilateral should not fire for plain responses');
  });

  it('test_bilateral_hash_mismatch — tampered response content but valid _signet_bilateral → onerror "hash mismatch"', async () => {
    const errors: Error[] = [];
    const mock = new MockTransport();
    const signing = new SigningTransport(mock, agentKp.secretKey, 'test-agent', 'owner', {
      target: 'mcp://test-server',
      transport: 'stdio',
      trustedServerKeys: [`ed25519:${serverKp.publicKey}`],
    });
    signing.onerror = (e) => { errors.push(e); };

    await signing.send({ jsonrpc: '2.0', id: 12, method: 'tools/call', params: { name: 'echo', arguments: { message: 'hello' } } });

    // Build bilateral over original content, but send tampered content
    const originalContent = { content: [{ type: 'text', text: 'original' }] };
    const { result } = buildBilateralResponse(originalContent);
    const bilateral = (result._meta as any)._signet_bilateral;

    // Tamper: send different content but keep original bilateral receipt (hash won't match)
    mock.simulateResponseWithMeta(12, { content: [{ type: 'text', text: 'tampered' }] }, { _signet_bilateral: bilateral });

    assert(errors.length > 0, 'onerror should have been called');
    assert(errors[0].message.includes('hash mismatch'), `Expected 'hash mismatch', got: ${errors[0].message}`);
  });

  it('test_bilateral_trusted_bare_key — trustedServerKeys with bare base64 key (no prefix) matches prefixed server receipt key → onBilateral fires', async () => {
    // Fix #2: normalization logic must accept bare base64 in trustedServerKeys even when server
    // receipt contains a prefixed key (ed25519:<base64>)
    let bilateralReceived: BilateralReceipt | null = null;
    const mock = new MockTransport();
    const signing = new SigningTransport(mock, agentKp.secretKey, 'test-agent', 'owner', {
      target: 'mcp://test-server',
      transport: 'stdio',
      // Pass bare base64 key (no ed25519: prefix) — normalization should still match
      trustedServerKeys: [serverKp.publicKey],
      onBilateral: (r) => { bilateralReceived = r; },
    });

    await signing.send({ jsonrpc: '2.0', id: 20, method: 'tools/call', params: { name: 'echo', arguments: { message: 'hello' } } });

    const responseContent = { content: [{ type: 'text', text: 'world' }] };
    const { result } = buildBilateralResponse(responseContent);
    mock.simulateResponseWithMeta(20, responseContent, { _signet_bilateral: (result._meta as any)._signet_bilateral });

    assert(bilateralReceived !== null, 'onBilateral should have been called even when trustedServerKeys uses bare base64 (no ed25519: prefix)');
    assert.strictEqual((bilateralReceived as BilateralReceipt).v, 3);
  });

  it('test_bilateral_untrusted_server_key — valid v3 but server pubkey not in trustedServerKeys → onerror "untrusted"', async () => {
    const errors: Error[] = [];
    const untrustedKp = generateKeypair(); // A different keypair not in trustedServerKeys
    const mock = new MockTransport();
    const signing = new SigningTransport(mock, agentKp.secretKey, 'test-agent', 'owner', {
      target: 'mcp://test-server',
      transport: 'stdio',
      trustedServerKeys: [`ed25519:${serverKp.publicKey}`], // only trust serverKp, not untrustedKp
    });
    signing.onerror = (e) => { errors.push(e); };

    await signing.send({ jsonrpc: '2.0', id: 13, method: 'tools/call', params: { name: 'echo', arguments: { message: 'hello' } } });

    // Build bilateral with untrustedKp instead of serverKp
    const responseContent = { content: [{ type: 'text', text: 'world' }] };
    const action = makeAction('echo', { message: 'hello' });
    const agentReceipt = sign(agentKp.secretKey, action, 'test-agent', 'owner');
    const bilateral = signBilateral(
      untrustedKp.secretKey,
      JSON.stringify(agentReceipt),
      responseContent,
      'untrusted-server',
      new Date().toISOString(),
    );

    mock.simulateResponseWithMeta(13, responseContent, { _signet_bilateral: bilateral });

    assert(errors.length > 0, 'onerror should have been called');
    assert(errors[0].message.includes('untrusted'), `Expected 'untrusted' in error, got: ${errors[0].message}`);
  });
});
