import { sign, type SignetAction, type SignetReceipt } from '@signet/core';

// Minimal Transport interface — compatible with @modelcontextprotocol/sdk Transport
// but defined here to avoid requiring the SDK as a dependency
export interface JSONRPCMessage {
  jsonrpc: '2.0';
  id?: string | number;
  method?: string;
  params?: Record<string, unknown>;
  result?: unknown;
  error?: unknown;
}

export interface Transport {
  start(): Promise<void>;
  send(message: JSONRPCMessage, options?: unknown): Promise<void>;
  close(): Promise<void>;
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage, extra?: unknown) => void;
  sessionId?: string;
  setProtocolVersion?: (version: string) => void;
}

export interface SigningTransportOptions {
  target?: string;
  transport?: string;
  onSign?: (receipt: SignetReceipt) => void;
}

export class SigningTransport implements Transport {
  private inner: Transport;
  private secretKey: string;
  private signerName: string;
  private signerOwner: string;
  private opts: SigningTransportOptions;

  constructor(
    inner: Transport,
    secretKey: string,
    signerName: string,
    signerOwner?: string,
    options?: SigningTransportOptions,
  ) {
    this.inner = inner;
    this.secretKey = secretKey;
    this.signerName = signerName;
    this.signerOwner = signerOwner ?? '';
    this.opts = options ?? {};

    // Forward callbacks using lazy closures.
    // MCP SDK's Protocol.connect() sets our callbacks AFTER construction,
    // so these closures must read this.onclose/etc lazily at call time.
    this.inner.onclose = () => this.onclose?.();
    this.inner.onerror = (e: Error) => this.onerror?.(e);
    this.inner.onmessage = (msg: JSONRPCMessage, extra?: unknown) =>
      this.onmessage?.(msg, extra);
  }

  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage, extra?: unknown) => void;

  get sessionId() { return this.inner.sessionId; }

  setProtocolVersion = (v: string) => {
    this.inner.setProtocolVersion?.(v);
  };

  start(): Promise<void> { return this.inner.start(); }
  close(): Promise<void> { return this.inner.close(); }

  async send(message: JSONRPCMessage, options?: unknown): Promise<void> {
    if (this.isToolCall(message)) {
      const receipt = this.signToolCall(message);
      this.injectSignet(message, receipt);
      this.opts.onSign?.(receipt);
    }
    return this.inner.send(message, options);
  }

  private isToolCall(message: JSONRPCMessage): boolean {
    return message.method === 'tools/call';
  }

  private signToolCall(message: JSONRPCMessage): SignetReceipt {
    const params = (message.params ?? {}) as Record<string, unknown>;
    const action: SignetAction = {
      tool: (params.name as string) ?? 'unknown',
      params: (params.arguments as Record<string, unknown>) ?? {},
      params_hash: '',
      target: this.opts.target ?? 'unknown',
      transport: this.opts.transport ?? 'stdio',
    };
    return sign(this.secretKey, action, this.signerName, this.signerOwner);
  }

  private injectSignet(message: JSONRPCMessage, receipt: SignetReceipt): void {
    // Deep-clone params to avoid mutating the original object
    const params = JSON.parse(JSON.stringify(message.params ?? {}));
    if (!params._meta) params._meta = {};
    params._meta._signet = {
      ...receipt,
      action: { ...receipt.action, params: null },
    };
    message.params = params;
  }
}
