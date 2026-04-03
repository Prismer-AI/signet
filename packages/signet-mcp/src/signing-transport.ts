import { sign, signCompound, type CompoundReceipt, type SignetAction, type SignetReceipt } from '@signet-auth/core';

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
  responseTimeout?: number; // ms, default 30000
  onReceipt?: (receipt: CompoundReceipt) => void;
  onDispatch?: (receipt: SignetReceipt) => void;
}

export class SigningTransport implements Transport {
  private inner: Transport;
  private secretKey: string;
  private signerName: string;
  private signerOwner: string;
  private opts: SigningTransportOptions;
  private pendingRequests = new Map<
    string | number,
    { action: SignetAction; tsRequest: string; timer: ReturnType<typeof setTimeout> }
  >();

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

    const timeout = this.opts.responseTimeout ?? 30000;

    // Forward callbacks using lazy closures.
    // MCP SDK's Protocol.connect() sets our callbacks AFTER construction,
    // so these closures must read this.onclose/etc lazily at call time.
    this.inner.onclose = () => this.onclose?.();
    this.inner.onerror = (e: Error) => this.onerror?.(e);
    this.inner.onmessage = (msg: JSONRPCMessage, extra?: unknown) => {
      // Check if this is a response to a pending tool call
      if (msg.id !== undefined && this.pendingRequests.has(msg.id)) {
        const pending = this.pendingRequests.get(msg.id)!;
        clearTimeout(pending.timer);
        this.pendingRequests.delete(msg.id);

        const tsResponse = new Date().toISOString();
        const responseContent = 'result' in msg ? msg.result : (msg.error ?? null);

        try {
          const receipt = signCompound(
            this.secretKey,
            pending.action,
            responseContent,
            this.signerName,
            this.signerOwner,
            pending.tsRequest,
            tsResponse,
          );
          this.opts.onReceipt?.(receipt);
        } catch (err) {
          this.onerror?.(err instanceof Error ? err : new Error(String(err)));
        }
      }

      // Always forward message to outer onmessage
      this.onmessage?.(msg, extra);
    };

    // Store timeout for use in send()
    this._timeout = timeout;
  }

  private _timeout: number;

  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage, extra?: unknown) => void;

  get sessionId() { return this.inner.sessionId; }

  setProtocolVersion = (v: string) => {
    this.inner.setProtocolVersion?.(v);
  };

  start(): Promise<void> { return this.inner.start(); }

  async close(): Promise<void> {
    for (const entry of this.pendingRequests.values()) {
      if (entry.timer) clearTimeout(entry.timer);
    }
    this.pendingRequests.clear();
    return this.inner.close();
  }

  async send(message: JSONRPCMessage, options?: unknown): Promise<void> {
    if (this.isToolCall(message) && message.id !== undefined) {
      const params = (message.params ?? {}) as Record<string, unknown>;
      const action: SignetAction = {
        tool: (params.name as string) ?? 'unknown',
        params: (params.arguments as Record<string, unknown>) ?? {},
        params_hash: '',
        target: this.opts.target ?? 'unknown',
        transport: this.opts.transport ?? 'stdio',
      };
      const tsRequest = new Date().toISOString();

      // Sign v1 dispatch receipt with full params for server verification
      try {
        const dispatchReceipt = sign(this.secretKey, action, this.signerName, this.signerOwner);
        // Deep-clone and inject into _meta._signet
        const clonedParams = JSON.parse(JSON.stringify(message.params ?? {}));
        if (!clonedParams._meta) clonedParams._meta = {};
        clonedParams._meta._signet = dispatchReceipt;
        message.params = clonedParams;
        this.opts.onDispatch?.(dispatchReceipt);
      } catch (err) {
        this.onerror?.(err instanceof Error ? err : new Error(String(err)));
        return;
      }

      const id = message.id;
      const timer = setTimeout(() => {
        this.pendingRequests.delete(id);
      }, this._timeout);

      this.pendingRequests.set(id, { action, tsRequest, timer });
    }

    return this.inner.send(message, options);
  }

  private isToolCall(message: JSONRPCMessage): boolean {
    return message.method === 'tools/call';
  }
}
