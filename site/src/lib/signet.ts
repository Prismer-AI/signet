// Thin typed wrapper around the browser WASM build of signet-core.
// All crypto runs in WebAssembly compiled from the same Rust core as the CLI —
// there is no JavaScript reimplementation here.
import init, {
  wasm_generate_keypair,
  wasm_sign,
  wasm_verify,
} from '../wasm/signet_wasm';

let ready: Promise<void> | null = null;

/** Initialize the WASM module exactly once. Safe to call repeatedly. */
export function initSignet(): Promise<void> {
  if (!ready) {
    ready = init().then(() => undefined);
  }
  return ready;
}

export interface Keypair {
  secret_key: string;
  public_key: string;
}

export interface Action {
  tool: string;
  params: unknown;
  params_hash: string;
  target: string;
  transport: string;
}

/** Generate an Ed25519 keypair (base64 seed + public key). */
export function generateKeypair(): Keypair {
  return JSON.parse(wasm_generate_keypair()) as Keypair;
}

/** Sign an action, returning the receipt as a JSON string. */
export function sign(
  secretKey: string,
  action: Action,
  signerName: string,
  signerOwner: string,
): string {
  return wasm_sign(secretKey, JSON.stringify(action), signerName, signerOwner);
}

/**
 * Verify a v1 receipt against a public key.
 * Returns false on a signature mismatch (the tamper case), and throws only on
 * malformed input (e.g. invalid JSON), which the caller surfaces separately.
 */
export function verify(receiptJson: string, publicKey: string): boolean {
  return wasm_verify(receiptJson, publicKey);
}
