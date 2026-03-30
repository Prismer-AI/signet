// @signet-auth/core — TypeScript wrapper for signet WASM
import { wasm_generate_keypair, wasm_sign, wasm_verify } from '../wasm/signet_wasm.js';

export interface SignetKeypair {
  secretKey: string;
  publicKey: string;
}

export interface SignetAction {
  tool: string;
  params: unknown;
  params_hash: string;
  target: string;
  transport: string;
}

export interface SignetSigner {
  pubkey: string;
  name: string;
  owner: string;
}

export interface SignetReceipt {
  v: number;
  id: string;
  action: SignetAction;
  signer: SignetSigner;
  ts: string;
  nonce: string;
  sig: string;
}

export function generateKeypair(): SignetKeypair {
  const json = wasm_generate_keypair();
  const result = JSON.parse(json);
  return {
    secretKey: result.secret_key,
    publicKey: result.public_key,
  };
}

export function sign(
  secretKey: string,
  action: SignetAction,
  signerName: string,
  signerOwner: string,
): SignetReceipt {
  const actionJson = JSON.stringify(action);
  const receiptJson = wasm_sign(secretKey, actionJson, signerName, signerOwner);
  return JSON.parse(receiptJson);
}

export function verify(receipt: SignetReceipt, publicKey: string): boolean {
  return wasm_verify(JSON.stringify(receipt), publicKey);
}
