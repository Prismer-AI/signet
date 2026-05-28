/* tslint:disable */
/* eslint-disable */

export function wasm_compute_policy_hash(policy_json: string): string;

export function wasm_content_hash(json: string): string;

export function wasm_evaluate_policy(action_json: string, agent_name: string, policy_json: string): string;

export function wasm_generate_keypair(): string;

export function wasm_parse_policy_yaml(yaml: string): string;

export function wasm_pubkey_from_seed(seed_b64: string): string;

export function wasm_sign(secret_key_b64: string, action_json: string, signer_name: string, signer_owner: string): string;

export function wasm_sign_authorized(key_b64: string, action_json: string, signer_name: string, chain_json: string): string;

export function wasm_sign_bilateral(server_key_b64: string, agent_receipt_json: string, response_content_json: string, server_name: string, ts_response: string): string;

/**
 * Same as `wasm_sign_bilateral` but additionally records a final outcome
 * (executed / failed / rejected / requires_approval / verified) inside the signature scope.
 *
 * `outcome_json` is a JSON object with shape:
 *   { "status": "executed" | "failed" | "rejected" | "requires_approval" | "verified",
 *     "reason": ?string, "error": ?string }
 * or the literal string "null" / empty string to omit the outcome.
 */
export function wasm_sign_bilateral_with_outcome(server_key_b64: string, agent_receipt_json: string, response_content_json: string, server_name: string, ts_response: string, outcome_json: string): string;

export function wasm_sign_compound(secret_key_b64: string, action_json: string, response_content_json: string, signer_name: string, signer_owner: string, ts_request: string, ts_response: string): string;

export function wasm_sign_delegation(delegator_key_b64: string, delegator_name: string, delegate_pubkey_b64: string, delegate_name: string, scope_json: string, parent_scope_json?: string | null): string;

export function wasm_sign_with_expiration(secret_key_b64: string, action_json: string, signer_name: string, signer_owner: string, expires_at: string): string;

export function wasm_sign_with_policy(secret_key_b64: string, action_json: string, signer_name: string, signer_owner: string, policy_json: string): string;

export function wasm_verify(receipt_json: string, public_key_b64: string): boolean;

export function wasm_verify_allow_expired(receipt_json: string, public_key_b64: string): boolean;

export function wasm_verify_any(receipt_json: string, public_key_b64: string): boolean;

export function wasm_verify_authorized(receipt_json: string, trusted_roots_json: string, clock_skew_secs: bigint): string;

export function wasm_verify_bilateral(receipt_json: string, server_pubkey_b64: string): boolean;

export function wasm_verify_bilateral_with_options(receipt_json: string, server_pubkey_b64: string, expected_session: string, expected_call_id: string, max_time_window_secs: bigint): boolean;

export function wasm_verify_delegation(token_json: string): boolean;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly wasm_compute_policy_hash: (a: number, b: number) => [number, number, number, number];
    readonly wasm_content_hash: (a: number, b: number) => [number, number, number, number];
    readonly wasm_evaluate_policy: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly wasm_generate_keypair: () => [number, number, number, number];
    readonly wasm_parse_policy_yaml: (a: number, b: number) => [number, number, number, number];
    readonly wasm_pubkey_from_seed: (a: number, b: number) => [number, number, number, number];
    readonly wasm_sign: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly wasm_sign_authorized: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly wasm_sign_bilateral: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number, number];
    readonly wasm_sign_bilateral_with_outcome: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number) => [number, number, number, number];
    readonly wasm_sign_compound: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number) => [number, number, number, number];
    readonly wasm_sign_delegation: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number) => [number, number, number, number];
    readonly wasm_sign_with_expiration: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number, number];
    readonly wasm_sign_with_policy: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number, number];
    readonly wasm_verify: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly wasm_verify_allow_expired: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly wasm_verify_any: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly wasm_verify_authorized: (a: number, b: number, c: number, d: number, e: bigint) => [number, number, number, number];
    readonly wasm_verify_bilateral: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly wasm_verify_bilateral_with_options: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: bigint) => [number, number, number];
    readonly wasm_verify_delegation: (a: number, b: number) => [number, number, number];
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
