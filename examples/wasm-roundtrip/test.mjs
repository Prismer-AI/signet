import assert from 'node:assert';
import { wasm_generate_keypair, wasm_sign, wasm_verify } from '../../bindings/signet-ts/pkg/signet_wasm.js';

// Test 1: Generate keypair
console.log('Test 1: Generate keypair...');
const keypair = wasm_generate_keypair();
// serde_wasm_bindgen serializes JSON objects as JS Map
const secret_key = keypair instanceof Map ? keypair.get('secret_key') : keypair.secret_key;
const public_key = keypair instanceof Map ? keypair.get('public_key') : keypair.public_key;
assert(secret_key && public_key, 'keypair should have both keys');
console.log('  PASS');

// Test 2: Sign an action
console.log('Test 2: Sign an action...');
const action = JSON.stringify({
    tool: 'github_create_issue',
    params: { title: 'fix bug', body: 'details' },
    params_hash: '',
    target: 'mcp://github.local',
    transport: 'stdio'
});
const receipt_json = wasm_sign(secret_key, action, 'test-agent', 'willamhou');
const receipt = JSON.parse(receipt_json);
assert(receipt.sig.startsWith('ed25519:'), 'sig should have ed25519: prefix');
assert(receipt.id.startsWith('rec_'), 'id should have rec_ prefix');
assert.strictEqual(receipt.signer.name, 'test-agent');
assert.strictEqual(receipt.action.tool, 'github_create_issue');
assert(receipt.action.params_hash.startsWith('sha256:'), 'params_hash should be computed');
console.log('  PASS');

// Test 3: Verify valid receipt
console.log('Test 3: Verify valid receipt...');
assert.strictEqual(wasm_verify(receipt_json, public_key), true, 'valid receipt should verify');
console.log('  PASS');

// Test 4: Tampered action should fail
console.log('Test 4: Tampered action should fail...');
const tampered = { ...receipt, action: { ...receipt.action, tool: 'evil_tool' } };
assert.strictEqual(wasm_verify(JSON.stringify(tampered), public_key), false, 'tampered action should fail');
console.log('  PASS');

// Test 5: Wrong key should fail
console.log('Test 5: Wrong key should fail...');
const other_keypair = wasm_generate_keypair();
const other_key = other_keypair instanceof Map ? other_keypair.get('public_key') : other_keypair.public_key;
assert.strictEqual(wasm_verify(receipt_json, other_key), false, 'wrong key should fail');
console.log('  PASS');

// Test 6: Tampered signer should fail
console.log('Test 6: Tampered signer should fail...');
const tampered_signer = { ...receipt, signer: { ...receipt.signer, name: 'impostor' } };
assert.strictEqual(wasm_verify(JSON.stringify(tampered_signer), public_key), false, 'tampered signer should fail');
console.log('  PASS');

// Test 7: Invalid secret key should throw
console.log('Test 7: Invalid secret key should throw...');
try {
    wasm_sign('not-valid-base64!!!', action, 'agent', 'owner');
    assert.fail('should have thrown');
} catch (e) {
    assert(e.message.includes('invalid'), `expected invalid key error, got: ${e.message}`);
}
console.log('  PASS');

// Test 8: Malformed action JSON should throw
console.log('Test 8: Malformed action JSON should throw...');
try {
    wasm_sign(secret_key, '{not json', 'agent', 'owner');
    assert.fail('should have thrown');
} catch (e) {
    assert(e.message.includes('invalid') || e.message.includes('JSON'), `expected JSON error, got: ${e.message}`);
}
console.log('  PASS');

console.log('\n=== All 8 tests passed. M0 validation complete. ===');
