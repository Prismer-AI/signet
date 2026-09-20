import assert from 'node:assert';
import {
    wasm_generate_keypair,
    wasm_sign,
    wasm_sign_with_principal,
    wasm_verify,
    wasm_parse_principal,
    wasm_validate_principal
} from '../../bindings/signet-ts/pkg/signet_wasm.js';

// Test 1: Generate keypair
console.log('Test 1: Generate keypair...');
const keypair = JSON.parse(wasm_generate_keypair());
const { secret_key, public_key } = keypair;
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
const other_keypair = JSON.parse(wasm_generate_keypair());
assert.strictEqual(wasm_verify(receipt_json, other_keypair.public_key), false, 'wrong key should fail');
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

// Test 9: Principal grammar — parse and validate
console.log('Test 9: Principal grammar...');
const parsed = JSON.parse(wasm_parse_principal('agent://prismer/deploy-bot'));
assert.strictEqual(parsed.scheme, 'agent');
assert.strictEqual(parsed.trust_domain, 'prismer');
assert.deepStrictEqual(parsed.path, ['deploy-bot']);
try {
    wasm_validate_principal('agent://deploy-bot'); // missing trust domain
    assert.fail('should have thrown');
} catch (e) {
    assert(e.message.includes('principal'), `expected principal error, got: ${e.message}`);
}
console.log('  PASS');

// Test 10: Sign with principals — roundtrip, tamper, absent-by-default
console.log('Test 10: Sign with principals...');
const principal_receipt_json = wasm_sign_with_principal(
    secret_key, action, 'deploy-bot', 'alice',
    'agent://prismer/deploy-bot',
    'user://prismer/alice'
);
const principal_receipt = JSON.parse(principal_receipt_json);
assert.strictEqual(principal_receipt.signer.principal, 'agent://prismer/deploy-bot');
assert.strictEqual(principal_receipt.signer.acting_for, 'user://prismer/alice');
assert.strictEqual(wasm_verify(principal_receipt_json, public_key), true, 'principal receipt should verify');

const tampered_principal = {
    ...principal_receipt,
    signer: { ...principal_receipt.signer, principal: 'agent://evil/imposter' }
};
assert.strictEqual(
    wasm_verify(JSON.stringify(tampered_principal), public_key), false,
    'tampered principal should fail'
);

const plain_receipt = JSON.parse(wasm_sign(secret_key, action, 'agent', 'owner'));
assert.strictEqual(plain_receipt.signer.principal, undefined, 'no principal when none given');
assert.strictEqual(plain_receipt.signer.acting_for, undefined, 'no acting_for when none given');
console.log('  PASS');

console.log('\n=== All 10 tests passed. M0 validation complete. ===');
