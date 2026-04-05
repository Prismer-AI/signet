'use strict';
const path = require('node:path');
const fs = require('node:fs');
const wasm = require('../wasm/signet_wasm.js');

function generateKeypair() {
  const result = JSON.parse(wasm.wasm_generate_keypair());
  return { publicKey: result.public_key, secretKey: result.secret_key };
}

function sign(secretKey, action, signerName) {
  const json = wasm.wasm_sign(secretKey, JSON.stringify(action), signerName, '');
  return JSON.parse(json);
}

function contentHash(value) {
  return wasm.wasm_content_hash(JSON.stringify(value));
}

function loadOrCreateKey(keyPath) {
  if (fs.existsSync(keyPath)) {
    const data = JSON.parse(fs.readFileSync(keyPath, 'utf8'));
    if (data.kdf || data.ciphertext) {
      throw new Error(
        'Encrypted key detected at ' + keyPath + '. ' +
        'Run: signet identity generate --name claude-agent --unencrypted'
      );
    }
    return regenerateFromSeed(data.seed);
  }

  const kp = generateKeypair();
  const keyDir = path.dirname(keyPath);
  fs.mkdirSync(keyDir, { recursive: true });

  const keyName = path.basename(keyPath, '.key');
  const keyFile = {
    v: 1,
    algorithm: 'ed25519',
    name: keyName,
    seed: kp.secretKey,
  };
  fs.writeFileSync(keyPath, JSON.stringify(keyFile, null, 2) + '\n', { mode: 0o600 });

  const pubPath = keyPath.replace(/\.key$/, '.pub');
  const pubFile = {
    v: 1,
    algorithm: 'ed25519',
    name: keyName,
    pubkey: 'ed25519:' + kp.publicKey,
  };
  fs.writeFileSync(pubPath, JSON.stringify(pubFile, null, 2) + '\n', { mode: 0o644 });

  return kp;
}

function regenerateFromSeed(seed) {
  const dummyAction = JSON.stringify({
    tool: '_keygen',
    params: {},
    params_hash: '',
    target: '',
    transport: '',
  });
  const receipt = JSON.parse(wasm.wasm_sign(seed, dummyAction, '_', ''));
  const pubkey = receipt.signer.pubkey;
  const bare = pubkey.startsWith('ed25519:') ? pubkey.slice('ed25519:'.length) : pubkey;
  return { publicKey: bare, secretKey: seed };
}

module.exports = { generateKeypair, sign, contentHash, loadOrCreateKey };
