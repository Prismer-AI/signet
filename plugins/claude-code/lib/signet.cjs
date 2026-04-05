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
    // Warn if key file has lax permissions (Unix only)
    try {
      const stat = fs.statSync(keyPath);
      if ((stat.mode & 0o077) !== 0) {
        process.stderr.write(
          'signet: WARNING: ' + keyPath + ' has permissions ' +
          (stat.mode & 0o777).toString(8) + ' (expected 600)\n'
        );
      }
    } catch { /* non-Unix, skip */ }

    const data = JSON.parse(fs.readFileSync(keyPath, 'utf8'));
    if (!data.seed) {
      throw new Error(
        'Key at ' + keyPath + ' has no seed field. ' +
        'If encrypted, run: signet identity generate --name claude-agent --unencrypted'
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
  const tmpPath = keyPath + '.tmp';
  fs.writeFileSync(tmpPath, JSON.stringify(keyFile, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmpPath, keyPath);

  const pubPath = keyPath.replace(/\.key$/, '.pub');
  const pubFile = {
    v: 1,
    algorithm: 'ed25519',
    name: keyName,
    pubkey: kp.publicKey,
    created_at: new Date().toISOString(),
  };
  const tmpPub = pubPath + '.tmp';
  fs.writeFileSync(tmpPub, JSON.stringify(pubFile, null, 2) + '\n', { mode: 0o644 });
  fs.renameSync(tmpPub, pubPath);

  return kp;
}

function regenerateFromSeed(seed) {
  const publicKey = wasm.wasm_pubkey_from_seed(seed);
  return { publicKey, secretKey: seed };
}

module.exports = { generateKeypair, sign, contentHash, loadOrCreateKey };
