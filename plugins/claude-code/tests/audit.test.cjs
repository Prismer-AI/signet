'use strict';
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const { Worker } = require('node:worker_threads');
const audit = require('../lib/audit.cjs');

function makeTmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'signet-audit-'));
}

function fakeReceipt(tool) {
  return {
    v: 1,
    id: 'rec_test_' + Math.random().toString(36).slice(2),
    action: { tool, params: {}, params_hash: '', target: 'test', transport: 'stdio' },
    signer: { pubkey: 'ed25519:fake', name: 'test', owner: '' },
    ts: new Date().toISOString(),
    nonce: 'nonce_test',
    sig: 'ed25519:fakesig',
  };
}

describe('audit.cjs', () => {
  it('append creates audit directory and file', () => {
    const tmpDir = makeTmpDir();
    const receipt = fakeReceipt('Bash');
    audit.append(tmpDir, receipt);

    const auditDir = path.join(tmpDir, 'audit');
    assert.ok(fs.existsSync(auditDir), 'audit dir should exist');

    const files = fs.readdirSync(auditDir);
    assert.equal(files.length, 1);
    assert.ok(files[0].endsWith('.jsonl'));
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('append writes valid JSONL record with hash chain fields', () => {
    const tmpDir = makeTmpDir();
    audit.append(tmpDir, fakeReceipt('Bash'));

    const auditDir = path.join(tmpDir, 'audit');
    const file = fs.readdirSync(auditDir)[0];
    const line = fs.readFileSync(path.join(auditDir, file), 'utf8').trim();
    const record = JSON.parse(line);

    assert.ok(record.receipt, 'should have receipt');
    assert.ok(record.prev_hash, 'should have prev_hash');
    assert.ok(record.record_hash, 'should have record_hash');
    assert.equal(record.prev_hash, 'sha256:0000000000000000000000000000000000000000000000000000000000000000');
    assert.ok(record.record_hash.startsWith('sha256:'));
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('append chains hashes across records', () => {
    const tmpDir = makeTmpDir();
    audit.append(tmpDir, fakeReceipt('Bash'));
    audit.append(tmpDir, fakeReceipt('Read'));

    const auditDir = path.join(tmpDir, 'audit');
    const file = fs.readdirSync(auditDir)[0];
    const lines = fs.readFileSync(path.join(auditDir, file), 'utf8').trim().split('\n');
    assert.equal(lines.length, 2);

    const rec1 = JSON.parse(lines[0]);
    const rec2 = JSON.parse(lines[1]);

    assert.equal(rec2.prev_hash, rec1.record_hash);
    assert.notEqual(rec1.record_hash, rec2.record_hash);
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('record_hash is deterministic (same input = same hash)', () => {
    const tmpDir1 = makeTmpDir();
    const tmpDir2 = makeTmpDir();
    const receipt = fakeReceipt('Bash');
    receipt.id = 'rec_fixed';
    receipt.nonce = 'nonce_fixed';
    receipt.ts = '2026-04-05T00:00:00.000Z';

    audit.append(tmpDir1, receipt);
    audit.append(tmpDir2, receipt);

    const read = (dir) => {
      const f = fs.readdirSync(path.join(dir, 'audit'))[0];
      return JSON.parse(fs.readFileSync(path.join(dir, 'audit', f), 'utf8').trim());
    };

    assert.equal(read(tmpDir1).record_hash, read(tmpDir2).record_hash);
    fs.rmSync(tmpDir1, { recursive: true });
    fs.rmSync(tmpDir2, { recursive: true });
  });

  it('append serializes concurrent writers with a lock', async () => {
    const tmpDir = makeTmpDir();
    const gateBuffer = new SharedArrayBuffer(4);
    const gate = new Int32Array(gateBuffer);
    const workerScript = `
      'use strict';
      const { workerData, parentPort } = require('node:worker_threads');
      const audit = require(workerData.auditPath);
      const gate = new Int32Array(workerData.gateBuffer);
      Atomics.wait(gate, 0, 0);
      audit.append(workerData.tmpDir, workerData.receipt);
      parentPort.postMessage('done');
    `;
    const auditPath = path.resolve(__dirname, '../lib/audit.cjs');
    const workerCount = 8;

    const completions = Array.from({ length: workerCount }, (_, index) => {
      const receipt = fakeReceipt('Bash');
      receipt.id = `rec_lock_${index}`;
      receipt.nonce = `nonce_lock_${index}`;
      receipt.ts = '2026-04-05T00:00:00.000Z';

      return new Promise((resolve, reject) => {
        const worker = new Worker(workerScript, {
          eval: true,
          workerData: { auditPath, gateBuffer, tmpDir, receipt },
        });
        worker.once('message', resolve);
        worker.once('error', reject);
        worker.once('exit', (code) => {
          if (code !== 0) {
            reject(new Error(`worker exited with code ${code}`));
          }
        });
      });
    });

    Atomics.store(gate, 0, 1);
    Atomics.notify(gate, 0);
    await Promise.all(completions);

    const auditDir = path.join(tmpDir, 'audit');
    const files = fs.readdirSync(auditDir).filter((file) => file.endsWith('.jsonl'));
    assert.equal(files.length, 1);

    const filepath = path.join(auditDir, files[0]);
    assert.equal(fs.existsSync(filepath + '.lock'), false, 'lock file should be removed after append');

    const lines = fs.readFileSync(filepath, 'utf8').trim().split('\n');
    assert.equal(lines.length, workerCount);

    const records = lines.map((line) => JSON.parse(line));
    for (let index = 1; index < records.length; index++) {
      assert.equal(records[index].prev_hash, records[index - 1].record_hash);
    }

    fs.rmSync(tmpDir, { recursive: true });
  });
});
