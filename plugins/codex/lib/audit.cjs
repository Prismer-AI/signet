'use strict';
const fs = require('node:fs');
const path = require('node:path');
const signet = require('./signet.cjs');

// Must match Rust CLI: crates/signet-core/src/audit.rs GENESIS_HASH
const GENESIS_HASH = 'sha256:0000000000000000000000000000000000000000000000000000000000000000';
const LOCK_TIMEOUT_MS = 5000;
const LOCK_RETRY_MS = 10;
const LOCK_STALE_MS = 30000;

function sleepMs(ms) {
  if (typeof Atomics.wait === 'function') {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
    return;
  }

  const end = Date.now() + ms;
  while (Date.now() < end) {
    // Busy wait fallback for runtimes without Atomics.wait.
  }
}

function withAuditLock(lockPath, fn) {
  const startedAt = Date.now();

  while (true) {
    let lockFd;
    try {
      lockFd = fs.openSync(lockPath, 'wx');
      fs.writeFileSync(lockFd, String(process.pid));
      try {
        return fn();
      } finally {
        try {
          fs.closeSync(lockFd);
        } catch {}
        try {
          fs.unlinkSync(lockPath);
        } catch {}
      }
    } catch (err) {
      if (!err || err.code !== 'EEXIST') throw err;

      try {
        const stat = fs.statSync(lockPath);
        if (Date.now() - stat.mtimeMs > LOCK_STALE_MS) {
          fs.unlinkSync(lockPath);
          continue;
        }
      } catch (statErr) {
        if (statErr && statErr.code === 'ENOENT') continue;
        throw statErr;
      }

      if (Date.now() - startedAt > LOCK_TIMEOUT_MS) {
        throw new Error(`timed out waiting for audit lock: ${lockPath}`);
      }
      sleepMs(LOCK_RETRY_MS);
    }
  }
}

function append(signetDir, receipt, meta) {
  const auditDir = path.join(signetDir, 'audit');
  fs.mkdirSync(auditDir, { recursive: true });

  const ts = receipt.ts || receipt.ts_request || new Date().toISOString();
  const date = ts.slice(0, 10);
  const filepath = path.join(auditDir, date + '.jsonl');
  const lockPath = filepath + '.lock';

  return withAuditLock(lockPath, () => {
    const prevHash = lastRecordHash(filepath, auditDir);
    // meta is intentionally excluded from record_hash to stay consistent
    // with Rust compute_record_hash() in crates/signet-core/src/audit.rs.
    // The signed response_hash in the receipt provides integrity for the response.
    const recordHash = signet.contentHash({ prev_hash: prevHash, receipt });

    const record = {
      receipt,
      prev_hash: prevHash,
      record_hash: recordHash,
    };
    if (meta) record.meta = meta;

    fs.appendFileSync(filepath, JSON.stringify(record) + '\n');
  });
}

function lastRecordHash(filepath, auditDir) {
  if (fs.existsSync(filepath)) {
    const content = fs.readFileSync(filepath, 'utf8');
    const lines = content.trim().split('\n').filter(l => l.trim());
    for (let i = lines.length - 1; i >= 0; i--) {
      try {
        const rec = JSON.parse(lines[i]);
        if (rec.record_hash) return rec.record_hash;
      } catch { /* skip truncated line */ }
    }
  }

  if (fs.existsSync(auditDir)) {
    const files = fs.readdirSync(auditDir)
      .filter(f => f.endsWith('.jsonl'))
      .sort()
      .reverse();
    for (const file of files) {
      const fullPath = path.join(auditDir, file);
      if (fullPath === filepath) continue;
      const content = fs.readFileSync(fullPath, 'utf8');
      const lines = content.trim().split('\n').filter(l => l.trim());
      for (let i = lines.length - 1; i >= 0; i--) {
        try {
          const rec = JSON.parse(lines[i]);
          if (rec.record_hash) return rec.record_hash;
        } catch { /* skip truncated line */ }
      }
    }
  }

  return GENESIS_HASH;
}

module.exports = { append };
