'use strict';
const fs = require('node:fs');
const path = require('node:path');
const signet = require('./signet.cjs');

const GENESIS_HASH = 'sha256:genesis';

function append(signetDir, receipt) {
  const auditDir = path.join(signetDir, 'audit');
  fs.mkdirSync(auditDir, { recursive: true });

  const ts = receipt.ts || receipt.ts_request || new Date().toISOString();
  const date = ts.slice(0, 10);
  const filepath = path.join(auditDir, date + '.jsonl');

  const prevHash = lastRecordHash(filepath, auditDir);
  const recordHash = signet.contentHash({ prev_hash: prevHash, receipt });

  const record = {
    receipt,
    prev_hash: prevHash,
    record_hash: recordHash,
  };

  fs.appendFileSync(filepath, JSON.stringify(record) + '\n');
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
