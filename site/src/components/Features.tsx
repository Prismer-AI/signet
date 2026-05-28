const ROWS: Array<{ ordinary: string; signet: string }> = [
  { ordinary: 'Provider says it happened', signet: 'Anyone can verify it, offline' },
  { ordinary: 'Mutable after the fact', signet: 'Signature breaks on tamper' },
  { ordinary: 'No ordering proof', signet: 'Hash chain breaks on delete/reorder' },
  { ordinary: 'Trust the log host', signet: 'Verify with the public key' },
  { ordinary: 'One-sided claim', signet: 'Bilateral co-signing available' },
];

const STEPS: Array<{ n: string; title: string; body: string }> = [
  {
    n: '01',
    title: 'Sign',
    body: 'Each agent holds an Ed25519 identity. Every tool call is canonicalized (RFC 8785) and signed before it runs.',
  },
  {
    n: '02',
    title: 'Chain',
    body: 'Receipts append to a SHA-256 hash-chained JSONL log. Delete or reorder an entry and the chain breaks.',
  },
  {
    n: '03',
    title: 'Verify',
    body: 'Anyone can re-check a receipt offline with just the public key. Change any field and the check fails.',
  },
];

export default function Features() {
  return (
    <section id="how" className="features">
      <div className="why">
        <h2>Why not just logs?</h2>
        <p className="section-lede">
          A log tells you what a system <em>says</em> happened, and you have to trust
          whoever wrote it. Nothing stops it from being edited later. A Signet receipt
          can be checked on its own, by anyone, after the fact.
        </p>
        <div className="compare">
          <div className="compare-col compare-ordinary">
            <span className="compare-head">Ordinary logs</span>
            {ROWS.map((r) => (
              <span key={r.ordinary} className="compare-cell">
                {r.ordinary}
              </span>
            ))}
          </div>
          <div className="compare-col compare-signet">
            <span className="compare-head">Signet receipts</span>
            {ROWS.map((r) => (
              <span key={r.signet} className="compare-cell">
                {r.signet}
              </span>
            ))}
          </div>
        </div>
      </div>

      <div className="steps">
        {STEPS.map((s) => (
          <div key={s.n} className="step-card">
            <span className="step-n">{s.n}</span>
            <h3>{s.title}</h3>
            <p>{s.body}</p>
          </div>
        ))}
      </div>
    </section>
  );
}
