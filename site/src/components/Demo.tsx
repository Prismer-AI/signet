import { useCallback, useEffect, useRef, useState } from 'react';
import {
  type Action,
  type Keypair,
  generateKeypair,
  initSignet,
  sign,
  verify,
} from '../lib/signet';

type Status = 'loading' | 'valid' | 'invalid' | 'error';

const DEMO_ACTION: Action = {
  tool: 'github_create_issue',
  params: {
    repo: 'acme/payments',
    title: 'Refund overcharged customer',
    amount_usd: 480,
  },
  params_hash: '',
  target: 'mcp://github',
  transport: 'stdio',
};

function prettyReceipt(receiptJson: string): string {
  try {
    return JSON.stringify(JSON.parse(receiptJson), null, 2);
  } catch {
    return receiptJson;
  }
}

export default function Demo() {
  const [keypair, setKeypair] = useState<Keypair | null>(null);
  const [receipt, setReceipt] = useState('');
  const [status, setStatus] = useState<Status>('loading');
  const [error, setError] = useState<string | null>(null);
  const pubkeyRef = useRef('');
  const didInit = useRef(false);

  const runVerify = useCallback((text: string) => {
    if (!pubkeyRef.current) return;
    try {
      const ok = verify(text, pubkeyRef.current);
      setStatus(ok ? 'valid' : 'invalid');
      setError(null);
    } catch (e) {
      setStatus('error');
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  const freshSign = useCallback((kp: Keypair, action: Action) => {
    try {
      const signed = prettyReceipt(sign(kp.secret_key, action, 'demo-agent', 'acme'));
      setReceipt(signed);
      runVerify(signed);
    } catch (e) {
      // wasm_sign rejects a structurally invalid action (e.g. the user edited
      // the receipt into something un-signable before hitting Re-sign).
      setStatus('error');
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [runVerify]);

  // Initialize exactly once. The didInit ref guards against React StrictMode's
  // double-mount and against any future re-render that changes freshSign's
  // identity — either way the keypair never silently rotates mid-session.
  useEffect(() => {
    if (didInit.current) return;
    didInit.current = true;
    initSignet().then(() => {
      const kp = generateKeypair();
      pubkeyRef.current = kp.public_key;
      setKeypair(kp);
      freshSign(kp, DEMO_ACTION);
    });
  }, [freshSign]);

  const onEdit = (text: string) => {
    setReceipt(text);
    runVerify(text);
  };

  const tamper = () => {
    try {
      const obj = JSON.parse(receipt);
      // Silently bump the refund amount — exactly the kind of after-the-fact
      // edit an attacker or a buggy log pipeline would make.
      if (obj?.action?.params) {
        obj.action.params.amount_usd = 48000;
      }
      onEdit(JSON.stringify(obj, null, 2));
    } catch {
      /* if the user already broke the JSON, leave it as-is */
    }
  };

  const reSign = () => {
    if (!keypair) return;
    let action: Action = DEMO_ACTION;
    try {
      const obj = JSON.parse(receipt);
      if (obj?.action) action = { ...obj.action, params_hash: '' };
    } catch {
      /* fall back to the canonical demo action */
    }
    freshSign(keypair, action);
  };

  const reset = () => {
    if (keypair) freshSign(keypair, DEMO_ACTION);
  };

  return (
    <section id="demo" className="demo">
      <div className="demo-head">
        <h2>Verify a receipt, then try to change it</h2>
        <p>
          This runs the real <code>signet-core</code> crypto compiled to
          WebAssembly. Signing and verification happen in your browser; nothing is
          sent to a server.
        </p>
      </div>

      <div className="demo-grid">
        <div className="demo-panel">
          <div className="panel-label">
            <span className="step">1</span> The signed receipt
            {keypair && (
              <span className="pubkey" title={keypair.public_key}>
                pubkey {keypair.public_key.slice(0, 10)}…
              </span>
            )}
          </div>
          <textarea
            className="receipt"
            spellCheck={false}
            value={receipt}
            disabled={status === 'loading'}
            onChange={(e) => onEdit(e.target.value)}
            aria-label="Signed receipt JSON — edit any character to break the signature"
          />
        </div>

        <div className="demo-panel demo-controls">
          <div className="panel-label">
            <span className="step">2</span> Verification (offline)
          </div>

          <div className={`verdict verdict-${status}`}>
            {status === 'loading' && <span>Loading WASM…</span>}
            {status === 'valid' && (
              <>
                <span className="verdict-mark">✓</span>
                <span>Signature valid</span>
              </>
            )}
            {status === 'invalid' && (
              <>
                <span className="verdict-mark">✗</span>
                <span>Signature invalid</span>
              </>
            )}
            {status === 'error' && (
              <>
                <span className="verdict-mark">!</span>
                <span>Malformed receipt JSON</span>
              </>
            )}
          </div>

          {error && <p className="verdict-error">{error}</p>}

          <p className="hint">
            Change anything in the receipt and verification fails. The check needs
            only the public key, never the secret. Edit the JSON directly, or use
            the button below to bump the <code>amount_usd</code> field.
          </p>

          <div className="btn-row">
            <button className="btn btn-danger" onClick={tamper} disabled={status === 'loading'}>
              Tamper a field
            </button>
            <button className="btn" onClick={reSign} disabled={status === 'loading'}>
              Re-sign
            </button>
            <button className="btn btn-ghost" onClick={reset} disabled={status === 'loading'}>
              Reset
            </button>
          </div>
        </div>
      </div>
    </section>
  );
}
