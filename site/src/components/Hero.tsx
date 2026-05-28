const GITHUB_URL = 'https://github.com/Prismer-AI/signet';

export default function Hero() {
  return (
    <header className="hero">
      <nav className="nav">
        <span className="brand">◆ Signet</span>
        <div className="nav-links">
          <a href="#demo">Demo</a>
          <a href="#how">How it works</a>
          <a href={GITHUB_URL} target="_blank" rel="noreferrer">
            GitHub
          </a>
        </div>
      </nav>

      <div className="hero-body">
        <span className="eyebrow">Cryptographic receipts for AI agent tool calls</span>
        <h1>
          Don&apos;t just log agent actions.
          <br />
          <span className="accent">Prove them.</span>
        </h1>
        <p className="lede">
          Each tool call your agent makes is signed with an Ed25519 key and written
          to a hash-chained log. Later, anyone can check it using only the public
          key, with no access to the system that ran the agent.
        </p>
        <div className="hero-cta">
          <a className="btn btn-primary" href="#demo">
            See the demo
          </a>
          <a
            className="btn btn-ghost"
            href={GITHUB_URL}
            target="_blank"
            rel="noreferrer"
          >
            View on GitHub
          </a>
        </div>
        <code className="install">pip install signet-auth</code>
      </div>
    </header>
  );
}
