const GITHUB_URL = 'https://github.com/Prismer-AI/signet';

export default function Footer() {
  return (
    <footer className="footer">
      <div className="cta-block">
        <h2>Put Signet in front of an MCP server</h2>
        <p>
          <code>signet proxy</code> sits between your agent and an MCP server and
          signs every tool call, with no changes to either side. You can export a
          signed bundle and re-verify it offline on another machine. There are
          integrations for Claude Code, Codex, and the Vercel AI SDK, plus a Python
          SDK for LangChain and similar frameworks.
        </p>
        <div className="hero-cta">
          <a className="btn btn-primary" href={GITHUB_URL} target="_blank" rel="noreferrer">
            Read the docs on GitHub
          </a>
          <a className="btn btn-ghost" href="#demo">
            Back to the demo
          </a>
        </div>
      </div>
      <div className="footer-meta">
        <span>◆ Signet</span>
        <span>Apache-2.0 / MIT · Ed25519 · RFC 8785 · SHA-256</span>
      </div>
    </footer>
  );
}
