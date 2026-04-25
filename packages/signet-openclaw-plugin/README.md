# @signet-auth/openclaw-plugin

Cryptographic tool-call receipts for [OpenClaw](https://openclaw.ai), powered by [Signet](https://github.com/Prismer-AI/signet).

Every tool call dispatched by your OpenClaw gateway is:

1. **Signed** with an Ed25519 key (Signet receipt v1+)
2. **Appended** to a hash-chained audit log (`~/.signet/audit/*.jsonl`)
3. **Optionally policed** by a Signet policy — denied calls return `{ block: true }` from the `before_tool_call` hook
4. **Optionally encrypted** at rest — `action.params` is wrapped in an XChaCha20-Poly1305 envelope keyed off the signing key, so a third party can verify the signature chain without seeing the parameters

The plugin shells out to the local `signet` CLI via [`@signet-auth/node`](https://www.npmjs.com/package/@signet-auth/node), so it inherits everything Signet already does — keystore unlocking, encrypted audit envelopes, trust bundle support — without re-implementing any of it in the OpenClaw process.

## Prerequisites

- An OpenClaw gateway (`>=2026.3.24-beta.2`)
- The `signet` CLI on `$PATH` — install via [`cargo install signet-cli`](https://crates.io/crates/signet-cli) or the [release binaries](https://github.com/Prismer-AI/signet/releases)
- A Signet identity: `signet identity create openclaw-agent`

## Install

```bash
openclaw plugins install @signet-auth/openclaw-plugin
```

OpenClaw checks ClawHub first and falls back to npm.

## Configure

Add the plugin to your OpenClaw config (`~/.openclaw/config.json`):

```json
{
  "plugins": {
    "entries": {
      "signet": {
        "config": {
          "keyName": "openclaw-agent",
          "target": "openclaw://gateway/local",
          "policy": "/Users/me/.signet/policies/openclaw.yaml",
          "encryptParams": true,
          "blockOnSignFailure": true
        }
      }
    }
  }
}
```

If your identity is passphrase-protected, export it before starting the gateway:

```bash
export SIGNET_PASSPHRASE='...'
openclaw start
```

## What the plugin registers

| Hook                   | Behavior                                                                                       |
| ---------------------- | ---------------------------------------------------------------------------------------------- |
| `before_tool_call`     | Signs the call. On policy `deny` returns `{ block: true, blockReason }`.                        |
| `after_tool_call`      | Logs tool errors (warning level).                                                               |
| Security audit collector | Emits `signet:configured`, `signet:policy`, `signet:trust-bundle`, `signet:fail-mode` checks.  |

## Verifying receipts

```bash
# Hash-chain integrity
signet verify --chain

# Replay against a trust bundle (for an external auditor)
signet audit --verify --trust-bundle ./trust.yaml
```

## Configuration reference

| Field                | Default                       | Notes                                                                                                       |
| -------------------- | ----------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `keyName`            | `openclaw-agent`              | Identity name in `~/.signet/identities/`.                                                                   |
| `signerOwner`        | `openclaw`                    | Written into `receipt.signer.owner`.                                                                        |
| `target`             | `openclaw://gateway/local`    | Logical target string. Recommended: `openclaw://gateway/<gatewayId>`.                                       |
| `policy`             | (none)                        | Path to a Signet policy YAML. When set, denials block tool execution.                                       |
| `trustBundle`        | (none)                        | Reserved for future verification flows; surfaced today for parity with the verify CLI.                      |
| `auditDir`           | (CLI default — `~/.signet`)   | Override `SIGNET_HOME`.                                                                                     |
| `passphraseEnv`      | `SIGNET_PASSPHRASE`           | Env var that holds the keystore passphrase.                                                                 |
| `encryptParams`      | `false`                       | Encrypt `action.params` in the audit log.                                                                   |
| `signetBin`          | (uses `$PATH`)                | Path to the `signet` binary.                                                                                |
| `blockOnSignFailure` | `true`                        | Fail-closed (`true`) aborts the tool call on signing errors; fail-open (`false`) logs and lets the call run. |

## License

Apache-2.0 OR MIT
