# CI/CD Integration Guide

Use Signet in CI pipelines to sign and audit automated agent actions.

## Key Management for CI

In CI, use **unencrypted keys** or the `SIGNET_PASSPHRASE` environment variable.

### Option 1: Unencrypted key (simpler)

```bash
# Generate an unencrypted identity for CI
signet identity generate --name ci-bot --owner "ci" --unencrypted
```

### Option 2: Encrypted key with env var

```bash
# Generate normally (will prompt for passphrase)
signet identity generate --name ci-bot --owner "ci"

# In CI, set the passphrase as a secret
export SIGNET_PASSPHRASE="your-passphrase"
```

### Option 3: Ephemeral keys per pipeline run

```bash
# Generate a fresh identity for each run
signet identity generate --name "ci-${GITHUB_RUN_ID}" --owner "ci" --unencrypted

# Sign actions during the run
signet sign --key "ci-${GITHUB_RUN_ID}" --tool "deploy" --params '{"env":"staging"}'

# Export the public key as an artifact
signet identity export --name "ci-${GITHUB_RUN_ID}" > pubkey.json
```

## GitHub Actions Example

```yaml
name: Deploy with Signet Audit

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      SIGNET_PASSPHRASE: ${{ secrets.SIGNET_PASSPHRASE }}

    steps:
      - uses: actions/checkout@v4

      - name: Install Signet CLI
        run: cargo install signet-cli  # or: cargo install --path signet-cli

      - name: Generate CI identity
        run: signet identity generate --name ci-deploy --owner "github-actions" --unencrypted

      - name: Sign deploy action
        run: |
          signet sign --key ci-deploy \
            --tool "deploy" \
            --params "{\"commit\":\"${{ github.sha }}\",\"env\":\"production\"}" \
            --target "deploy://production" \
            --output deploy-receipt.json

      - name: Run deployment
        run: ./deploy.sh

      - name: Sign post-deploy verification
        run: |
          signet sign --key ci-deploy \
            --tool "health_check" \
            --params "{\"status\":\"healthy\",\"url\":\"https://app.example.com\"}" \
            --output health-receipt.json

      - name: Verify audit trail
        run: signet verify --chain

      - name: Export audit log
        run: signet audit --export audit-log.json

      - name: Upload audit artifacts
        uses: actions/upload-artifact@v4
        with:
          name: signet-audit-${{ github.run_id }}
          path: |
            deploy-receipt.json
            health-receipt.json
            audit-log.json
```

## Privacy: Hash-Only Mode

For CI environments where you don't want to log raw parameters (e.g., secrets in deploy configs):

```bash
signet sign --key ci-bot \
  --tool "deploy" \
  --params '{"api_key":"sk-...","env":"prod"}' \
  --hash-only
```

This stores only `params_hash: "sha256:..."` in the receipt, not the raw params. You can still prove the params haven't changed by recomputing the hash.

## Verifying CI Receipts Locally

```bash
# Download the audit artifacts from CI
# Then verify any receipt:
signet verify deploy-receipt.json --pubkey ci-deploy

# Or verify the full chain:
signet verify --chain
```
