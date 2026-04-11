#!/usr/bin/env bash
set -euo pipefail

echo "=== Building Signet CLI ==="
cargo build --release -p signet-cli

# Make signet available globally
sudo cp target/release/signet /usr/local/bin/signet
echo "signet $(signet --version 2>/dev/null || echo 'installed')"

echo ""
echo "=== Installing Python SDK ==="
pip install signet-auth 2>/dev/null || pip install maturin && cd bindings/signet-py && maturin develop --release && cd ../..

echo ""
echo "=== Installing npm packages ==="
npm install 2>/dev/null || true

echo ""
echo "============================================"
echo "  Signet is ready! Run:"
echo ""
echo "    ./demo.sh"
echo ""
echo "  This will generate an identity, sign some"
echo "  tool calls, and open the audit dashboard."
echo "============================================"
