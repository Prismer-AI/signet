#!/usr/bin/env bash
set -euo pipefail

echo "=== Installing Rust nightly toolchain ==="
# rust-toolchain.toml specifies nightly — rustup auto-installs on first cargo call,
# but we do it explicitly so the user sees progress.
rustup show active-toolchain || rustup install nightly

echo ""
echo "=== Building Signet CLI ==="
cargo build --release -p signet-cli

# Make signet available globally
sudo cp target/release/signet /usr/local/bin/signet
echo "signet installed at /usr/local/bin/signet"

echo ""
echo "=== Installing Python SDK ==="
pip install signet-auth 2>/dev/null || {
    pip install maturin
    cd bindings/signet-py && maturin develop --release && cd ../..
}

echo ""
echo "============================================"
echo "  Signet is ready! Run:"
echo ""
echo "    ./demo.sh"
echo ""
echo "  This will generate an identity, sign some"
echo "  tool calls, and open the audit dashboard."
echo "============================================"
