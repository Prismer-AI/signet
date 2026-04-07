#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGIN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$PLUGIN_DIR/../.." && pwd)"
WASM_SRC="$REPO_ROOT/packages/signet-core/wasm"

if [ ! -f "$WASM_SRC/signet_wasm_bg.wasm" ]; then
  echo "Error: WASM not built. Run first:"
  echo "  wasm-pack build bindings/signet-ts --target nodejs --out-dir ../../packages/signet-core/wasm"
  exit 1
fi

cp "$WASM_SRC/signet_wasm_bg.wasm" "$PLUGIN_DIR/wasm/"
cp "$WASM_SRC/signet_wasm.js" "$PLUGIN_DIR/wasm/"

echo "WASM copied. Verifying..."
node -e "
  const w = require('$PLUGIN_DIR/wasm/signet_wasm.js');
  const kp = JSON.parse(w.wasm_generate_keypair());
  if (!kp.public_key) throw new Error('WASM verification failed');
  console.log('WASM OK — pubkey:', kp.public_key.slice(0, 20) + '...');
"

echo "Plugin build complete."
