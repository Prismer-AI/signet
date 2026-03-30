#!/bin/bash
# Signet Terminal Demo — 用于录制 GIF/截图
# 运行前：cargo build --release -p signet-cli
# 录制工具推荐：asciinema (asciinema rec demo.cast) 或 vhs (brew install vhs)

set -e

export SIGNET_HOME=$(mktemp -d)
SIGNET=./target/release/signet

echo "=== Signet Demo ==="
echo ""

# 1. Generate identity
echo "$ signet identity generate --name deploy-bot --owner willamhou --unencrypted"
$SIGNET identity generate --name deploy-bot --owner willamhou --unencrypted
echo ""

# 2. List identities
echo "$ signet identity list"
$SIGNET identity list
echo ""

# 3. Sign a tool call
echo "$ signet sign --key deploy-bot --tool github_create_issue \\"
echo "    --params '{\"title\":\"fix auth bug\",\"priority\":\"high\"}' \\"
echo "    --target mcp://github.local --output receipt.json"
$SIGNET sign --key deploy-bot \
  --tool github_create_issue \
  --params '{"title":"fix auth bug","priority":"high"}' \
  --target mcp://github.local \
  --output /tmp/signet-demo-receipt.json
echo ""

# 4. Show receipt
echo "$ cat receipt.json | python3 -m json.tool"
cat /tmp/signet-demo-receipt.json | python3 -m json.tool
echo ""

# 5. Verify
echo "$ signet verify receipt.json --pubkey deploy-bot"
$SIGNET verify /tmp/signet-demo-receipt.json --pubkey deploy-bot
echo ""

# 6. Sign a few more for audit demo
for tool in slack_send_message db_query api_call; do
  $SIGNET sign --key deploy-bot --tool $tool --params '{}' --target mcp://test > /dev/null
done

# 7. Audit
echo "$ signet audit --since 1h"
$SIGNET audit --since 1h
echo ""

# 8. Verify chain
echo "$ signet verify --chain"
$SIGNET verify --chain
echo ""

echo "=== Every tool call signed. Audit log hash-chained. ==="

# Cleanup
rm -rf "$SIGNET_HOME" /tmp/signet-demo-receipt.json
