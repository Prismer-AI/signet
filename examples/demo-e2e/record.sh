#!/usr/bin/env bash
# End-to-end Signet demo recording script
# Usage: asciinema rec --command ./examples/demo-e2e/record.sh demo-e2e.cast
set -e

SIGNET="./target/release/signet"
export SIGNET_HOME=$(mktemp -d)

# Typing simulation
type_cmd() {
  echo ""
  echo -ne "\033[1;32m❯\033[0m "
  for ((i=0; i<${#1}; i++)); do
    echo -n "${1:$i:1}"
    sleep 0.03
  done
  echo ""
  sleep 0.3
  eval "$1"
  sleep 1
}

clear
echo ""
echo "  ┌─────────────────────────────────────────┐"
echo "  │  Signet — End-to-End Demo               │"
echo "  │  Sign → Audit → Verify → Dashboard      │"
echo "  └─────────────────────────────────────────┘"
echo ""
sleep 2

# Step 1: Generate identity
type_cmd "$SIGNET identity generate --name my-agent --unencrypted"

# Step 2: Sign tool calls
type_cmd "$SIGNET sign --key my-agent --tool web_search --params '{\"query\":\"signet\"}' --target mcp://search --no-log"
sleep 0.5

type_cmd "$SIGNET sign --key my-agent --tool github_create_issue --params '{\"title\":\"fix bug\"}' --target mcp://github"

type_cmd "$SIGNET sign --key my-agent --tool file_write --params '{\"path\":\"/tmp/out.txt\"}' --target mcp://fs"

# Step 3: Query audit log
type_cmd "$SIGNET audit"

# Step 4: Verify signatures
type_cmd "$SIGNET audit --verify"

# Step 5: Verify chain integrity
type_cmd "$SIGNET verify --chain"

# Step 6: Launch dashboard
echo ""
echo -ne "\033[1;32m❯\033[0m "
echo "signet dashboard --open"
echo ""
echo "  Signet Dashboard: http://localhost:9191"
echo "  → Timeline, Chain Integrity, Signatures, Stats"
echo ""
sleep 3

echo ""
echo "  ✓ Every tool call signed with Ed25519"
echo "  ✓ Hash-chained audit log"
echo "  ✓ Offline verification"
echo "  ✓ Local web dashboard"
echo ""
echo "  github.com/Prismer-AI/signet"
echo ""
sleep 3

# Cleanup
rm -rf "$SIGNET_HOME"
