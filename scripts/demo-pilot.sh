#!/usr/bin/env bash
# 30-second demo of the single-host pilot flow:
# identity → sign → bundle → restore-on-another-machine.
#
# Designed to be recorded via asciinema and converted to GIF via agg.
# Output is paced for human readability (sleep + typing animation).

set -euo pipefail

BOLD='\033[1m'
DIM='\033[2m'
GREEN='\033[32m'
CYAN='\033[36m'
YELLOW='\033[33m'
RESET='\033[0m'

# Pacing: short pauses so a viewer can read but not get bored.
PAUSE_SHORT=0.6
PAUSE_LONG=1.2

# Use ephemeral signet home so the demo doesn't pollute the user's keys.
export SIGNET_HOME=$(mktemp -d)
PILOT_BUNDLE=$(mktemp -d)
AUDITOR_RESTORE_DIR="$PILOT_BUNDLE"

cleanup() {
  rm -rf "$SIGNET_HOME" "$PILOT_BUNDLE"
}
trap cleanup EXIT

clear
echo -e "${BOLD}signet — single-host pilot demo${RESET}"
echo -e "${DIM}Sign every agent tool call. Verify offline. Hand off as evidence.${RESET}"
sleep $PAUSE_LONG

# Step 1
echo
echo -e "${CYAN}\$ signet identity generate --name agent-pilot${RESET}"
sleep $PAUSE_SHORT
signet identity generate --name agent-pilot --unencrypted >/dev/null
echo -e "${GREEN}✓${RESET} ed25519 keypair created at ${DIM}\$SIGNET_HOME/keys/agent-pilot.{key,pub}${RESET}"
sleep $PAUSE_LONG

# Step 2
echo
echo -e "${CYAN}\$ signet sign --tool web_search --params '{\"q\":\"crypto\"}' ...${RESET}"
sleep $PAUSE_SHORT
signet sign --key agent-pilot --tool "web_search" \
  --params '{"q":"crypto"}' --target "mcp://search" >/dev/null
signet sign --key agent-pilot --tool "Bash" \
  --params '{"cmd":"deploy.sh"}' --target "mcp://shell" >/dev/null
signet sign --key agent-pilot --tool "Read" \
  --params '{"path":"audit.log"}' --target "mcp://fs" >/dev/null
echo -e "${GREEN}✓${RESET} 3 tool calls signed → hash-chained audit log"
sleep $PAUSE_LONG

# Step 3
echo
echo -e "${CYAN}\$ signet audit --since 1h${RESET}"
sleep $PAUSE_SHORT
signet audit --since 1h | head -7
sleep $PAUSE_LONG

# Step 4
echo
echo -e "${CYAN}\$ signet audit --bundle ./pilot-evidence-2026-04${RESET}"
sleep $PAUSE_SHORT
signet audit --bundle "$PILOT_BUNDLE/evidence" 2>&1 | head -2
sleep $PAUSE_SHORT
echo -e "${DIM}  $(ls "$PILOT_BUNDLE/evidence" | tr '\n' ' ')${RESET}"
sleep $PAUSE_LONG

# Step 5: simulate auditor on a different machine, no keystore
echo
echo -e "${YELLOW}# auditor's machine — no keys, no keystore${RESET}"
echo -e "${CYAN}\$ signet audit --restore ./pilot-evidence-2026-04${RESET}"
sleep $PAUSE_SHORT
SIGNET_HOME=/nonexistent signet audit --restore "$PILOT_BUNDLE/evidence" | head -7
sleep $PAUSE_LONG

echo
echo -e "${BOLD}${GREEN}Off-host evidence: signed, chain-verified, ready for handoff.${RESET}"
echo -e "${DIM}github.com/Prismer-AI/signet${RESET}"
sleep 2
