#!/usr/bin/env bash
set -euo pipefail

BOLD='\033[1m'
DIM='\033[2m'
GREEN='\033[32m'
CYAN='\033[36m'
RESET='\033[0m'

echo -e "${BOLD}=== Signet Interactive Demo ===${RESET}"
echo ""

# 1. Generate identity
echo -e "${CYAN}1. Generating agent identity...${RESET}"
signet identity generate --name demo-agent --unencrypted 2>/dev/null || true
signet identity export --name demo-agent
echo ""

# 2. Sign tool calls with different tools
echo -e "${CYAN}2. Signing tool calls...${RESET}"

signet sign --key demo-agent --tool "Bash" \
  --params '{"command":"pip install flask"}' \
  --target "mcp://local" > /dev/null
echo -e "  ${GREEN}✓${RESET} Bash: pip install flask"

signet sign --key demo-agent --tool "Write" \
  --params '{"path":"app.py","content":"from flask import Flask"}' \
  --target "mcp://local" > /dev/null
echo -e "  ${GREEN}✓${RESET} Write: app.py"

signet sign --key demo-agent --tool "Bash" \
  --params '{"command":"python app.py"}' \
  --target "mcp://local" > /dev/null
echo -e "  ${GREEN}✓${RESET} Bash: python app.py"

signet sign --key demo-agent --tool "Read" \
  --params '{"path":"/etc/hosts"}' \
  --target "mcp://filesystem" > /dev/null
echo -e "  ${GREEN}✓${RESET} Read: /etc/hosts"

signet sign --key demo-agent --tool "github_create_issue" \
  --params '{"title":"fix auth bug","body":"details"}' \
  --target "mcp://github.local" > /dev/null
echo -e "  ${GREEN}✓${RESET} github_create_issue: fix auth bug"

echo ""

# 3. Query audit log
echo -e "${CYAN}3. Audit log:${RESET}"
signet audit --since 1h
echo ""

# 4. Verify chain
echo -e "${CYAN}4. Verifying chain integrity...${RESET}"
signet verify --chain
echo ""

# 5. Verify signatures
echo -e "${CYAN}5. Verifying all signatures...${RESET}"
signet audit --verify
echo ""

# 6. Launch dashboard
echo -e "${CYAN}6. Launching dashboard on port 8384...${RESET}"
echo -e "${DIM}   Press Ctrl+C to stop${RESET}"
echo ""
signet dashboard --port 8384
