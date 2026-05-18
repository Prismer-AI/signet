# vhs script — install the OpenClaw plugin + show tamper-evident audit
#
# Render with:    vhs install-and-verify.tape
# Output:         install-and-verify.gif (~1.5MB, ~30s)
#
# Prereqs on the recording machine:
#   - signet CLI installed (`cargo install signet-cli` or release binary)
#   - openclaw CLI installed (`npm i -g openclaw` or via npx)
#   - clean ~/.signet (rm -rf ~/.signet before recording)
#   - clean ~/.openclaw/config.json (or a config that has the signet
#     plugin entry pre-staged)
#
# Optional: replace the `openclaw ask` line with a real prompt that
# triggers a tool call in your gateway (e.g. read_file, web_search).

Output install-and-verify.gif

Set FontSize 14
Set Width 1000
Set Height 560
Set TypingSpeed 35ms
Set Theme "Catppuccin Mocha"
Set Padding 16
Set Margin 8
Set MarginFill "#1e1e2e"

# --- Setup (title card) ---------------------------------------------------
Type "# Signet plugin for OpenClaw — Ed25519 audit receipts on every tool call"
Enter
Sleep 1.5s

# --- 1. Install plugin from ClawHub --------------------------------------
Type "openclaw plugins install @signet-auth/openclaw-plugin"
Enter
Sleep 2.5s

# --- 2. Create the signing identity (one-time) ---------------------------
Type "signet identity generate --name openclaw-agent --unencrypted"
Enter
Sleep 1.5s

# --- 3. Start OpenClaw with the plugin armed -----------------------------
Type "openclaw start &"
Enter
Sleep 1.2s
Type "# plugin self-check passes → ACTIVE mode"
Enter
Sleep 1s

# --- 4. Trigger a tool call via OpenClaw ---------------------------------
Type `openclaw ask "write the string 'hello' to /tmp/demo.txt"`
Enter
Sleep 3s

# --- 5. Inspect the audit log --------------------------------------------
Type "signet audit"
Enter
Sleep 2.5s
Type "# every tool call is a hash-chained signed receipt"
Enter
Sleep 1.2s

# --- 6. Verify integrity end-to-end --------------------------------------
Type "signet audit --verify"
Enter
Sleep 2s

# --- 7. Demonstrate tamper detection -------------------------------------
Type "# tamper with the audit log..."
Enter
Sleep 800ms
Type "sed -i 's/demo.txt/evil.txt/' ~/.signet/audit/*.jsonl"
Enter
Sleep 600ms

Type "signet audit --verify"
Enter
Sleep 2.5s
Type "# tamper detected → audit fails"
Enter
Sleep 2s

# --- Outro ----------------------------------------------------------------
Type "# install:  openclaw plugins install @signet-auth/openclaw-plugin"
Enter
Type "# source:   github.com/Prismer-AI/signet"
Enter
Sleep 3s
