# vhs script — shorter "value prop" demo without needing OpenClaw running.
# Shows: sign a tool call manually → audit shows it → tamper → verify fails.
# Useful when you want to record the cryptography part fast without the
# OpenClaw setup cost.
#
# Render with:    vhs audit-only.tape
# Output:         audit-only.gif (~1MB, ~20s)

Output audit-only.gif

Set FontSize 14
Set Width 1000
Set Height 480
Set TypingSpeed 35ms
Set Theme "Catppuccin Mocha"
Set Padding 16

Type "# Signet — tamper-evident audit log for AI agent tool calls"
Enter
Sleep 1.2s

Type "signet identity generate --name openclaw-agent --unencrypted"
Enter
Sleep 1.2s

Type `signet sign --key openclaw-agent --tool write_file --params '{"path":"/tmp/demo.txt","content":"hello"}' --target openclaw://gateway/local`
Enter
Sleep 2s

Type "signet audit"
Enter
Sleep 2s

Type "signet audit --verify"
Enter
Sleep 1.5s

Type "# now an attacker tampers with the audit log..."
Enter
Sleep 800ms

Type "sed -i 's/demo.txt/evil.txt/' ~/.signet/audit/*.jsonl"
Enter
Sleep 600ms

Type "signet audit --verify"
Enter
Sleep 2.5s

Type "# tamper detected. log is hash-chained + Ed25519-signed."
Enter
Sleep 2.5s
