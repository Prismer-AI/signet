#!/usr/bin/env node
// Daily contract drift check for @signet-auth/openclaw-plugin.
//
// Usage:
//   node scripts/check-openclaw-contract.mjs [<types.ts> <hook-types.ts> <api-builder.ts>]
//
// When no args are given, the script fetches the live files from
// openclaw/openclaw main (gh CLI required). When args are given, those local
// paths are inspected instead — useful for offline runs and unit tests.
//
// Exit code 0 = contracts our packages/signet-openclaw-plugin/src/index.ts
// rely on are still present in OpenClaw main. Exit code 1 = drift detected.
// On drift the failing checks and a remediation hint are printed to stderr.

import { readFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const REMOTE_FILES = {
  types: "src/plugins/types.ts",
  hookTypes: "src/plugins/hook-types.ts",
  apiBuilder: "src/plugins/api-builder.ts",
};

const REPO = "openclaw/openclaw";

async function fetchRemote(path) {
  const { stdout } = await execFileAsync("gh", [
    "api",
    `repos/${REPO}/contents/${path}`,
    "--jq",
    ".content",
  ]);
  return Buffer.from(stdout.trim(), "base64").toString("utf8");
}

async function loadSources(args) {
  if (args.length === 0) {
    const [types, hookTypes, apiBuilder] = await Promise.all([
      fetchRemote(REMOTE_FILES.types),
      fetchRemote(REMOTE_FILES.hookTypes),
      fetchRemote(REMOTE_FILES.apiBuilder),
    ]);
    return { types, hookTypes, apiBuilder };
  }
  if (args.length !== 3) {
    throw new Error(
      "expected 0 or 3 args: <types.ts> <hook-types.ts> <api-builder.ts>",
    );
  }
  const [types, hookTypes, apiBuilder] = await Promise.all(
    args.map((p) => readFile(p, "utf8")),
  );
  return { types, hookTypes, apiBuilder };
}

const checks = [
  {
    id: "OpenClawPluginApi.on(hookName, handler, opts) — typed hook entry",
    source: "types.ts",
    patterns: [
      /on:\s*<K extends PluginHookName>/,
      /handler:\s*PluginHookHandlerMap\[K\]/,
      /opts\?:\s*\{\s*priority\?:\s*number\s*\}/,
    ],
    impact:
      "src/index.ts uses api.on('before_tool_call', handler, { priority }). " +
      "If api.on goes away or its signature changes, every signed call is dropped.",
  },
  {
    id: "PluginHookBeforeToolCallEvent shape",
    source: "hook-types.ts",
    patterns: [
      /export type PluginHookBeforeToolCallEvent\s*=\s*\{/,
      /toolName:\s*string/,
      /params:\s*Record<string,\s*unknown>/,
      /toolCallId\?:\s*string/,
    ],
    impact:
      "src/index.ts reads event.toolName / event.params / event.toolCallId. " +
      "Field rename or removal silently breaks signing payload assembly.",
  },
  {
    id: "PluginHookBeforeToolCallResult shape",
    source: "hook-types.ts",
    patterns: [
      /export type PluginHookBeforeToolCallResult\s*=\s*\{/,
      /params\?:\s*Record<string,\s*unknown>/,
      /block\?:\s*boolean/,
      /blockReason\?:\s*string/,
    ],
    impact:
      "src/index.ts returns { block, blockReason } on policy denial. " +
      "If block semantics change, denied tool calls may execute anyway.",
  },
  {
    id: "PluginHookToolContext exposes sessionKey/runId/agentId",
    source: "hook-types.ts",
    patterns: [
      /export type PluginHookToolContext\s*=\s*\{/,
      /sessionKey\?:\s*string/,
      /runId\?:\s*string/,
      /agentId\?:\s*string/,
    ],
    impact:
      "src/index.ts passes ctx.sessionKey -> receipt.action.session and " +
      "ctx.runId -> receipt.action.trace_id. Drift here breaks session binding.",
  },
  {
    id: "PluginHookAfterToolCallEvent.error field still optional",
    source: "hook-types.ts",
    patterns: [
      /export type PluginHookAfterToolCallEvent\s*=\s*\{/,
      /error\?:\s*string/,
    ],
    impact:
      "src/index.ts logs after.error at warn level. If error rename happens, " +
      "tool failure observability silently regresses.",
  },
  {
    id: "OpenClawPluginSecurityAuditCollector is a function (ctx) => findings",
    source: "types.ts",
    patterns: [
      /export type OpenClawPluginSecurityAuditCollector\s*=\s*\(/,
      /ctx:\s*OpenClawPluginSecurityAuditContext\s*,?\s*\)/,
      /=>\s*SecurityAuditFinding\[\]/,
    ],
    impact:
      "src/index.ts passes a function to api.registerSecurityAuditCollector(). " +
      "If the API regresses to an object form, the security audit collector throws on load.",
  },
  {
    id: "registerSecurityAuditCollector wired through api-builder",
    source: "api-builder.ts",
    patterns: [
      /registerSecurityAuditCollector/,
    ],
    impact:
      "If the registrar disappears from api-builder, the collector wire is dead even if the type still exists.",
  },
];

// SecurityAuditFinding lives in src/security/audit.types.ts. We check the
// type body field-by-field so a benign reorder (which is not a TypeScript
// contract break) does not trigger a drift alert.
const SECURITY_AUDIT_TYPE_RE = /export type SecurityAuditFinding\s*=\s*\{([\s\S]+?)\};/;
const SECURITY_AUDIT_REQUIRED_FIELDS = [
  /\bcheckId\s*:\s*string/,
  /\bseverity\s*:\s*[A-Za-z][\w]*/,
  /\btitle\s*:\s*string/,
  /\bdetail\s*:\s*string/,
];

function runChecks(sources) {
  const failed = [];
  for (const check of checks) {
    const sourceText = sources[sourceKey(check.source)];
    if (!sourceText) {
      failed.push({
        check,
        reason: `source file not loaded: ${check.source}`,
      });
      continue;
    }
    const missing = check.patterns.filter((re) => !re.test(sourceText));
    if (missing.length > 0) {
      failed.push({
        check,
        reason: `missing patterns: ${missing.map((re) => re.source).join("; ")}`,
      });
    }
  }

  // Cross-source: SecurityAuditFinding shape lives in src/security/audit.types.ts
  // upstream; we check it via the fact that hook-types or types references it
  // and the four fields stay together when fetched directly.
  return failed;
}

function sourceKey(name) {
  switch (name) {
    case "types.ts":
      return "types";
    case "hook-types.ts":
      return "hookTypes";
    case "api-builder.ts":
      return "apiBuilder";
    default:
      throw new Error(`unknown source name: ${name}`);
  }
}

async function main() {
  const args = process.argv.slice(2);
  const sources = await loadSources(args);
  const failures = runChecks(sources);

  // Extra: pull SecurityAuditFinding shape directly from upstream to confirm
  // its 4 fields are intact. Done separately because the type lives in a
  // different file we do not need for the rest of the checks.
  if (args.length === 0) {
    try {
      const auditTypes = await fetchRemote("src/security/audit.types.ts");
      const typeMatch = SECURITY_AUDIT_TYPE_RE.exec(auditTypes);
      if (!typeMatch) {
        failures.push({
          check: {
            id: "SecurityAuditFinding type still exported from audit.types.ts",
            source: "security/audit.types.ts",
          },
          reason: "could not locate `export type SecurityAuditFinding = { ... };`",
        });
      } else {
        const body = typeMatch[1];
        const missing = SECURITY_AUDIT_REQUIRED_FIELDS.filter((re) => !re.test(body));
        if (missing.length > 0) {
          failures.push({
            check: {
              id: "SecurityAuditFinding {checkId,severity,title,detail} fields preserved",
              source: "security/audit.types.ts",
            },
            reason: `missing fields (order-independent): ${missing.map((re) => re.source).join("; ")}`,
          });
        }
      }
    } catch (err) {
      // Treat fetch failure as infrastructure problem, not contract drift.
      // Re-throw so main() can route it to exit code 2 distinct from drift.
      throw new Error(
        `failed to fetch src/security/audit.types.ts (infrastructure issue, not drift): ${
          err instanceof Error ? err.message : String(err)
        }`,
      );
    }
  }

  if (failures.length === 0) {
    console.log(
      `[openclaw-contract-check] PASS — ${checks.length + (args.length === 0 ? 1 : 0)} contract assertions hold against ${REPO}@main`,
    );
    process.exit(0);
  }

  console.error(
    `[openclaw-contract-check] FAIL — ${failures.length} drift(s) detected:\n`,
  );
  for (const { check, reason } of failures) {
    console.error(`  - ${check.id} (${check.source})`);
    console.error(`      ${reason}`);
    if (check.impact) {
      console.error(`      impact: ${check.impact}`);
    }
    console.error("");
  }
  console.error(
    "Re-read packages/signet-openclaw-plugin/src/index.ts against the upstream source above " +
      "and either (a) update our *Like interfaces and call sites to match the new shape, " +
      "or (b) bump openclaw.compat.pluginApi to exclude the OpenClaw build that introduced the drift.",
  );
  process.exit(1);
}

main().catch((err) => {
  console.error("[openclaw-contract-check] unexpected error:", err);
  process.exit(2);
});
