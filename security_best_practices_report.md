# Security Review Report

## Executive Summary

本次审计以静态代码审查为主，并补充了 `npm audit --omit=dev --json` 的实时依赖检查。结论是：Rust 核心加密实现没有看到明显的 `unsafe`/弱算法误用，但仓库里存在几处会削弱“可验证性”承诺的实现风险，尤其集中在 bilateral receipt、插件审计日志写入，以及示例/代理的默认安全边界上。

优先级最高的 2 个问题：

1. 服务器端 `signResponse()` 只验证“签名自洽”，不验证 agent 是否受信，示例代码还会对未受信请求进行 co-sign。
2. Codex / Claude 插件的 audit 日志写入没有加锁，并发时会破坏 hash chain。

初次扫描时确认了 3 个 npm advisory、1 个 RustSec 漏洞，以及 1 个 RustSec unsound 警告。Python 项目级 `pip-audit` 没发现可扫描的顶层依赖，因为 `bindings/signet-py/pyproject.toml` 没有 `dependencies` 列表。

状态更新（2026-04-23）：

- SBP-001 已在当前工作区修复：`signResponse()` 现在要求先执行 `verifyRequest()`，并默认拒绝对未锚定 trust anchor 的请求 co-sign。
- SBP-002 已在当前工作区修复：Codex / Claude 插件的 audit append 已加入 lock file 临界区，并补了并发测试。
- SBP-004 已在当前工作区修复：`signet proxy` 默认改为 argv 直接执行，shell 模式需要显式 `--shell`，并且默认过滤常见 token/API key，支持 `--allow-env` 精确放行。
- SBP-005 已在当前工作区修复：reference verifier example 现在默认要求签名并要求 signer 命中 trust anchor；未配置 `SIGNET_TRUSTED_KEYS` 时会明确拒绝而不是退化到 signature-only。
- SBP-003 已进一步缓解：`@signet-auth/mcp` 的 `SigningTransport` 默认不再把未锚定 trust anchor 的 bilateral receipt 当成 trusted callback；Rust core 新增了显式 bilateral trust outcome；CLI / Python 的 audit verify 现已支持显式 trusted agent/server keys，未提供 trust anchor 时会把 v3 的 integrity-only 校验标成 warning，而不是静默归入 fully trusted 语义。
- DEP-001 / DEP-002 已在当前工作区修复：root 与 example 的 `npm audit --omit=dev` 现在都为 0。
- DEP-003 / DEP-004 已在当前工作区修复：`cargo-audit` 当前结果为 0，`pyo3` 已更新到 `0.24.2`，`pythonize` 到 `0.24.0`，`rand` 到 `0.8.6`。

## High Severity

### SBP-001: Server can co-sign untrusted agent receipts
**Impact:** 攻击者可用自签名 receipt 换取服务器的 bilateral receipt，导致下游把“服务器确实处理过”误读为“服务器确认了受信 agent 身份”。

- `signResponse()` 只校验 `_meta._signet` 的签名是否能被 receipt 自带公钥验证，不要求该 agent key 在信任列表中：[packages/signet-mcp-server/src/sign-response.ts](/home/willamhou/codes/signet/packages/signet-mcp-server/src/sign-response.ts:13)
- 示例 `echo-server` 默认 `requireSignature: false`，且只要带了 `_signet` 就会 co-sign，即使请求未受信：[examples/mcp-agent/echo-server.ts](/home/willamhou/codes/signet/examples/mcp-agent/echo-server.ts:14), [examples/mcp-agent/echo-server.ts](/home/willamhou/codes/signet/examples/mcp-agent/echo-server.ts:53)
- Rust 侧 bilateral 验证默认也不要求 `trusted_agent_pubkey`，只保证 receipt 自洽：[crates/signet-core/src/verify.rs](/home/willamhou/codes/signet/crates/signet-core/src/verify.rs:202), [crates/signet-core/src/verify.rs](/home/willamhou/codes/signet/crates/signet-core/src/verify.rs:222), [crates/signet-core/src/verify.rs](/home/willamhou/codes/signet/crates/signet-core/src/verify.rs:304)

建议：

- 让 `signResponse()` 接受 `verifyRequest()` 的成功结果或显式的 trusted signer context，而不是重复做“自证”校验。
- 示例代码只在 `verified.ok === true` 且启用了受信 key 校验时 co-sign。
- 文档上把“integrity verified”和“identity trusted”明确拆开。

修复状态：已在当前工作区落地，见 `packages/signet-mcp-server` 与 `examples/mcp-agent` 的对应改动。

### SBP-002: Plugin audit chain is not concurrency-safe
**Impact:** 并发 hook 写入时可能生成错误的 `prev_hash`，导致审计链分叉或损坏，直接削弱仓库宣称的 tamper-evident audit trail。

- 两个插件都先读最后一条 hash，再直接 `appendFileSync()`，中间没有锁或 CAS：[plugins/codex/lib/audit.cjs](/home/willamhou/codes/signet/plugins/codex/lib/audit.cjs:9), [plugins/claude-code/lib/audit.cjs](/home/willamhou/codes/signet/plugins/claude-code/lib/audit.cjs:9)
- Rust 正式实现已经使用 `.lock` 文件做排他锁，说明作者自己也认定这里需要并发保护：[crates/signet-core/src/audit.rs](/home/willamhou/codes/signet/crates/signet-core/src/audit.rs:173)

建议：

- 复用 Rust 的 `audit::append()` 逻辑，或在 Node 插件里实现 lock file / `flock`。
- 至少把“last hash lookup + append”做成同一临界区。

修复状态：已在当前工作区落地，见 `plugins/codex/lib/audit.cjs`、`plugins/claude-code/lib/audit.cjs` 及新增并发测试。

## Medium Severity

### SBP-003: Bilateral verification defaults validate integrity, not trust

- Rust `verify_bilateral()` 默认不校验受信 agent key：[crates/signet-core/src/verify.rs](/home/willamhou/codes/signet/crates/signet-core/src/verify.rs:234)
- `audit::verify_signatures()` 对 v3 receipt 直接使用 receipt 自报的 server key 做验签，因此结果只能说明“签名自洽”，不能说明“来自受信 server”：[crates/signet-core/src/audit.rs](/home/willamhou/codes/signet/crates/signet-core/src/audit.rs:391)
- TypeScript transport 在未配置 `trustedServerKeys` 时依然会触发 `onBilateral`，只是额外报一条 warning：[packages/signet-mcp/src/signing-transport.ts](/home/willamhou/codes/signet/packages/signet-mcp/src/signing-transport.ts:111)

建议：把“自洽但未锚定信任”的状态单独返回，避免落到同一个“verified”语义里。

修复状态：已在当前工作区进一步收紧。Rust core 公开了更明确的 bilateral verify outcome；`audit::verify_signatures()` 会对 v3 记录给出 integrity-only warning；CLI、dashboard JSON、Python binding 都能看到这个 warning，并且 CLI / Python 现在都支持传入 trusted agent/server keys，把 audit verify 升级为 anchored verification。为兼容现有调用方，旧的 `verify_bilateral()` 仍然保留并继续返回 `Result<(), _>`，Python 的 bool 接口也仍然保留，所以 integrity-only 路径并没有被彻底移除，只是有了不破坏兼容性的更强选项。

### SBP-004: `signet proxy` executes target through a shell and forwards ambient secrets by default

- 默认只过滤 `SIGNET_PASSPHRASE`，不会过滤 `OPENAI_API_KEY`、`GITHUB_TOKEN` 等环境变量：[signet-cli/src/cmd_proxy.rs](/home/willamhou/codes/signet/signet-cli/src/cmd_proxy.rs:11), [signet-cli/src/cmd_proxy.rs](/home/willamhou/codes/signet/signet-cli/src/cmd_proxy.rs:83)
- 实际启动目标进程时使用 `sh -c` / `cmd /C`：[signet-cli/src/cmd_proxy.rs](/home/willamhou/codes/signet/signet-cli/src/cmd_proxy.rs:156)

如果 `--target` 来自不完全可信的配置或第三方集成，这相当于给目标命令开放 shell 注入面，并把宿主机 token 一并暴露。

建议：默认改为 argv 形式执行，shell 模式显式 opt-in；环境变量改成 allowlist 或默认启用 `--env-filter`。

修复状态：已在当前工作区落地，`signet proxy` 默认使用 argv 直接执行；`--shell` 作为显式 opt-in；环境变量默认过滤常见凭据，并支持 `--allow-env` 精确放行。对应验证已补到 `signet-cli/tests/cli.rs`。

### SBP-005: Example verifier defaults are insecure-by-default

- 示例 verifier 默认 `requireSignature=false`，且 `trustedKeys` 为空数组：[examples/mcp-agent/verifier-server-lib.mjs](/home/willamhou/codes/signet/examples/mcp-agent/verifier-server-lib.mjs:11)
- `verifyRequest()` 在 `trustedKeys` 为空时明确跳过 trust check：[packages/signet-mcp-server/src/verify-request.ts](/home/willamhou/codes/signet/packages/signet-mcp-server/src/verify-request.ts:5), [packages/signet-mcp-server/src/verify-request.ts](/home/willamhou/codes/signet/packages/signet-mcp-server/src/verify-request.ts:80)

这更像“易误用默认值”而不是核心库漏洞，但如果有人把 example 直接部署，会得到一个只做格式/签名自检、不做认证的 verifier。

## Dependency Advisories

### DEP-001: `@modelcontextprotocol/sdk` chain pulls vulnerable `hono` / `@hono/node-server`

- Root lockfile: `@hono/node-server@1.19.12`, `hono@4.12.10`：[package-lock.json](/home/willamhou/codes/signet/package-lock.json:17), [package-lock.json](/home/willamhou/codes/signet/package-lock.json:1051)
- Example lockfile 更旧：`@hono/node-server@1.19.11`, `hono@4.12.9`：[examples/mcp-agent/package-lock.json](/home/willamhou/codes/signet/examples/mcp-agent/package-lock.json:464), [examples/mcp-agent/package-lock.json](/home/willamhou/codes/signet/examples/mcp-agent/package-lock.json:1100)

`npm audit` 命中：

- GHSA-92pp-h63x-v22m
- GHSA-wmmm-f939-6g9c
- GHSA-26pp-8wgv-hjvm
- GHSA-r5rp-j6wh-rvv4
- GHSA-458j-xx4x-4375

这些 advisory 是否在本仓库中可达，还取决于 SDK 内部实际用法，但版本已经落在受影响范围内，建议优先升级 `@modelcontextprotocol/sdk` 并重锁定。

修复状态：已在当前工作区落地。`packages/signet-mcp-tools` / `examples/mcp-agent` 的 SDK 基线已提升到 `^1.29.0`，并通过 `npm audit fix` + overrides 将 `hono` / `@hono/node-server` 提升到安全版本。当前 root 与 example 的 `npm audit --omit=dev --json` 均返回 0 vulnerabilities。

### DEP-002: `basic-ftp@5.2.1` vulnerable via `puppeteer-core`

- `basic-ftp@5.2.1` 在 root lockfile 中存在：[package-lock.json](/home/willamhou/codes/signet/package-lock.json:332)
- 来源链路为 `puppeteer-core -> @puppeteer/browsers -> proxy-agent -> get-uri -> basic-ftp`：[package-lock.json](/home/willamhou/codes/signet/package-lock.json:1457)

`npm audit` 命中：

- GHSA-6v7q-wjvx-w8wg
- GHSA-rp42-5vxx-qpwr

这条链目前更像示例/工具链暴露，而不是核心 SDK 运行时暴露，但仍建议升级 `puppeteer-core` 或用 overrides 拉高 `basic-ftp` 版本。

修复状态：已在当前工作区落地。root `package.json` 使用 overrides 将 `basic-ftp` 提升到安全版本，当前 `npm audit --omit=dev --json` 返回 0 vulnerabilities。

### DEP-003: Rust binding uses vulnerable `pyo3@0.23.5`

- `bindings/signet-py` 直接依赖 `pyo3 = "0.23"`：[bindings/signet-py/Cargo.toml](/home/willamhou/codes/signet/bindings/signet-py/Cargo.toml:12)
- 当前锁文件解析到 `pyo3@0.23.5`：[Cargo.lock](/home/willamhou/codes/signet/Cargo.lock:1074)
- `cargo-audit` 命中 `RUSTSEC-2025-0020` / `GHSA-pph8-gcv7-4qj5`，修复版本为 `>=0.24.1`

该问题描述为 `PyString::from_object` 的越界读取/内存暴露风险。是否在本仓库中可达，取决于具体是否调用了受影响 API；但因为这是 Python 绑定栈中的核心依赖，建议尽快把 `pyo3` 升级到 `0.24.1+` 并回归测试 ABI / Python 版本兼容性。

修复状态：已在当前工作区落地。`bindings/signet-py/Cargo.toml` 已提升到 `pyo3 = 0.24.1+` / `pythonize = 0.24`，实际锁文件解析到 `pyo3@0.24.2`、`pythonize@0.24.0`，并通过 `cargo test -p signet-python --no-run` 编译验证。

### DEP-004: `rand@0.8.5` has RustSec unsound warning

- 锁文件中存在 `rand@0.8.5`：[Cargo.lock](/home/willamhou/codes/signet/Cargo.lock:1162)
- `cargo-audit` 给出 `RUSTSEC-2026-0097` informational `unsound` 警告，修复版本包括 `>=0.8.6`

这不是已确认可利用的仓库漏洞，但属于值得排期处理的底层依赖风险，尤其如果未来启用了受影响的日志/线程随机数路径。

修复状态：已在当前工作区落地。`crates/signet-core/Cargo.toml` 已提升到 `rand = 0.8.6`，当前 `cargo-audit` 结果为 0 advisories。

## Optimization Opportunities

1. `audit::append()` / `query()` 频繁整文件 `read_to_string()`，大日志下会变成 O(file size) 到 O(total log size) 的热点：[crates/signet-core/src/audit.rs](/home/willamhou/codes/signet/crates/signet-core/src/audit.rs:148), [crates/signet-core/src/audit.rs](/home/willamhou/codes/signet/crates/signet-core/src/audit.rs:247)
2. `verify_signatures()` 仍然不是流式验签，内存占用模型没变；不过当前工作区已经补回真实 `file/line` 并对 v3 integrity-only 路径给出 warning，定位性比初始状态好很多：[crates/signet-core/src/audit.rs](/home/willamhou/codes/signet/crates/signet-core/src/audit.rs:371)
3. `NonceCache` 只按 `nonce` 去重，跨 signer 会误冲突，而且 `prune()` 是全表扫描；建议 key 改成 `signerPubkey:nonce`，并用 LRU/时间轮结构：[packages/signet-mcp-server/src/nonce-cache.ts](/home/willamhou/codes/signet/packages/signet-mcp-server/src/nonce-cache.ts:5)
4. `cmd_proxy` 用 `split_whitespace()` 推导 `target_uri`，对带引号/空格路径会误判；建议把命令和参数拆成显式数组：[signet-cli/src/cmd_proxy.rs](/home/willamhou/codes/signet/signet-cli/src/cmd_proxy.rs:133)

状态更新：

- Optimization #3 已在当前工作区修复：`NonceCache` 内部已按 `signerPubkey + nonce` 去重，并增加了基于 `nextExpiry` 的懒扫描，避免每次定时 prune 都全表遍历。

## Scope And Limitations

- 已完成：源码静态审查、修复后 `npm audit --omit=dev --json`、修复后 `cargo-audit`、项目级 `pip-audit`
- Python 扫描结果为“无可审计顶层依赖”，因为 [bindings/signet-py/pyproject.toml](/home/willamhou/codes/signet/bindings/signet-py/pyproject.toml:1) 只声明了 optional dependencies，没有顶层 runtime `dependencies`
- 为安装 `pip-audit`，本机用户站点包里 `tomli` / `tomli-w` 被升级；这不是仓库变更，但会影响当前用户 Python 环境
- 未做：动态模糊测试、运行时渗透、外部部署面扫描
