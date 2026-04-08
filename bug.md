# Signet Review — Bug & Issue Tracker

Reviewed: 2026-04-07
Verified by Codex (394k tokens): 2026-04-07

Legend: CONFIRMED / PARTIALLY / FALSE POSITIVE | severity from original review, Codex disagreement noted

---

## CRITICAL

- [x] ~~**`signet_sign` MCP tool 接受明文 `secret_key` 参数**~~ — 已移除 `secret_key` 参数，只从 `SIGNET_SECRET_KEY` 环境变量读取（f304aa9, 2026-04-08）
  - 位置: `packages/signet-mcp-tools/src/tools.ts:39, 89`
  - Codex: **CONFIRMED** — severity 同意

- [x] ~~**Token 文件残留在仓库目录**~~ — `.mcpregistry_*` 为 untracked/ignored，未 committed
  - Codex: **PARTIALLY CONFIRMED** — 文件存在于磁盘但不在 git 中，已加入 .gitignore，风险已控制
  - ⚠️ 仍建议：token 已轮换，可安全忽略

---

## HIGH

- [x] ~~**Audit log 无文件锁**~~ — 已加 `fs2::lock_exclusive()` 排他锁���防止并发���损坏 hash chain（f304aa9, 2026-04-08）
  - 位置: `crates/signet-core/src/audit.rs:162-199`
  - Codex: **CONFIRMED** — severity 同意

- [x] ~~**`verify_bilateral` 信任 receipt 内嵌的 agent pubkey**~~ — `BilateralVerifyOptions` 新增 `trusted_agent_pubkey` 字段，设置后校验 agent key 是否在信任列表中（f304aa9, 2026-04-08）
  - 位置: `crates/signet-core/src/verify.rs:161-176`
  - 额外: `audit.rs:346` 同样存在 v3 receipt self-trust 路径（Codex 新发现）
  - Codex: **CONFIRMED** — severity 同意

- [ ] **CI 用 nightly Rust 不锁版本** — nightly 破坏可能导致发布失败
  - 位置: `.github/workflows/ci.yml:19`, `.github/workflows/release.yml:33`
  - Codex: **CONFIRMED** — severity 降级（认为是低风险，非 HIGH）

- [x] ~~**Release pipeline `|| true` 吞错误**~~ — 改为只在 "already published" 时跳过，其他错误会让 job 失败（e7a887c, 2026-04-08）
  - 位置: `.github/workflows/release.yml:148, 154, 182, 190, 198, 206, 236`
  - Codex: **CONFIRMED** — severity 同意

- [x] ~~**版本不一致**~~ — 已统一到 0.4.5（d14c883, 2026-04-08）
  - 位置: `packages/signet-mcp-tools/src/tools.ts:22`
  - Codex: **CONFIRMED** — severity 降级（认为是 MEDIUM）

- [ ] **NonceCache 纯内存** — 进程重启后 nonce 历史丢失，5 分钟窗口内可重放
  - 位置: `packages/signet-mcp-server/src/nonce-cache.ts`
  - Codex: **CONFIRMED** — severity 降级（认为是 MEDIUM，单进程场景下可接受）

---

## HIGH (Codex 新发现)

- [ ] **`signing-transport.ts` 默认不校验 server pubkey** — `trustedServerKeys` 未设置时 bilateral verification 接受任意 server pubkey
  - 位置: `packages/signet-mcp/src/signing-transport.ts:110, 130`
  - Codex: 新发现

---

## MEDIUM

- [x] ~~**CI 不测 `mcp-server`、`mcp-tools`、`vercel-ai`**~~ — CI 已补充测��这 3 个包（e7a887c, 2026-04-08）
  - 位置: `.github/workflows/ci.yml`
  - Codex: **CONFIRMED** — severity 同意

- [ ] **`load_key_info` 不校验文件名与内容 `name` 字段一致性** — 攻击者可篡改 `.pub` 文件造成 key confusion
  - 位置: `crates/signet-core/src/identity.rs:136-149`（测试 357 行已验证此场景）
  - Codex: **CONFIRMED** — severity 同意

- [ ] **`params_hash` 直通不校验格式** — 应要求 `sha256:[0-9a-f]{64}`
  - 位置: `crates/signet-core/src/sign.rs:14-17`
  - Codex: **CONFIRMED** — severity 降级（认为是 LOW）

- [ ] **`generate_keypair` MCP tool 生成后丢弃 secret key** — 用户只拿到 public key，UX 易困惑
  - 位置: `packages/signet-mcp-tools/src/tools.ts:81-85`
  - Codex: **PARTIALLY CONFIRMED** — 注释说明是故意行为，severity 降级

- [ ] **NonceCache 无上限** — 无 maxSize，高并发可 OOM
  - 位置: `packages/signet-mcp-server/src/nonce-cache.ts:6, 32`
  - Codex: **CONFIRMED** — severity 同意

- [x] ~~**Cargo.lock 在 .gitignore 但实际已提交**~~ — FALSE POSITIVE，Cargo.lock 未被 git 追踪
  - Codex: **FALSE POSITIVE**

- [ ] **`signing-transport.ts` 注释与行为不一致** — 注释说 "only after bilateral checks pass" 但实际无条件转发
  - 位置: `packages/signet-mcp/src/signing-transport.ts:141-142`
  - Codex: **CONFIRMED** — severity 降级（认为是 LOW）

- [ ] **`sign.rs` 重复代码** — `sign()`、`sign_compound()`、`sign_bilateral()` 共享样板代码
  - 位置: `crates/signet-core/src/sign.rs:38, 107, 186`
  - Codex: **PARTIALLY CONFIRMED** — 维护层面的 smell，非 bug，severity 降级

---

## LOW

- [x] ~~**`unsafe` grep 检查过于宽泛**~~ — 已改为 `cargo clippy -D unsafe_code`（e7a887c, 2026-04-08）
  - 位置: `.github/workflows/ci.yml:33-37`
  - Codex: **CONFIRMED** — severity 同意

- [ ] **Regex 每次调用都编译** — `validate_key_name` 应用 `LazyLock` 缓存
  - 位置: `crates/signet-core/src/identity.rs:37`
  - Codex: **CONFIRMED** — severity 同意

- [ ] **Dockerfile 引用 `package-lock.json` 但 .gitignore 排除了它** — 文件实际被 git 追踪但 .gitignore 有矛盾条目，clean clone 后若 .gitignore 生效可能缺失
  - 位置: `Dockerfile:5`, `.gitignore:64`
  - Codex: **PARTIALLY CONFIRMED** — 当前不会 break，但配置矛盾

- [ ] **`console.warn` 硬编码在 vercel-ai 集成中** — 应支持自定义 logger callback
  - 位置: `packages/signet-vercel-ai/src/index.ts:82`
  - Codex: **CONFIRMED** — severity 同意

---

## 验证摘要 (Codex)

| 结论                | 数量                      |
| ------------------- | ------------------------- |
| CONFIRMED           | 14                        |
| PARTIALLY CONFIRMED | 4                         |
| FALSE POSITIVE      | 2 (CRITICAL-2 / MEDIUM-6) |
| 新发现              | 2                         |

两个 FALSE POSITIVE 已在上方标记删除线。

## 修复进度（2026-04-08）

已修复 7 项：

- CRITICAL: `signet_sign` 明文 secret_key → 环境变量专用
- HIGH: audit log 文件锁 → fs2 flock
- HIGH: verify_bilateral 自签信任 → trusted_agent_pubkey
- HIGH: release `|| true` → 只跳过 already-published
- HIGH: 版本不一致 → 统一 0.4.5
- MEDIUM: CI 不测 3 个包 → 已补充
- LOW: unsafe grep → cargo clippy -D unsafe_code

剩余 open 项：11（HIGH 3 + MEDIUM 5 + LOW 3）
