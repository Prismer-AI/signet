# Signet Compliance Mapping

Signet provides the technical controls that auditors look for when assessing AI agent operations. This document maps Signet's capabilities to specific compliance framework requirements.

> Signet is an open-source tool, not a compliance certification. These mappings show which audit controls Signet's features address. Your compliance posture depends on how you deploy and configure them.

---

## SOC 2 Type II

| Trust Service Criteria | Control | Signet Feature |
|----------------------|---------|---------------|
| **CC6.1** — Logical access security | Authorized agents are identified before acting | Ed25519 agent identity + delegation chains with scoped authority |
| **CC6.3** — Role-based access | Agents operate within defined scope | Policy engine (tool/target/param rules) + delegation scope narrowing |
| **CC7.2** — System monitoring | Actions are logged for review | Hash-chained audit log with `signet audit` queries |
| **CC7.3** — Anomaly detection | Unauthorized changes are detectable | Tamper-evident chain (`signet verify --chain`) + signature verification |
| **CC8.1** — Change management | Changes are authorized and tracked | v4 receipts embed delegation proof showing who authorized what |
| **A1.2** — Recovery objectives | Audit evidence supports incident review and operator-managed preservation | Append-only JSONL files, exportable audit records, bilateral co-signing where configured |

### What an auditor sees

```bash
# Show all agent actions in the last 7 days
signet audit --since 7d

# Verify no records were tampered with
signet verify --chain

# Verify all signatures are valid
signet audit --verify

# Export as JSON for evidence package
signet audit --since 30d --export evidence.json
```

---

## ISO 27001:2022

| Control | Requirement | Signet Feature |
|---------|------------|---------------|
| **A.8.15** — Logging | Event logs recording user activities | Every tool call signed with agent identity, timestamp, params hash |
| **A.8.16** — Monitoring | Logs shall be regularly reviewed | Dashboard (`signet dashboard`) + CLI queries |
| **A.8.17** — Clock synchronization | Consistent timestamps | RFC 3339 timestamps on all receipts (trusted timestamp planned) |
| **A.5.15** — Access control | Access based on business requirements | Policy engine enforces tool/target/param rules before signing |
| **A.5.17** — Authentication | Identity verification | Ed25519 cryptographic identity per agent |
| **A.8.5** — Secure authentication | Authentication mechanisms | Delegation chains verify who authorized the agent |
| **A.8.9** — Configuration management | Policies documented and enforced | YAML policy files with `compute_policy_hash()` for version tracking |

---

## EU AI Act (Article 12 — Record-Keeping)

Article 12 requires high-risk AI systems to have logging capabilities that record:

| Requirement | Article 12 Text (summarized) | Signet Feature |
|------------|------------------------------|---------------|
| Event logging | Record events over the system's lifetime | Hash-chained audit log, daily JSONL files |
| Traceability | Tracing the system's operation back to inputs | `trace_id` + `parent_receipt_id` link receipts across workflows |
| Identification | Identify the natural/legal person responsible | `signer.name` + `signer.owner` + delegation chain root |
| Monitoring | Enable post-market monitoring | `signet audit --since` queries + dashboard |
| Integrity | Logs cannot be modified undetected | SHA-256 hash chain + Ed25519 signatures |

### Exporting Article 12-supporting audit evidence

```bash
# Export audit records for a specific period
signet audit --since 90d --export article12-evidence.json

# Verify chain integrity before submission
signet verify --chain

# Verify all signatures
signet audit --verify
```

The exported JSON contains receipts with full signature data for later review.

Current limitation:

- this export is a raw JSON record dump, not yet a signed evidence bundle with its own manifest, restore flow, or off-host verification packaging

---

## DORA (Digital Operational Resilience Act)

Relevant for financial services deploying AI agents:

| DORA Requirement | Signet Feature |
|-----------------|---------------|
| ICT incident logging (Art. 17) | Audit trail with signed timestamps, violation records for denied actions |
| Third-party risk (Art. 28-30) | Bilateral co-signing proves what the agent sent AND what the server returned — independent of provider logs |
| Audit trail integrity | Hash chain + signatures — tamper-evident without trusting the platform |
| Testing and monitoring (Art. 24-27) | Policy engine dry-run (`signet policy check`) validates rules before deployment |

---

## NIST AI Risk Management Framework (AI RMF 1.0)

| Function | Category | Signet Feature |
|----------|---------|---------------|
| **GOVERN** | Accountability structures | Delegation chains prove authorization hierarchy |
| **MAP** | Context documentation | Signed receipts record tool, params, target, timestamp |
| **MEASURE** | Monitoring metrics | Audit queries by time, tool, signer; dashboard visualization |
| **MANAGE** | Risk controls | Policy engine blocks denied actions, logs violations |

---

## What Signet Does NOT Provide

- **Certification** — Signet is a tool, not a certification body. It provides controls, not attestations of compliance.
- **Legal advice** — Compliance requirements vary by jurisdiction. Consult your legal team.
- **Data residency** — Audit logs are stored locally. Off-host anchoring and hosted solutions are planned.
- **Trusted timestamps** — Receipts use agent-local clocks. RFC 3161 trusted timestamping is on the roadmap.
- **Key management HSM** — Keys are software-stored (Argon2id encrypted). HSM integration is planned.

---

## Quick Reference: Feature → Compliance Control

| Signet Feature | SOC 2 | ISO 27001 | EU AI Act | DORA | NIST AI RMF |
|---------------|-------|-----------|-----------|------|-------------|
| Ed25519 signing | CC6.1 | A.5.17 | Art. 12 (identification) | — | GOVERN |
| Hash-chain audit | CC7.2, CC7.3 | A.8.15 | Art. 12 (integrity) | Art. 17 | MEASURE |
| Policy engine | CC6.3 | A.5.15, A.8.9 | — | Art. 24-27 | MANAGE |
| Delegation chains | CC8.1 | A.8.5 | Art. 12 (identification) | — | GOVERN |
| Bilateral co-signing | A1.2 | — | Art. 12 (traceability) | Art. 28-30 | — |
| Trace correlation | — | — | Art. 12 (traceability) | — | MAP |
| Violation logging | CC7.3 | A.8.16 | — | Art. 17 | MANAGE |
| Dashboard | CC7.2 | A.8.16 | Art. 12 (monitoring) | — | MEASURE |
