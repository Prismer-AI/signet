# 20-Minute Demo Deck

Date: 2026-04-23
Audience: AI platform, security, internal tools, GRC
Goal: book a design-partner pilot for one protected workflow

## Slide 1: Title

**Signet: trusted execution for agent actions**

- signed requests
- execution-boundary verification
- verifiable receipts
- offline audit evidence

Talk track:
We are not replacing your agent stack. We add proof and control at the point where agents take action.

## Slide 2: Why This Matters Now

- agents are moving from chat to action
- MCP is becoming a standard integration layer
- more workflows now cross Slack, GitHub, tickets, docs, and internal systems
- governance pressure rises once agents are shared across teams

Talk track:
The market question changed. It is no longer just capability. It is whether teams can trust and prove what happened.

## Slide 3: The Gap

Most stacks can tell you:

- what the platform logged
- what the workflow engine claims happened

Most stacks cannot prove:

- that the request was trusted before execution
- what crossed the execution boundary
- whether the evidence can be verified later without vendor access

## Slide 4: What Signet Adds

- sign each action request
- verify trust before execution
- issue trusted bilateral receipts
- keep a tamper-evident audit trail
- export evidence for later verification

Talk track:
This is a narrow layer. It can sit next to MCP, internal tools, approval logic, and observability.

## Slide 5: Product Shape

- OSS core: SDKs, CLI, proxy, local audit log
- control layer: trusted keys, verification paths, warnings
- enterprise expansion: registry, policy UI, approvals, evidence export, SIEM/GRC connectors

Talk track:
The open-source layer proves the core model. Commercial expansion is around operating this across teams and environments.

## Slide 6: Best Use Cases

- trusted MCP gateway for internal tools
- high-risk actions that need approval and evidence
- document or operational workflows with audit pressure
- enterprise rollouts where platform teams want proof without platform lock-in

## Slide 7: Live Demo Flow

Show one workflow only:

1. signed request leaves the client
2. server verifies before execution
3. tampered or untrusted request gets rejected
4. valid request gets executed and co-signed
5. receipt is visible in audit output or dashboard

Repo demo assets:

- `examples/mcp-agent/demo-execution-boundary.mjs`
- `demo-execution-boundary.svg`
- `signet proxy`
- `signet audit --verify`

## Slide 8: Why Teams Buy

- security team gets stronger evidence
- platform team gets a narrow control layer
- workflow owner gets safer automation
- compliance team gets exportable proof

Talk track:
This helps multiple stakeholders without forcing them onto a new agent platform.

## Slide 9: Pilot Offer

**2-week protected-workflow pilot**

- choose one MCP or internal tool path
- add signing + verification
- export receipts and walkthrough evidence
- define success criteria up front

Success metrics:

- trusted requests verified before execution
- untrusted or tampered calls rejected
- evidence visible to both platform and security owners

## Slide 10: Close

**Start with one workflow. Do not boil the ocean.**

CTA:

- pick one protected path
- identify one security/platform owner
- run a 2-week pilot

## Appendix: Likely Questions

### Is this a replacement for observability?

No. Observability helps teams inspect. Signet helps teams prove.

### Do we have to change our agent stack?

Not necessarily. Start at the MCP boundary, transport layer, or one internal workflow.

### Can this work with existing controls?

Yes. Signet is designed to sit alongside logging, tracing, approvals, and policy engines.

### What should the first pilot be?

Choose the narrowest workflow that already has:

- a real action
- a real owner
- a trust or audit concern
