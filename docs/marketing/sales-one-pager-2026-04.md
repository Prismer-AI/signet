# Signet Sales One-Pager

Date: 2026-04-23
Status: draft for founder-led sales

## Positioning

**Signet proves and enforces agent actions before they run.**

Signet adds signed requests, trusted execution receipts, and verifiable audit trails to MCP and agent workflows. It helps teams let agents act across internal tools without relying on provider logs alone.

## The Problem

Once agents can touch Slack, GitHub, tickets, documents, or internal systems, ordinary logs stop being enough.

- Logs show what a platform says happened.
- Security teams need proof of what crossed the execution boundary.
- Auditors want evidence that can be checked later.
- Platform teams need a control layer without rebuilding their agent stack.

## What Signet Does

- Signs agent requests before execution
- Verifies trust at the tool boundary
- Produces bilateral execution receipts when both sides are trusted
- Keeps a tamper-evident audit trail that can be verified offline
- Works with MCP, internal tools, approval flows, and existing observability stacks

## Best-Fit Buyers

- AI platform / internal AI teams rolling out MCP or workspace agents
- Security engineering and security architecture teams
- GRC / compliance teams that need evidence for high-risk workflows
- Internal tooling and dev productivity teams operating agent actions in production

## Best First Use Cases

- Trusted MCP gateway for internal tools
- Approval and evidence for high-risk agent actions
- Audit-ready document and workflow automation
- Agent actions that cross teams, systems, and permissions boundaries

## Why Now

Major platforms are turning agents into shared, operational systems:

- OpenAI introduced workspace agents with custom MCP server support
- Cloudflare published internal MCP rollout and enterprise MCP security architecture
- Atlassian, Notion, Box, Datadog, and others are pushing agents from chat into action

This shifts the problem from "can agents do useful work?" to "can teams trust and prove what agents did?"

## Why Signet Wins

- Independent of any model or agent vendor
- Verifiable offline, not tied to a hosted control plane
- Narrow control layer, not another end-to-end agent platform
- Open core with clear enterprise expansion points

## 2-Week Pilot Offer

Pilot one workflow:

- 1 protected MCP or internal tool path
- request signing + boundary verification
- receipt export + audit walkthrough
- success criteria: trusted execution, visible warnings, evidence export

## Core Message

**LangSmith helps teams trace what happened. Signet helps teams prove what happened.**

## Sources

- OpenAI Workspace Agents: <https://openai.com/index/introducing-workspace-agents-in-chatgpt/>
- OpenAI enterprise help: <https://help.openai.com/en/articles/20001143-chatgpt-workspace-agents-for-enterprise-and-business>
- Cloudflare MCP rollout: <https://blog.cloudflare.com/internal-ai-engineering-stack/>
- Cloudflare enterprise MCP architecture: <https://blog.cloudflare.com/enterprise-mcp/>
- Atlassian Rovo + MCP: <https://www.atlassian.com/blog/announcements/rovo-mcp-gallery>
- Notion Custom Agents: <https://www.notion.com/blog/introducing-custom-agents>
- Datadog MCP Server: <https://www.datadoghq.com/about/latest-news/press-releases/datadog-launches-mcp-server/>
