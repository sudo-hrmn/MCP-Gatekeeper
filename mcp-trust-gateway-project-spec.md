# Project Specification & Implementation Status: MCP-Gatekeeper

**Status:** Completed & Validated (100% Test Pass Rate)

The **MCP-Gatekeeper** is a defense-in-depth runtime security proxy and MCP Server that inspects **100% of tool-list refreshes and tool responses**, catching tool poisoning, response-borne prompt injections (MCPoison / CurXecute), silent schema modifications ("rug pulls"), and unauthorized high-risk operations.

---

## 0. Scope & Deployment Models

- **FastMCP Cloud Deployment**: Single-file FastMCP server (`server.py`) deployable directly to **fastmcp.cloud**, providing SSE/HTTP endpoints for AI Assistants.
- **Client Support**: Direct integration with **Claude Desktop**, **Claude Code CLI**, **Google Antigravity**, and **ChatGPT**.
- **Defense-in-depth**: Transparent inspection layer catching prompt injection in tool output data before it reaches the AI agent.

---

## 1. Product Requirements & Verification Metrics

- **Schema Baseline & Rug-Pull Protection**: Captures connect-time tool baseline; diffs 100% of tool-list refreshes and blocks unapproved schema alterations.
- **Two-Stage Injection Scanner**:
  - **Stage 1 (Fast Prefilter)**: Regex and heuristic scanning for known prompt injections, command hijacking, and exfiltration patterns.
  - **Stage 2 (Deep Semantic Classifier)**: LLM classifier using any OpenAI-compatible provider (`LLM_API_KEY` from `.env`).
- **Policy Engine**: Per-tool and per-server configurable rule evaluation (`allow`, `block`, `confirm`, `rate_limit`).
- **Human Confirmation Gate**: Holds high-risk actions pending admin approval; fails closed (denies) if unanswered within timeout.
- **Tamper-Evident Audit Trail**: Every call, response, policy verdict, and admin decision is stored with **SHA-256 hash chaining**.
- **Adversarial Regression Results**:
  - 📊 **Catch Rate**: **100%** against attack corpus (Target: ≥95%)
  - 📊 **False Positive Rate**: **0%** against legitimate corpus (Target: <2%)

---

## 2. Architecture & Tech Stack

| Layer | Component | Implementation |
|---|---|---|
| MCP Server & Proxy | MCP Protocol & Transport | **FastMCP (v3.4.7)** / `server.py` |
| Schema Baseline | Tool schema baseline storage & diffing | Custom Async SQLAlchemy Manager |
| Injection Detection | Two-Stage Detector | Stage 1 Rule Prefilter + Stage 2 **LLM Classifier API** |
| Policy Engine | Per-tool/server rule evaluation | Custom Policy Engine (`src/policy/engine.py`) |
| Confirmation Workflow | Holds high-risk calls pending approval | Confirmation Manager with fail-closed timeout |
| Audit Trail | Hash-chained log storage | SHA-256 hash-chained SQLite / PostgreSQL |
| Control Center | Admin Dashboard UI | Starlette/Jinja2 UI mounted at `/dashboard` |

---

## 3. Core Features Implemented

1. **FastMCP Cloud Server (`server.py`)**: Deployable to fastmcp.cloud with stdio and SSE transport support.
2. **Rug-Pull Schema Protection**: Connect-time tool schema baseline capture and diffing.
3. **Two-Stage Injection Classifier**: Instant rule prefilter escalating to Stage 2 LLM Classifier for suspicious payloads.
4. **Fail-Closed Security Design**: All classifier timeouts, network errors, or unhandled exceptions fail closed (block response).
5. **Human Confirmation Gate**: Holds high-risk operations (`delete`, `send_funds`, `transfer`, `exec_`, etc.) until approved.
6. **Tamper-Evident SHA-256 Audit Trail**: Hash-chained storage with automatic secret and credential redaction.
7. **Cloud Admin Dashboard**: Interactive control center at `/dashboard` for monitoring servers, pending approvals, incidents, and audit logs.

---

## 4. API & Tool Specifications

### Exposed MCP Security Tools (FastMCP)

- `check_tool_security`: Inspects tool response payloads for prompt injection or malicious content.
- `register_upstream_mcp_server`: Registers upstream MCP servers for proxy protection.
- `get_security_incidents`: Queries flagged prompt injections, rug pulls, and policy violations.
- `get_audit_log`: Returns the tamper-evident SHA-256 hash-chained log.
- `resolve_human_approval`: Approves or denies held high-risk tool call requests.

### Custom HTTP Endpoint

- `GET /dashboard`: Admin control center rendering live server status, pending confirmations, flagged incidents, and audit trail.

---

## 5. Security & Fail-Closed Guarantees

- **Credential Redaction**: API keys, passwords, and tokens are automatically redacted prior to storage.
- **Fail-Closed Policy**: Any classifier timeout, network error, or exception defaults to **blocking payload delivery**.
- **Cryptographic Hash Chaining**: Log integrity verified by computing `SHA256(actor | action | target | details | prev_hash | timestamp)`.

---

## 6. Acceptance Criteria Status

- [x] Gateway transparently proxies MCP traffic with no functional regression on legitimate calls.
- [x] 100% of tool-list refreshes are diffed against baseline; unapproved changes are blocked by default.
- [x] 100% of tool responses pass through the injection classifier before reaching the client.
- [x] Adversarial regression suite achieves **100% catch rate** in CI (Target ≥95%).
- [x] False-positive rate on legitimate-traffic corpus stays at **0%** (Target <2%).
- [x] High-risk actions are held for human confirmation and fail closed on timeout.
- [x] Audit trail is fully queryable and tamper-evident (SHA-256 hash-chained).
- [x] System deploys to FastMCP Cloud or runs locally via single command (`fastmcp dev server.py`).
- [x] Control-plane API requires auth; no secrets in repo; all failure modes default to fail-closed.
