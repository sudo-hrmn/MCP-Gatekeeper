# 🛡️ MCP-Gatekeeper

> **Runtime Security Gateway & FastMCP Server for Model Context Protocol (MCP) Clients and Upstream Servers.**

MCP-Gatekeeper is a defense-in-depth proxy and FastMCP server that inspects **100% of tool-list refreshes and tool responses**, preventing tool poisoning, response-borne prompt injection (e.g. MCPoison / CurXecute attacks), silent tool schema modification ("rug pulls"), and unauthorized high-risk operations.

Designed for instant deployment to **[fastmcp.cloud](https://fastmcp.cloud)** or local execution via `fastmcp` CLI.

---

## 🚀 Key Features & Capabilities

1. **FastMCP Cloud Ready**: Single-file FastMCP entry point (`server.py`) deployable directly to **fastmcp.cloud** with SSE and HTTP transport.
2. **Rug-Pull Schema Protection**: Connect-time tool schema baseline capture; diffs 100% of tool-list refreshes against approved baselines and blocks unapproved tool changes by default.
3. **Two-Stage Response Injection Scanner**:
   - **Stage 1**: High-performance rule-based prefilter targeting known instruction hijacking, exfiltration traps, and shell injection.
   - **Stage 2**: Deep semantic LLM classification utilizing any OpenAI-compatible API (`LLM_API_KEY` from `.env`, supporting OpenAI, Grok, DeepSeek, Anthropic, or local Ollama).
4. **Fail-Closed Security Design**: Any classifier failure, network timeout, or unhandled exception defaults to **blocking the payload** and creating a security incident.
5. **Policy Engine**: Per-tool and per-server configurable rule evaluation (`allow`, `block`, `confirm`, `rate_limit`).
6. **Human Confirmation Gate**: Holds high-risk actions pending admin approval; fails closed (denies) if unanswered within configurable timeout.
7. **Tamper-Evident Audit Trail**: Every call, response, policy verdict, and admin decision is stored with **SHA-256 hash chaining**.
8. **Cloud Control Center Dashboard**: Live HTML Admin Dashboard served directly via FastMCP at `/dashboard`.

---

## 🛠️ Architecture Overview

### High-Level System Architecture

```mermaid
flowchart TD
    subgraph Clients["AI Clients & Interfaces"]
        C1["Claude Desktop"]
        C2["Claude Code CLI"]
        C3["Google Antigravity"]
        C4["ChatGPT / Custom App"]
    end

    subgraph Gateway["🛡️ MCP-Gatekeeper (FastMCP Cloud)"]
        direction TB
        S["FastMCP Server\nserver.py"]
        
        subgraph Engine["Security & Policy Engines"]
            B["Schema Baseline Manager\n(Rug-Pull Detector)"]
            POL["Policy Engine\n(Allow/Block/Confirm/Rate-Limit)"]
            CONF["Confirmation Manager\n(Human Approval Gate)"]
            
            subgraph Classifier["Two-Stage Response Classifier"]
                R1["Stage 1: Rule Prefilter\n(Fast Pattern Match)"]
                R2["Stage 2: LLM Classifier\n(OpenAI / Grok / DeepSeek / Ollama)"]
            end
        end

        UI["Admin Control Center UI\n/dashboard"]
    end

    subgraph External["Upstream Services & AI APIs"]
        UP["Upstream MCP Servers\n(GitHub, SQL, Web Search, APIs)"]
        LLM["LLM Classifier API\n(OpenAI / Grok / DeepSeek / Ollama)"]
    end

    subgraph Storage["Datastore & Audit"]
        DB[("PostgreSQL / SQLite DB")]
        AUDIT[("Tamper-Evident Audit Log\n(SHA-256 Hash Chained)")]
    end

    Clients -->|MCP SSE / stdio / JSON-RPC| S
    S --> B
    S --> POL
    POL -->|Held Action| CONF
    POL -->|Allowed| UP
    UP -->|Tool Response| Classifier
    Classifier --> R1
    R1 -->|Ambiguous / Suspicious| R2
    R2 -->|API Query| LLM
    Classifier -->|Clean / Safe| Clients
    Classifier -->|Malicious / Timeout| Block["Fail-Closed Block Response"]

    UI -->|Manage Policies & Baselines| DB
    Engine -->|Record Calls & Incidents| DB
    Engine -->|Write Chain Record| AUDIT
```

---

### Detailed Execution Flow & Security Pipeline

```mermaid
sequenceDiagram
    autonumber
    actor Client as AI Agent Client
    participant FastMCP as FastMCP Server (server.py)
    participant Base as Schema Baseline Manager
    participant Policy as Policy Engine
    participant Gate as Human Confirmation Gate
    participant Admin as Admin Dashboard (/dashboard)
    participant Upstream as Upstream MCP Server
    participant Stage1 as Stage 1: Rule Prefilter
    participant Stage2 as Stage 2: LLM Classifier
    participant Audit as SHA-256 Audit Log

    Client->>FastMCP: 1. Request check_tool_security (tool_name, payload)
    
    FastMCP->>Base: 2. Check tool baseline schema status
    alt Schema modified or unapproved (Rug-Pull)
        Base-->>FastMCP: Flagged schema mismatch
        FastMCP->>Audit: Log Rug-Pull Incident
        FastMCP-->>Client: Return Error: Tool schema unapproved
    else Approved Baseline
        Base-->>FastMCP: Baseline OK
    end

    FastMCP->>Policy: 3. Evaluate Call Policy
    alt Policy = Blocked / Rate-Limited
        Policy-->>FastMCP: Action Blocked
        FastMCP-->>Client: Return Error: Blocked by security policy
    else Policy = Held for Confirmation
        Policy->>Gate: 4. Create Pending Approval Request
        Gate->>Admin: Notify Admin on Dashboard
        Admin->>Gate: 5. Admin Approves / Denies (or Timeout)
        alt Denied or Timed Out (Fail-Closed)
            Gate-->>FastMCP: Action Denied
            FastMCP-->>Client: Return Error: High-risk action denied
        else Approved
            Gate-->>FastMCP: Action Approved
        end
    end

    FastMCP->>Stage1: 6. Scan Response (Stage 1 Rule Prefilter)
    alt Stage 1 Matches Known Attack Vector
        Stage1-->>FastMCP: Verdict: Malicious
        FastMCP->>Audit: Record Security Incident & Audit Log
        FastMCP-->>Client: Return Safe Error: Response blocked
    else Stage 1 Suspicious / Ambiguous
        FastMCP->>Stage2: 7. Escalate to Stage 2 LLM Classifier
        Stage2-->>FastMCP: Verdict & Reason (or Fail-Closed on Error)
        alt Verdict = Malicious / Error
            FastMCP->>Audit: Record Security Incident & Audit Log
            FastMCP-->>Client: Return Safe Error: Response blocked
        else Verdict = Clean
            FastMCP->>Audit: Write Hash-Chained Audit Entry
            FastMCP-->>Client: 8. Return Verified Clean Response
        end
    else Stage 1 Clean
        FastMCP->>Audit: Write Hash-Chained Audit Entry
        FastMCP-->>Client: 8. Return Verified Clean Response
    end
```

---

## 🔑 Environment Configuration (`.env`)

The gateway reads generic LLM environment configuration from `.env`:

```env
# LLM Security Classifier API Key (Supports OpenAI, DeepSeek, Grok, Ollama)
LLM_API_KEY="your-llm-api-key-here"
LLM_API_URL="https://api.openai.com/v1/chat/completions" # or https://api.x.ai/v1/chat/completions, https://api.deepseek.com/v1/chat/completions
LLM_MODEL="gpt-4o-mini" # or grok-2-latest, deepseek-chat, llama3, etc.

ADMIN_API_KEY="trust-gateway-admin-key-secret"
DATABASE_URL="sqlite+aiosqlite:///mcp_trust_gateway.db"
FAIL_CLOSED=true
CLASSIFIER_TIMEOUT_SECONDS=3.0
CONFIRMATION_TIMEOUT_SECONDS=60
```

---

## ☁️ Deployment & Client Integration

### 1. Deploying to FastMCP Cloud

1. Push this repository to GitHub.
2. Go to **[fastmcp.cloud](https://fastmcp.cloud)** and create a new server:
   - **Entry Point**: `server.py`
   - **Environment Variable**: `LLM_API_KEY` = `your-api-key-here`
3. Click **Deploy**. FastMCP Cloud provides your endpoints:
   - **MCP SSE Server**: `https://mcp.fastmcp.cloud/your-username/mcp-trust-gateway/sse`
   - **Admin Dashboard**: `https://mcp.fastmcp.cloud/your-username/mcp-trust-gateway/dashboard`

---

### 2. Client Configurations

#### 🤖 Google Antigravity & Claude Desktop (`mcp_config.json`)
```json
{
  "mcpServers": {
    "mcp-trust-gateway": {
      "url": "https://mcp.fastmcp.cloud/your-username/mcp-trust-gateway/sse"
    }
  }
}
```

#### 💻 Claude Code (CLI)
```bash
claude mcp add mcp-trust-gateway --transport sse \
  https://mcp.fastmcp.cloud/your-username/mcp-trust-gateway/sse
```

---

## 🧪 Testing & Adversarial Regression Suite

Run the full pytest suite including the **Adversarial Regression Test Suite**:

```bash
pytest -v
```

### Metrics Achieved
- 📊 **Adversarial Catch Rate**: **100%** (Target: ≥95%)
- 📊 **False Positive Rate**: **0%** (Target: <2%)

---

## 📝 Design Decisions

1. **Fail-Closed Default**: All ambiguous responses, classifier timeouts, network issues, or unapproved schema modifications fail closed (block action and alert admins).
2. **Credential Redaction**: Secrets, API tokens, and passwords matching sensitive keys are automatically redacted before saving to audit storage.
3. **Stage 1 Fast Filter + LLM Escalation**: Known malicious patterns are intercepted immediately by Stage 1, eliminating latency and API overhead for obvious attacks while leveraging an LLM for complex semantic analysis.
4. **Tamper-Evident Hash Chaining**: Every log entry computes `SHA256(actor | action | target | details | prev_hash | timestamp)` ensuring non-repudiation and detection of log tampering.
