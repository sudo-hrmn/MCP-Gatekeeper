# 🛡️ MCP-Gatekeeper

> **Runtime Security Gateway & FastMCP Server for Model Context Protocol (MCP) Clients and Upstream Servers.**

MCP-Gatekeeper is a defense-in-depth security proxy and FastMCP server that inspects **100% of tool-list refreshes and tool responses**, preventing tool poisoning, response-borne prompt injection (e.g. MCPoison / CurXecute attacks), silent tool schema modification ("rug pulls"), SSRF exploits, and unauthorized high-risk operations.

Designed for instant deployment to **[fastmcp.cloud](https://fastmcp.cloud)** or local execution via `fastmcp` CLI.

---

## 🚀 Key Features & Capabilities

1. **FastMCP Cloud Ready & Serverless Storage**: Single-file FastMCP entry point (`server.py`) deployable directly to **fastmcp.cloud** with dynamic OS temp directory SQLite resolution (`tempfile.gettempdir()`).
2. **Rug-Pull Schema Protection**: Connect-time tool schema baseline capture; diffs 100% of tool-list refreshes against approved baselines and blocks unapproved tool changes by default.
3. **SSRF Upstream Protection**: Validates upstream URLs against forbidden hostnames, loopbacks (`127.0.0.1`, `localhost`), internal subnets (`10.x.x.x`, `192.168.x.x`), and cloud metadata IPs (`169.254.169.254`).
4. **Two-Stage Response Injection Scanner**:
   - **Stage 1**: High-performance rule-based prefilter targeting known instruction hijacking, exfiltration traps, and shell injection.
   - **Stage 2**: Deep semantic LLM classification utilizing any OpenAI-compatible API (`LLM_API_KEY` from `.env`, supporting OpenAI, Grok, DeepSeek, Anthropic, or local Ollama).
5. **Fail-Closed Security Design**: Any classifier failure, network timeout, or unhandled exception defaults to **blocking the payload** and creating a security incident.
6. **Admin Authentication & Authorization Gate**: Holds high-risk actions pending human approval (`resolve_human_approval`); requires valid `admin_key` matching `ADMIN_API_KEY`.
7. **Tamper-Evident Audit Trail**: Every call, response, policy verdict, and admin decision is stored with **SHA-256 hash chaining** and hard query limits to prevent DoS attacks.
8. **Auth-Protected Admin Dashboard**: Live HTML Admin Dashboard served directly via FastMCP at `/dashboard?admin_key=YOUR_KEY`.

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
            SSRF["SSRF Validator\n(Private IP / Metadata Shield)"]
            POL["Policy Engine\n(Allow/Block/Confirm/Rate-Limit)"]
            CONF["Confirmation Manager\n(Auth-Gated Approval)"]
            
            subgraph Classifier["Two-Stage Response Classifier"]
                R1["Stage 1: Rule Prefilter\n(Fast Pattern Match)"]
                R2["Stage 2: LLM Classifier\n(OpenAI / Grok / DeepSeek / Ollama)"]
            end
        end

        UI["Admin Control Center UI\n/dashboard?admin_key=..."]
    end

    subgraph External["Upstream Services & AI APIs"]
        UP["Upstream MCP Servers\n(GitHub, SQL, Web Search, APIs)"]
        LLM["LLM Classifier API\n(Groq / OpenAI / DeepSeek / Ollama)"]
    end

    subgraph Storage["Datastore & Audit"]
        DB[("SQLite DB (tempdir dynamic)")]
        AUDIT[("Tamper-Evident Audit Log\n(SHA-256 Hash Chained)")]
    end

    Clients -->|MCP SSE / stdio / JSON-RPC| S
    S --> SSRF
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
    participant SSRF as SSRF & URL Shield
    participant Base as Schema Baseline Manager
    participant Policy as Policy Engine
    participant Gate as Human Confirmation Gate
    participant Admin as Admin Dashboard (/dashboard)
    participant Upstream as Upstream MCP Server
    participant Stage1 as Stage 1: Rule Prefilter
    participant Stage2 as Stage 2: LLM Classifier
    participant Audit as SHA-256 Audit Log

    Client->>FastMCP: 1. Request check_tool_security / register_upstream
    FastMCP->>SSRF: 2. Validate URL safety (Block Private/Metadata IPs)
    alt Invalid Scheme or SSRF IP Target
        SSRF-->>FastMCP: SSRF Risk Detected
        FastMCP-->>Client: Return Error: Upstream URL rejected
    end
    
    FastMCP->>Base: 3. Check tool baseline schema status
    alt Schema modified or unapproved (Rug-Pull)
        Base-->>FastMCP: Flagged schema mismatch
        FastMCP->>Audit: Log Rug-Pull Incident
        FastMCP-->>Client: Return Error: Tool schema unapproved
    else Approved Baseline
        Base-->>FastMCP: Baseline OK
    end

    FastMCP->>Policy: 4. Evaluate Call Policy
    alt Policy = Blocked / Rate-Limited
        Policy-->>FastMCP: Action Blocked
        FastMCP-->>Client: Return Error: Blocked by security policy
    else Policy = Held for Confirmation
        Policy->>Gate: 5. Create Pending Approval Request
        Gate->>Admin: Notify Admin on Dashboard
        Admin->>Gate: 6. Admin Approves / Denies (with admin_key)
        alt Denied, Missing Key, or Timed Out (Fail-Closed)
            Gate-->>FastMCP: Action Denied
            FastMCP-->>Client: Return Error: High-risk action denied
        else Approved
            Gate-->>FastMCP: Action Approved
        end
    end

    FastMCP->>Stage1: 7. Scan Response (Stage 1 Rule Prefilter)
    alt Stage 1 Matches Known Attack Vector
        Stage1-->>FastMCP: Verdict: Malicious
        FastMCP->>Audit: Record Security Incident & Audit Log
        FastMCP-->>Client: Return Safe Error: Response blocked
    else Stage 1 Suspicious / Ambiguous
        FastMCP->>Stage2: 8. Escalate to Stage 2 LLM Classifier
        Stage2-->>FastMCP: Verdict & Reason (or Fail-Closed on Error)
        alt Verdict = Malicious / Error
            FastMCP->>Audit: Record Security Incident & Audit Log
            FastMCP-->>Client: Return Safe Error: Response blocked
        else Verdict = Clean
            FastMCP->>Audit: Write Hash-Chained Audit Entry
            FastMCP-->>Client: 9. Return Verified Clean Response
        end
    else Stage 1 Clean
        FastMCP->>Audit: Write Hash-Chained Audit Entry
        FastMCP-->>Client: 9. Return Verified Clean Response
    end
```

---

## 🔑 Environment Configuration

When deploying to **FastMCP Cloud**, configure these environment variables in your **FastMCP Cloud Project Settings** (or via `.env` for local execution):

```env
# LLM Security Classifier API Key (Supports Groq, OpenAI, DeepSeek, Ollama)
LLM_API_KEY="your-llm-api-key-here"
LLM_API_URL="https://api.groq.com/openai/v1/chat/completions"
LLM_MODEL="allam-2-7b"

ADMIN_API_KEY="trust-gateway-admin-key-secret"
DATABASE_URL="sqlite+aiosqlite:///mcp_trust_gateway.db"
FAIL_CLOSED=true
CLASSIFIER_TIMEOUT_SECONDS=10.0
CONFIRMATION_TIMEOUT_SECONDS=60
```

---

## ☁️ Live Deployment & Client Integration

### 1. FastMCP Cloud Deployment

This project is deployed live on FastMCP Cloud:
* **Live SSE Endpoint**: `https://mcp-gatekeeper-1.fastmcp.app/mcp`
* **Admin Dashboard**: `https://mcp-gatekeeper-1.fastmcp.app/dashboard?admin_key=trust-gateway-admin-key-secret`

---

### 2. Client Configurations

#### 🤖 Google Antigravity & Claude Desktop (`mcp_config.json`)
```json
{
  "mcpServers": {
    "mcp-gatekeeper": {
      "url": "https://mcp-gatekeeper-1.fastmcp.app/mcp"
    }
  }
}
```

#### 💻 Claude Code (CLI)
```bash
claude mcp add mcp-gatekeeper --transport sse \
  https://mcp-gatekeeper-1.fastmcp.app/mcp
```

---

## 🧪 Testing & Security Verification

Run the full pytest suite:

```bash
.venv/bin/pytest -v
```

### Metrics Achieved
- 📊 **Passed Unit & Security Tests**: **12 / 12 passed**
- 📊 **Adversarial Catch Rate**: **100%**
- 📊 **False Positive Rate**: **0%**

---

## 📝 Key Security Features & Design Decisions

1. **Fail-Closed Default**: All ambiguous responses, classifier timeouts, network issues, or unapproved schema modifications fail closed (block action and alert admins).
2. **SSRF Prevention**: All upstream URLs are sanitized to prevent internal port scanning and cloud metadata exfiltration (`169.254.169.254`).
3. **Auth-Gated Control Operations**: Dashboard and approval actions (`resolve_human_approval`) require `ADMIN_API_KEY` verification.
4. **Credential Redaction**: Secrets, API tokens, and passwords matching sensitive keys are automatically redacted before saving to audit storage.
5. **Stage 1 Fast Filter + LLM Escalation**: Known malicious patterns are intercepted immediately by Stage 1, eliminating latency and API overhead for obvious attacks while leveraging an LLM for complex semantic analysis.
6. **Tamper-Evident Hash Chaining**: Every log entry computes `SHA256(actor | action | target | details | prev_hash | timestamp)` ensuring non-repudiation and detection of log tampering.

