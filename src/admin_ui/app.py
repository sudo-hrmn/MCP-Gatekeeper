"""Sleek Admin Dashboard UI for MCP Trust Gateway."""
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from src.database.connection import get_db
from src.database.models import (
    UpstreamServer, ToolBaseline, PolicyRule, HumanConfirmation, Incident, AuditLog
)

ui_router = APIRouter(tags=["Admin UI"])

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCP Trust Gateway — Control Center</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #090d16;
            --card-bg: #111827;
            --card-border: #1f293d;
            --accent: #3b82f6;
            --accent-glow: rgba(59, 130, 246, 0.25);
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg);
            color: var(--text-main);
            line-height: 1.5;
            padding: 24px;
        }
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--card-border);
            margin-bottom: 24px;
        }
        .logo { font-size: 1.4rem; font-weight: 700; background: linear-gradient(135deg, #60a5fa, #a78bfa); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 20px; margin-bottom: 24px; }
        .card {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
        }
        .card h2 { font-size: 1.1rem; font-weight: 600; margin-bottom: 16px; display: flex; align-items: center; justify-content: space-between; }
        .badge { font-size: 0.75rem; padding: 4px 8px; border-radius: 20px; font-weight: 600; }
        .badge-danger { background: rgba(239, 68, 68, 0.2); color: var(--danger); border: 1px solid var(--danger); }
        .badge-warning { background: rgba(245, 158, 11, 0.2); color: var(--warning); border: 1px solid var(--warning); }
        .badge-success { background: rgba(16, 185, 129, 0.2); color: var(--success); border: 1px solid var(--success); }
        table { width: 100%; border-collapse: collapse; margin-top: 8px; }
        th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--card-border); font-size: 0.875rem; }
        th { color: var(--text-muted); font-weight: 500; }
        code { font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; background: rgba(255,255,255,0.05); padding: 2px 6px; border-radius: 4px; }
        button {
            background: var(--accent);
            color: #fff;
            border: none;
            padding: 8px 14px;
            border-radius: 6px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        button:hover { background: #2563eb; box-shadow: 0 0 12px var(--accent-glow); }
        .hash-code { max-width: 140px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    </style>
</head>
<body>
    <header>
        <div class="logo">🛡️ MCP Trust Gateway</div>
        <div>
            <span class="badge badge-success">LLM Classifier Active</span>
            <span class="badge badge-success">Fail-Closed Mode</span>
        </div>
    </header>

    <div class="grid">
        <div class="card">
            <h2>Upstream Servers <span class="badge badge-success">{{ servers|length }} Active</span></h2>
            <table>
                <thead><tr><th>ID</th><th>Name</th><th>Upstream URL</th></tr></thead>
                <tbody>
                    {% for s in servers %}
                    <tr>
                        <td><code>{{ s.id }}</code></td>
                        <td>{{ s.name }}</td>
                        <td><code>{{ s.upstream_url }}</code></td>
                    </tr>
                    {% else %}
                    <tr><td colspan="3" style="color:var(--text-muted)">No upstream servers registered yet.</td></tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>Pending Human Approvals <span class="badge badge-warning">{{ confirmations|length }} Pending</span></h2>
            <table>
                <thead><tr><th>ID</th><th>Tool</th><th>Requested At</th></tr></thead>
                <tbody>
                    {% for c in confirmations %}
                    <tr>
                        <td><code>{{ c.id[:8] }}...</code></td>
                        <td><code>{{ c.tool_name }}</code></td>
                        <td>{{ c.requested_at.strftime('%H:%M:%S') if c.requested_at else '-' }}</td>
                    </tr>
                    {% else %}
                    <tr><td colspan="3" style="color:var(--text-muted)">No pending confirmations.</td></tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>

    <div class="grid">
        <div class="card" style="grid-column: span 2;">
            <h2>Recent Security Incidents <span class="badge badge-danger">{{ incidents|length }} Flagged</span></h2>
            <table>
                <thead><tr><th>Severity</th><th>Type</th><th>Details</th><th>Timestamp</th></tr></thead>
                <tbody>
                    {% for i in incidents %}
                    <tr>
                        <td><span class="badge badge-{{ 'danger' if i.severity=='high' else 'warning' }}">{{ i.severity }}</span></td>
                        <td><code>{{ i.detection_type }}</code></td>
                        <td>{{ i.details.get('message') or i.details.get('reason') or i.details }}</td>
                        <td>{{ i.created_at.strftime('%Y-%m-%d %H:%M:%S') if i.created_at else '-' }}</td>
                    </tr>
                    {% else %}
                    <tr><td colspan="4" style="color:var(--text-muted)">No incidents detected. System is clean.</td></tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>

    <div class="card">
        <h2>Tamper-Evident Audit Log (SHA-256 Hash Chained)</h2>
        <table>
            <thead><tr><th>Timestamp</th><th>Actor</th><th>Action</th><th>Target</th><th>Hash Chain</th></tr></thead>
            <tbody>
                {% for a in audit_log %}
                <tr>
                    <td>{{ a.created_at.strftime('%H:%M:%S') if a.created_at else '-' }}</td>
                    <td><code>{{ a.actor }}</code></td>
                    <td><strong>{{ a.action }}</strong></td>
                    <td><code>{{ a.target }}</code></td>
                    <td><code class="hash-code" title="{{ a.current_hash }}">{{ a.current_hash }}</code></td>
                </tr>
                {% else %}
                <tr><td colspan="5" style="color:var(--text-muted)">Audit log is clean.</td></tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
</body>
</html>
"""

@ui_router.get("/dashboard", response_class=HTMLResponse)
async def render_dashboard(request: Request, db: AsyncSession = Depends(get_db)):
    from jinja2 import Template
    
    servers_res = await db.execute(select(UpstreamServer))
    servers = servers_res.scalars().all()
    
    conf_res = await db.execute(select(HumanConfirmation).where(HumanConfirmation.status == "pending"))
    confirmations = conf_res.scalars().all()
    
    inc_res = await db.execute(select(Incident).order_by(desc(Incident.created_at)).limit(20))
    incidents = inc_res.scalars().all()
    
    audit_res = await db.execute(select(AuditLog).order_by(desc(AuditLog.created_at)).limit(30))
    audit_log = audit_res.scalars().all()
    
    template = Template(HTML_TEMPLATE)
    return template.render(
        servers=servers,
        confirmations=confirmations,
        incidents=incidents,
        audit_log=audit_log
    )
