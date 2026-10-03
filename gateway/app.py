from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from .store import Store
from .tokens import TokenError, issue_token, sha256_hex, verify_token


STATE_PATH = Path(os.environ.get("GATEWAY_STATE", "data/state.json"))
TOKEN_SECRET = os.environ.get("GATEWAY_TOKEN_SECRET", "dev-change-me")
ADMIN_KEY = os.environ.get("GATEWAY_ADMIN_KEY", "dev-admin-key")
RISK_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def risk_allowed(risk: str, tolerance: str) -> bool:
    return RISK_ORDER[risk] <= RISK_ORDER[tolerance]


class AgentUpsert(BaseModel):
    id: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=200)
    api_key: str | None = Field(default=None, min_length=16)
    active: bool = True
    allowed_actions: list[str] = Field(default_factory=list)
    allowed_data_policies: list[str] = Field(default_factory=list)


class ActionPolicy(BaseModel):
    id: str = Field(min_length=1, max_length=120)
    description: str = ""
    service: str = Field(min_length=1, max_length=120)
    operation: str = Field(min_length=1, max_length=120)
    ttl_seconds: int = Field(default=60, ge=5, le=3600)
    required_fields: list[str] = Field(default_factory=list)
    max_amount: float | None = Field(default=None, gt=0)
    allowed_roles: list[str] = Field(default_factory=list)
    base_risk: Literal["low", "medium", "high", "critical"] = "medium"
    risk_rules: list[dict[str, Any]] = Field(default_factory=list)


class DataPolicy(BaseModel):
    id: str = Field(min_length=1, max_length=120)
    description: str = ""
    tables: list[str] = Field(default_factory=list)
    columns: dict[str, list[str]] = Field(default_factory=dict)
    row_filters: dict[str, Any] = Field(default_factory=dict)
    ttl_seconds: int = Field(default=300, ge=5, le=86400)


class GatewayRequest(BaseModel):
    action: str
    params: dict[str, Any] = Field(default_factory=dict)
    data_policy: str | None = None
    subject: dict[str, Any] = Field(default_factory=dict)
    reason: str = ""


class GatewayBatchRequest(BaseModel):
    actions: list[GatewayRequest] = Field(min_length=1, max_length=50)


class SettingsUpdate(BaseModel):
    risk_tolerance: Literal["low", "medium", "high", "critical"]


class SystemRiskUpdate(BaseModel):
    service: str = Field(min_length=1, max_length=120)
    risk_tolerance: Literal["low", "medium", "high", "critical"] | None = None


class BlockRule(BaseModel):
    id: str = Field(min_length=1, max_length=120)
    enabled: bool = True
    action: str | None = None
    service: str | None = None
    operation: str | None = None
    min_amount: float | None = Field(default=None, gt=0)
    min_records: int | None = Field(default=None, ge=1)
    reason: str = "blocked by admin"


class IntrospectionRequest(BaseModel):
    token: str
    token_type: Literal["action", "data_access"] | None = None


class RevokeRequest(BaseModel):
    token: str | None = None
    jti: str | None = None
    reason: str = ""


ADMIN_UI_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Gateway Admin</title>
  <style>
    :root { color-scheme: light; font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", "SF Pro Text", Inter, system-ui, sans-serif; }
    * { -webkit-font-smoothing: antialiased; }
    body { margin: 0; min-height: 100vh; background: radial-gradient(circle at 12% 0%, #ffffff 0, #f7f8fb 28%, #eef2f7 100%); color: #121417; }
    body:before { content: ""; position: fixed; inset: 0; pointer-events: none; background: linear-gradient(120deg, rgba(255,255,255,.8), rgba(255,255,255,0)); }
    main { position: relative; max-width: 1160px; margin: 0 auto; padding: 44px 22px 64px; }
    h1 { margin: 0 0 8px; font-size: clamp(38px, 5vw, 60px); letter-spacing: -0.058em; line-height: .95; font-weight: 760; }
    h2 { margin: 0 0 18px; font-size: 19px; letter-spacing: -0.02em; font-weight: 680; }
    p { color: #667085; line-height: 1.55; }
    .eyebrow { color: #7b8494; font-size: 13px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; margin-bottom: 12px; }
    .lede { max-width: 690px; font-size: 17px; margin: 0 0 24px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 18px; }
    .card { background: rgba(255,255,255,.74); border: 1px solid rgba(198,207,222,.68); border-radius: 28px; padding: 22px; box-shadow: 0 28px 70px rgba(36,49,79,.09), inset 0 1px 0 rgba(255,255,255,.92); backdrop-filter: blur(22px) saturate(1.25); }
    label { display: block; color: #687386; font-size: 12px; font-weight: 650; margin: 14px 0 7px; letter-spacing: .01em; }
    input, select, textarea { width: 100%; box-sizing: border-box; border: 1px solid #d8dee9; background: rgba(255,255,255,.86); color: #111827; border-radius: 14px; padding: 11px 13px; outline: none; box-shadow: inset 0 1px 2px rgba(15,23,42,.04); transition: border-color .15s, box-shadow .15s, background .15s; }
    input:focus, select:focus, textarea:focus { border-color: #007aff; box-shadow: 0 0 0 4px rgba(0,122,255,.14); background: #fff; }
    textarea { min-height: 78px; resize: vertical; }
    button { border: 0; background: #0071e3; color: white; border-radius: 999px; padding: 10px 16px; font-weight: 680; cursor: pointer; margin-top: 14px; box-shadow: 0 10px 24px rgba(0,113,227,.23); transition: transform .15s, box-shadow .15s, background .15s; }
    button:hover { transform: translateY(-1px); box-shadow: 0 14px 28px rgba(0,122,255,.28); }
    button.secondary { background: #eef2f7; color: #1f2937; box-shadow: none; }
    button.danger { background: #ff3b30; color: white; box-shadow: 0 10px 24px rgba(255,59,48,.18); }
    code, pre { background: rgba(244,246,250,.9); color: #1f2937; border: 1px solid #e1e6ef; border-radius: 16px; }
    code { padding: 2px 6px; }
    pre { padding: 15px; overflow: auto; min-height: 70px; }
    table { width: 100%; border-collapse: collapse; font-size: 14px; }
    th, td { border-bottom: 1px solid #e7ebf2; padding: 12px 8px; text-align: left; vertical-align: top; }
    th { color: #687386; font-weight: 680; }
    .row { display: flex; gap: 12px; align-items: end; }
    .row > * { flex: 1; }
    .pill { display: inline-block; padding: 5px 11px; border-radius: 999px; background: #eef2f7; color: #637083; font-size: 12px; font-weight: 680; margin-left: 8px; }
    .ok { color: #168a3a; background: #e9f8ee; }
    .bad { color: #c92a20; background: #fff0ee; }
    @media (max-width: 720px) { main { padding-top: 28px; } .row { display: block; } .card { border-radius: 22px; } }
  </style>
</head>
<body>
<main>
  <div class="eyebrow">Policy control</div>
  <h1>Gateway Admin</h1>
  <p class="lede">Review authorization policy, tune risk tolerance, and block risky requests before agents reach downstream systems. Changes apply immediately to newly issued tokens and validation checks.</p>

  <section class="card">
    <h2>Access</h2>
    <label>Admin key</label>
    <input id="adminKey" type="password" value="dev-admin-key" autocomplete="off">
    <button onclick="loadAll()">Refresh</button>
    <span id="status" class="pill">idle</span>
  </section>

  <div class="grid" style="margin-top:16px">
    <section class="card">
      <h2>Global Risk Level</h2>
      <label>Global tolerance</label>
      <select id="globalRisk">
        <option>low</option><option>medium</option><option>high</option><option>critical</option>
      </select>
      <button onclick="saveGlobalRisk()">Save global setting</button>
      <p>Requests above this level are denied. Previously issued tokens are also rejected during validation if the current tolerance no longer allows them.</p>
    </section>

    <section class="card">
      <h2>Risk Per System</h2>
      <div class="row">
        <div><label>System/service</label><input id="systemName" placeholder="mini-bank"></div>
        <div><label>Tolerance</label><select id="systemRisk"><option>low</option><option>medium</option><option>high</option><option>critical</option></select></div>
      </div>
      <button onclick="saveSystemRisk()">Save system override</button>
      <button class="secondary" onclick="clearSystemRisk()">Clear override</button>
      <pre id="systemRiskOut">{}</pre>
    </section>
  </div>

  <div class="grid" style="margin-top:16px">
    <section class="card">
      <h2>Block Rule</h2>
      <label>Rule ID</label><input id="blockId" placeholder="block-large-delete">
      <label>Action</label><input id="blockAction" placeholder="records.delete">
      <label>Service</label><input id="blockService" placeholder="mini-bank">
      <label>Operation</label><input id="blockOperation" placeholder="delete.records">
      <div class="row">
        <div><label>Min amount</label><input id="blockMinAmount" type="number" step="0.01"></div>
        <div><label>Min records</label><input id="blockMinRecords" type="number"></div>
      </div>
      <label>Reason</label><input id="blockReason" placeholder="large delete disabled">
      <button onclick="saveBlock()">Save block rule</button>
    </section>

    <section class="card">
      <h2>Active Blocks</h2>
      <div id="blocks"></div>
    </section>
  </div>

  <section class="card" style="margin-top:16px">
    <h2>Actions And Systems</h2>
    <div id="actions"></div>
  </section>

  <section class="card" style="margin-top:16px">
    <h2>API Response</h2>
    <pre id="output"></pre>
  </section>
</main>

<script>
const risks = ['low', 'medium', 'high', 'critical'];
function key() { return document.getElementById('adminKey').value; }
function setStatus(text, ok=true) { const el = document.getElementById('status'); el.textContent = text; el.className = ok ? 'pill ok' : 'pill bad'; }
function show(data) { document.getElementById('output').textContent = JSON.stringify(data, null, 2); }
async function api(path, options = {}) {
  const res = await fetch(path, { ...options, headers: { 'content-type': 'application/json', 'x-admin-key': key(), ...(options.headers || {}) } });
  const data = await res.json();
  show(data);
  if (!res.ok) throw new Error(data.detail || data.error || res.statusText);
  return data;
}
async function loadAll() {
  try {
    const settings = await api('/admin/settings');
    document.getElementById('globalRisk').value = settings.settings.risk_tolerance;
    document.getElementById('systemRiskOut').textContent = JSON.stringify(settings.settings.system_risk_tolerances || {}, null, 2);
    const blocks = await api('/admin/blocks');
    renderBlocks(blocks.blocks || []);
    const actions = await api('/admin/actions');
    renderActions(actions.actions || [], settings.settings.system_risk_tolerances || {});
    setStatus('loaded');
  } catch (err) { setStatus(err.message, false); }
}
async function saveGlobalRisk() {
  try { await api('/admin/settings', { method: 'PUT', body: JSON.stringify({ risk_tolerance: document.getElementById('globalRisk').value }) }); await loadAll(); }
  catch (err) { setStatus(err.message, false); }
}
async function saveSystemRisk() {
  try { await api('/admin/systems/risk', { method: 'PUT', body: JSON.stringify({ service: document.getElementById('systemName').value, risk_tolerance: document.getElementById('systemRisk').value }) }); await loadAll(); }
  catch (err) { setStatus(err.message, false); }
}
async function clearSystemRisk() {
  try { await api('/admin/systems/risk', { method: 'PUT', body: JSON.stringify({ service: document.getElementById('systemName').value, risk_tolerance: null }) }); await loadAll(); }
  catch (err) { setStatus(err.message, false); }
}
async function saveBlock() {
  const body = {
    id: document.getElementById('blockId').value,
    action: document.getElementById('blockAction').value || null,
    service: document.getElementById('blockService').value || null,
    operation: document.getElementById('blockOperation').value || null,
    min_amount: document.getElementById('blockMinAmount').value ? Number(document.getElementById('blockMinAmount').value) : null,
    min_records: document.getElementById('blockMinRecords').value ? Number(document.getElementById('blockMinRecords').value) : null,
    reason: document.getElementById('blockReason').value || 'blocked by admin'
  };
  try { await api('/admin/blocks', { method: 'POST', body: JSON.stringify(body) }); await loadAll(); }
  catch (err) { setStatus(err.message, false); }
}
async function deleteBlock(id) {
  try { await api('/admin/blocks/' + encodeURIComponent(id), { method: 'DELETE' }); await loadAll(); }
  catch (err) { setStatus(err.message, false); }
}
function renderBlocks(blocks) {
  if (!blocks.length) { document.getElementById('blocks').innerHTML = '<p>No active block rules.</p>'; return; }
  document.getElementById('blocks').innerHTML = '<table><tr><th>ID</th><th>Scope</th><th>Reason</th><th></th></tr>' + blocks.map(b => `<tr><td>${b.id}</td><td>action=${b.action || '*'}<br>service=${b.service || '*'}<br>operation=${b.operation || '*'}<br>min_amount=${b.min_amount || '-'} min_records=${b.min_records || '-'}</td><td>${b.reason || ''}</td><td><button class="danger" onclick="deleteBlock('${b.id}')">Delete</button></td></tr>`).join('') + '</table>';
}
function renderActions(actions, systemRisks) {
  if (!actions.length) { document.getElementById('actions').innerHTML = '<p>No actions configured yet. Run <code>make bootstrap</code> to load sample policies.</p>'; return; }
  document.getElementById('actions').innerHTML = '<table><tr><th>Action</th><th>System</th><th>Operation</th><th>Base risk</th><th>System tolerance</th></tr>' + actions.map(a => `<tr><td>${a.id}</td><td>${a.service}</td><td>${a.operation}</td><td>${a.base_risk}</td><td>${systemRisks[a.service] || '(global)'}</td></tr>`).join('') + '</table>';
}
loadAll();
</script>
</body>
</html>
"""


DEMO_UI_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Gateway Live Demo</title>
  <style>
    :root { color-scheme: light; font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", "SF Pro Text", Inter, system-ui, sans-serif; }
    * { box-sizing: border-box; -webkit-font-smoothing: antialiased; }
    body { margin: 0; min-height: 100vh; background: #f5f5f7; color: #1d1d1f; }
    main { max-width: 980px; margin: 0 auto; padding: 42px 20px 64px; }
    .top { display: flex; justify-content: space-between; gap: 18px; align-items: end; margin-bottom: 24px; }
    h1 { margin: 0; font-size: clamp(36px, 5vw, 56px); line-height: .96; letter-spacing: -.055em; }
    p { color: #6e6e73; line-height: 1.5; }
    .card { background: rgba(255,255,255,.78); border: 1px solid rgba(210,210,215,.7); border-radius: 28px; box-shadow: 0 22px 55px rgba(0,0,0,.08); backdrop-filter: blur(20px); }
    .chat { padding: 22px; min-height: 410px; }
    .bubble { max-width: 76%; padding: 13px 15px; border-radius: 20px; margin: 12px 0; line-height: 1.42; white-space: pre-wrap; }
    .human { margin-left: auto; background: #0071e3; color: white; border-bottom-right-radius: 6px; }
    .agent { background: #fff; color: #1d1d1f; border: 1px solid #e5e5ea; border-bottom-left-radius: 6px; }
    .gateway { background: #f2f4f7; border: 1px solid #e0e5ee; color: #344054; }
    .deny { background: #fff1f0; border-color: #ffd3ce; color: #b42318; }
    .allow { background: #ecfdf3; border-color: #bbf7d0; color: #067647; }
    .controls { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 12px; padding: 16px; border-top: 1px solid #ececf0; }
    button { border: 0; border-radius: 999px; padding: 11px 15px; font-weight: 700; cursor: pointer; background: #0071e3; color: white; }
    button.secondary { background: #e8ebf0; color: #1d1d1f; }
    button.danger { background: #ff3b30; color: white; }
    button:disabled { opacity: .45; cursor: not-allowed; }
    code { background: #f2f4f7; border: 1px solid #e3e8ef; border-radius: 8px; padding: 1px 5px; }
    pre { margin: 12px 0 0; padding: 12px; overflow: auto; background: #0b1020; color: #d8e4f8; border-radius: 16px; font-size: 12px; }
    .meta { font-size: 13px; color: #86868b; }
  </style>
</head>
<body>
<main>
  <div class="top">
    <div>
      <p class="meta">Live presentation</p>
      <h1>Agent request,<br>gateway decision.</h1>
      <p>The agent asks for permission to create a user. First it is blocked by policy. Then the admin allows it and the same agent gets a token.</p>
    </div>
  </div>
  <section class="card">
    <div id="chat" class="chat"></div>
    <div class="controls">
      <button class="danger" onclick="prepareDenied()">1. Set policy to deny</button>
      <button onclick="agentAttempt()">2. Agent asks gateway</button>
      <button class="secondary" onclick="allowAction()">3. Admin allows it</button>
      <button onclick="agentAttempt()">4. Agent retries</button>
      <button class="secondary" onclick="resetChat()">Reset chat</button>
    </div>
  </section>
</main>
<script>
const adminKey = 'dev-admin-key';
const agentHeaders = { 'content-type': 'application/json', 'x-agent-id': 'agent-demo', 'x-agent-key': 'demo-agent-key-please-change' };
const task = { action: 'user.create', params: { email: 'presentation.user@example.com', name: 'Presentation User', initial_balance: '25.00' }, subject: { role: 'admin' }, reason: 'employee asked the agent to create a customer user' };
function chat() { return document.getElementById('chat'); }
function add(kind, text, data) {
  const div = document.createElement('div');
  div.className = 'bubble ' + kind;
  div.textContent = text;
  if (data) { const pre = document.createElement('pre'); pre.textContent = JSON.stringify(data, null, 2); div.appendChild(pre); }
  chat().appendChild(div); chat().scrollTop = chat().scrollHeight;
}
async function admin(path, options = {}) {
  const res = await fetch(path, { ...options, headers: { 'content-type': 'application/json', 'x-admin-key': adminKey, ...(options.headers || {}) } });
  const data = await res.json();
  if (!res.ok) throw new Error(JSON.stringify(data));
  return data;
}
async function prepareDenied() {
  await admin('/admin/blocks', { method: 'POST', body: JSON.stringify({ id: 'presentation-block-user-create', action: 'user.create', reason: 'Admin approval required for user creation demo' }) });
  add('gateway deny', 'Policy prepared: user.create is currently blocked.');
}
async function allowAction() {
  await admin('/admin/blocks/presentation-block-user-create', { method: 'DELETE' });
  add('gateway allow', 'Admin allowed user.create by removing the block rule.');
}
async function agentAttempt() {
  add('human', 'Employee: Create a new bank user for Presentation User.');
  add('agent', 'Agent: I built an action plan: user.create. Asking Gateway for a token...');
  const res = await fetch('/v1/authorize', { method: 'POST', headers: agentHeaders, body: JSON.stringify(task) });
  const data = await res.json();
  if (!res.ok) {
    add('gateway deny', 'Gateway: denied. No token issued.', data);
    add('agent', 'Agent: I cannot call mini-bank without an action token.');
    return;
  }
  add('gateway allow', 'Gateway: allowed. Token issued for user.create.', { decision: data.decision, action: data.action, risk_level: data.risk_level, token_preview: data.action_token.slice(0, 44) + '...' });
  add('agent', 'Agent: I can now call mini-bank with Authorization: GatewayAction <token>.');
}
function resetChat() { chat().innerHTML = ''; add('gateway', 'Ready. Start with “Set policy to deny”, then let the agent ask for a token.'); }
resetChat();
</script>
</body>
</html>
"""


def create_app(store: Store | None = None) -> FastAPI:
    app = FastAPI(title="Agent Gateway", version="0.1.0")
    app.state.store = store or Store(STATE_PATH)

    def current_store() -> Store:
        return app.state.store

    def require_admin(request: Request) -> None:
        if not secrets.compare_digest(request.headers.get("x-admin-key", ""), ADMIN_KEY):
            raise HTTPException(status_code=401, detail="admin key required")

    def require_agent(request: Request) -> dict[str, Any]:
        agent_id = request.headers.get("x-agent-id", "")
        api_key = request.headers.get("x-agent-key", "")
        agent = current_store().get("agents", agent_id)
        if not agent or not agent.get("active") or not secrets.compare_digest(api_key, agent.get("api_key", "")):
            raise HTTPException(status_code=401, detail="agent authentication failed")
        return agent

    def revoked(jti: str) -> bool:
        return jti in current_store().state["revoked_tokens"]

    def risk_tolerance() -> str:
        value = current_store().state.get("settings", {}).get("risk_tolerance", "high")
        return value if value in RISK_ORDER else "high"

    def effective_risk_tolerance(service: str | None = None) -> str:
        global_tolerance = risk_tolerance()
        if not service:
            return global_tolerance
        system_tolerances = current_store().state.get("settings", {}).get("system_risk_tolerances", {})
        system_tolerance = system_tolerances.get(service)
        if system_tolerance not in RISK_ORDER:
            return global_tolerance
        return global_tolerance if RISK_ORDER[global_tolerance] <= RISK_ORDER[system_tolerance] else system_tolerance

    def blocked_reason(action_id: str, action: dict[str, Any], params: dict[str, Any]) -> str | None:
        amount = params.get("amount")
        records = params.get("records") or params.get("record_count") or params.get("limit")
        for rule in current_store().list("blocks"):
            if not rule.get("enabled", True):
                continue
            if rule.get("action") and rule["action"] != action_id:
                continue
            if rule.get("service") and rule["service"] != action.get("service"):
                continue
            if rule.get("operation") and rule["operation"] != action.get("operation"):
                continue
            if rule.get("min_amount") is not None and (not isinstance(amount, (int, float)) or amount < rule["min_amount"]):
                continue
            if rule.get("min_records") is not None and (not isinstance(records, int) or records < rule["min_records"]):
                continue
            return rule.get("reason") or "blocked by admin"
        return None

    def assess_risk(action: dict[str, Any], params: dict[str, Any]) -> str:
        risk = action.get("base_risk", "medium")
        for rule in action.get("risk_rules", []):
            field = rule.get("field")
            if not isinstance(field, str):
                continue
            value = params.get(field)
            if rule.get("gte") is not None and isinstance(value, (int, float)) and value >= rule["gte"]:
                candidate = rule.get("risk", risk)
                if candidate in RISK_ORDER and RISK_ORDER[candidate] > RISK_ORDER[risk]:
                    risk = candidate
            if rule.get("equals") is not None and value == rule["equals"]:
                candidate = rule.get("risk", risk)
                if candidate in RISK_ORDER and RISK_ORDER[candidate] > RISK_ORDER[risk]:
                    risk = candidate
        operation = action.get("operation", "")
        records = params.get("records") or params.get("record_count") or params.get("limit")
        if isinstance(operation, str) and operation.startswith("delete") and isinstance(records, int) and records >= 100:
            risk = "high" if RISK_ORDER[risk] < RISK_ORDER["high"] else risk
        if isinstance(operation, str) and operation.startswith(("select", "list", "read")) and isinstance(records, int) and records <= 10:
            risk = "low" if RISK_ORDER[risk] <= RISK_ORDER["low"] else risk
        return risk

    def ensure_token_still_allowed(claims: dict[str, Any]) -> None:
        token_risk = claims.get("risk_level")
        tolerance = effective_risk_tolerance(claims.get("service") if isinstance(claims.get("service"), str) else None)
        if isinstance(token_risk, str) and token_risk in RISK_ORDER and not risk_allowed(token_risk, tolerance):
            raise HTTPException(status_code=401, detail="token revoked by current risk tolerance")

    def authorize_one(body: GatewayRequest, agent: dict[str, Any], *, raise_on_deny: bool) -> dict[str, Any]:
        store = current_store()
        action = store.get("actions", body.action)

        def deny(reason: str, status_code: int = 403, extra: dict[str, Any] | None = None) -> dict[str, Any]:
            event = {"decision": "deny", "agent_id": agent["id"], "action": body.action, "reason": reason, **(extra or {})}
            store.audit(event)
            if raise_on_deny:
                raise HTTPException(status_code=status_code, detail=event)
            return event

        if action is None:
            return deny("unknown action")
        if body.action not in agent.get("allowed_actions", []):
            return deny("action not allowed for agent")
        missing = [field for field in action.get("required_fields", []) if field not in body.params]
        if missing:
            return deny("missing required fields", status_code=400, extra={"missing_fields": missing})
        amount = body.params.get("amount")
        if action.get("max_amount") is not None and isinstance(amount, (int, float)) and amount > action["max_amount"]:
            return deny("amount limit exceeded")
        roles = set(action.get("allowed_roles", []))
        subject_role = body.subject.get("role")
        if roles and subject_role not in roles:
            return deny("subject role not allowed")
        block = blocked_reason(body.action, action, body.params)
        if block:
            return deny(block, extra={"blocked": True})

        risk_level = assess_risk(action, body.params)
        tolerance = effective_risk_tolerance(action.get("service"))
        if not risk_allowed(risk_level, tolerance):
            return deny("risk level exceeds gateway tolerance", extra={"risk_level": risk_level, "risk_tolerance": tolerance})

        action_claims = {
            "agent_id": agent["id"],
            "action": body.action,
            "service": action["service"],
            "operation": action["operation"],
            "params_hash": sha256_hex(body.params),
            "subject": body.subject,
            "risk_level": risk_level,
        }
        action_token = issue_token(TOKEN_SECRET, "action", action_claims, action["ttl_seconds"])
        response: dict[str, Any] = {"decision": "allow", "action": body.action, "risk_level": risk_level, "action_token": action_token, "expires_in": action["ttl_seconds"]}

        if body.data_policy:
            policy = store.get("data_policies", body.data_policy)
            if policy is None or body.data_policy not in agent.get("allowed_data_policies", []):
                return deny("data policy not allowed")
            data_claims = {
                "agent_id": agent["id"],
                "service": action["service"],
                "policy_id": policy["id"],
                "tables": policy.get("tables", []),
                "columns": policy.get("columns", {}),
                "row_filters": policy.get("row_filters", {}),
                "subject": body.subject,
                "risk_level": risk_level,
            }
            response["data_access_token"] = issue_token(TOKEN_SECRET, "data_access", data_claims, policy["ttl_seconds"])
            response["data_expires_in"] = policy["ttl_seconds"]

        store.audit({"decision": "allow", "agent_id": agent["id"], "action": body.action, "risk_level": risk_level, "data_policy": body.data_policy})
        return response

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/admin/ui", response_class=HTMLResponse)
    def admin_ui() -> str:
        return ADMIN_UI_HTML

    @app.get("/demo", response_class=HTMLResponse)
    def demo_ui() -> str:
        return DEMO_UI_HTML

    @app.post("/v1/authorize")
    def authorize(body: GatewayRequest, request: Request) -> dict[str, Any]:
        agent = require_agent(request)
        return authorize_one(body, agent, raise_on_deny=True)

    @app.post("/v1/authorize/batch")
    def authorize_batch(body: GatewayBatchRequest, request: Request) -> dict[str, Any]:
        agent = require_agent(request)
        results = [authorize_one(item, agent, raise_on_deny=False) for item in body.actions]
        allowed = sum(1 for item in results if item["decision"] == "allow")
        return {"decision": "partial_allow" if allowed != len(results) else "allow", "allowed": allowed, "denied": len(results) - allowed, "results": results}

    @app.post("/v1/introspect")
    def introspect(body: IntrospectionRequest) -> dict[str, Any]:
        expected = body.token_type
        try:
            claims = verify_token(TOKEN_SECRET, body.token, expected)
        except TokenError as exc:
            return {"active": False, "reason": str(exc)}
        if revoked(claims["jti"]):
            return {"active": False, "reason": "revoked"}
        token_risk = claims.get("risk_level")
        tolerance = effective_risk_tolerance(claims.get("service") if isinstance(claims.get("service"), str) else None)
        if isinstance(token_risk, str) and token_risk in RISK_ORDER and not risk_allowed(token_risk, tolerance):
            return {"active": False, "reason": "revoked_by_risk_tolerance", "risk_level": token_risk, "risk_tolerance": tolerance}
        return {"active": True, "claims": claims}

    @app.post("/v1/validate/action")
    def validate_action(body: IntrospectionRequest) -> dict[str, Any]:
        claims = verify_token(TOKEN_SECRET, body.token, "action")
        if revoked(claims["jti"]):
            raise HTTPException(status_code=401, detail="token revoked")
        ensure_token_still_allowed(claims)
        return {"ok": True, "claims": claims}

    @app.post("/v1/validate/data-access")
    def validate_data_access(body: IntrospectionRequest) -> dict[str, Any]:
        claims = verify_token(TOKEN_SECRET, body.token, "data_access")
        if revoked(claims["jti"]):
            raise HTTPException(status_code=401, detail="token revoked")
        ensure_token_still_allowed(claims)
        return {"ok": True, "claims": claims}

    @app.get("/admin/settings")
    def get_settings(request: Request) -> dict[str, Any]:
        require_admin(request)
        return {"settings": current_store().state["settings"]}

    @app.put("/admin/settings")
    def update_settings(body: SettingsUpdate, request: Request) -> dict[str, Any]:
        require_admin(request)
        current_store().state["settings"]["risk_tolerance"] = body.risk_tolerance
        current_store().save()
        current_store().audit({"decision": "admin_change", "op": "settings.update", "risk_tolerance": body.risk_tolerance})
        return {"settings": current_store().state["settings"]}

    @app.put("/admin/systems/risk")
    def update_system_risk(body: SystemRiskUpdate, request: Request) -> dict[str, Any]:
        require_admin(request)
        settings = current_store().state["settings"]
        settings.setdefault("system_risk_tolerances", {})
        if body.risk_tolerance is None:
            settings["system_risk_tolerances"].pop(body.service, None)
        else:
            settings["system_risk_tolerances"][body.service] = body.risk_tolerance
        current_store().save()
        current_store().audit({"decision": "admin_change", "op": "system_risk.update", "service": body.service, "risk_tolerance": body.risk_tolerance})
        return {"settings": settings}

    @app.get("/admin/agents")
    def list_agents(request: Request) -> dict[str, Any]:
        require_admin(request)
        agents = [{k: v for k, v in agent.items() if k != "api_key"} for agent in current_store().list("agents")]
        return {"agents": agents}

    @app.post("/admin/agents")
    def upsert_agent(body: AgentUpsert, request: Request) -> dict[str, Any]:
        require_admin(request)
        api_key = body.api_key or secrets.token_urlsafe(32)
        agent = {**body.model_dump(), "api_key": api_key}
        current_store().put("agents", body.id, agent)
        current_store().audit({"decision": "admin_change", "op": "agent.upsert", "agent_id": body.id})
        return {"agent": {k: v for k, v in agent.items() if k != "api_key"}, "api_key": api_key}

    @app.get("/admin/actions")
    def list_actions(request: Request) -> dict[str, Any]:
        require_admin(request)
        return {"actions": current_store().list("actions")}

    @app.post("/admin/actions")
    def upsert_action(body: ActionPolicy, request: Request) -> dict[str, Any]:
        require_admin(request)
        action = body.model_dump()
        current_store().put("actions", body.id, action)
        current_store().audit({"decision": "admin_change", "op": "action.upsert", "action": body.id})
        return {"action": action}

    @app.get("/admin/blocks")
    def list_blocks(request: Request) -> dict[str, Any]:
        require_admin(request)
        return {"blocks": current_store().list("blocks")}

    @app.post("/admin/blocks")
    def upsert_block(body: BlockRule, request: Request) -> dict[str, Any]:
        require_admin(request)
        rule = body.model_dump()
        current_store().put("blocks", body.id, rule)
        current_store().audit({"decision": "admin_change", "op": "block.upsert", "block": body.id})
        return {"block": rule}

    @app.delete("/admin/blocks/{block_id}")
    def delete_block(block_id: str, request: Request) -> dict[str, Any]:
        require_admin(request)
        deleted = current_store().delete("blocks", block_id)
        current_store().audit({"decision": "admin_change", "op": "block.delete", "block": block_id})
        return {"deleted": deleted}

    @app.get("/admin/data-policies")
    def list_data_policies(request: Request) -> dict[str, Any]:
        require_admin(request)
        return {"data_policies": current_store().list("data_policies")}

    @app.post("/admin/data-policies")
    def upsert_data_policy(body: DataPolicy, request: Request) -> dict[str, Any]:
        require_admin(request)
        policy = body.model_dump()
        current_store().put("data_policies", body.id, policy)
        current_store().audit({"decision": "admin_change", "op": "data_policy.upsert", "policy": body.id})
        return {"data_policy": policy}

    @app.post("/admin/tokens/revoke")
    def revoke_token(body: RevokeRequest, request: Request) -> dict[str, Any]:
        require_admin(request)
        jti = body.jti
        if body.token:
            try:
                jti = verify_token(TOKEN_SECRET, body.token).get("jti")
            except TokenError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not jti:
            raise HTTPException(status_code=400, detail="token or jti required")
        current_store().state["revoked_tokens"][jti] = {"reason": body.reason}
        current_store().save()
        current_store().audit({"decision": "admin_change", "op": "token.revoke", "jti": jti})
        return {"revoked": jti}

    @app.get("/admin/audit")
    def audit(request: Request, limit: int = 100) -> dict[str, Any]:
        require_admin(request)
        return {"events": current_store().state["audit"][-limit:]}

    @app.exception_handler(TokenError)
    def token_error_handler(_: Request, exc: TokenError) -> JSONResponse:
        return JSONResponse({"error": str(exc)}, status_code=401)

    return app


app = create_app()
