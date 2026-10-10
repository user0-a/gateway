from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from .crypto import JwsError, public_key_from_x, request_signing_payload, sign_jws, unb64url
from .crypto import jwk_thumbprint
from .keyring import KeyRing
from .store import Store
from .tokens import TYP, TokenError, issue_token, sha256_hex, verify_token

ENV = os.environ.get("GATEWAY_ENV", "development")
STATE_PATH = Path(os.environ.get("GATEWAY_STATE", "data/state.json"))
KEY_DIR = Path(os.environ.get("GATEWAY_KEY_DIR", "data/keys"))
ISSUER = os.environ.get("GATEWAY_ISSUER", "wwgateway-dev")
ADMIN_KEY = os.environ.get("GATEWAY_ADMIN_KEY", "dev-admin-key")
ALLOW_LEGACY_AGENT_KEYS = os.environ.get("GATEWAY_ALLOW_LEGACY_AGENT_KEYS", "1" if ENV != "production" else "0") == "1"
REQUEST_MAX_SKEW = 60          # seconds a signed request may be old
SNAPSHOT_TTL = 10              # policy snapshot validity; verifiers refresh after this
PLAN_TTL = int(os.environ.get("GATEWAY_PLAN_TTL", "3600"))
DIRECT_MAX_RISK = "medium"     # anything riskier needs an employee-approved plan
MAX_STEP_ISSUANCES = 3         # re-issue allowed (e.g. token expired); downstream executes a step once
AGENT_RATE_LIMIT = int(os.environ.get("GATEWAY_AGENT_RATE_LIMIT", "120"))  # requests / minute / agent
RISK_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
DEV_SECRETS = {"dev-admin-key", "dev-change-me", ""}


def risk_allowed(risk: str, tolerance: str) -> bool:
    return RISK_ORDER[risk] <= RISK_ORDER[tolerance]


def check_production_config() -> None:
    problems = []
    if ADMIN_KEY in DEV_SECRETS or len(ADMIN_KEY) < 32:
        problems.append("GATEWAY_ADMIN_KEY must be set to a random value of at least 32 characters")
    if ALLOW_LEGACY_AGENT_KEYS:
        problems.append("GATEWAY_ALLOW_LEGACY_AGENT_KEYS must be 0 in production")
    if ISSUER == "wwgateway-dev":
        problems.append("GATEWAY_ISSUER must identify this deployment")
    if problems:
        raise RuntimeError("Refusing to start in production: " + "; ".join(problems))


class AgentUpsert(BaseModel):
    id: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=200)
    public_key: str | None = Field(default=None, description="Ed25519 public key, base64url (JWK 'x')")
    api_key: str | None = Field(default=None, min_length=16, description="legacy, development only")
    active: bool = True
    allowed_actions: list[str] = Field(default_factory=list)
    allowed_data_policies: list[str] = Field(default_factory=list)


class EmployeeUpsert(BaseModel):
    id: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=200)
    role: str = Field(min_length=1, max_length=60)
    public_key: str = Field(description="Ed25519 public key, base64url (JWK 'x')")
    attributes: dict[str, Any] = Field(default_factory=dict, description="e.g. tenant_id used by row filters")
    active: bool = True


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
    requires_plan: bool = False


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
    plan_id: str | None = None
    step_id: str | None = None


class GatewayBatchRequest(BaseModel):
    actions: list[GatewayRequest] = Field(min_length=1, max_length=50)


class PlanStep(BaseModel):
    id: str = Field(min_length=1, max_length=120)
    action: str = Field(min_length=1, max_length=120)
    params: dict[str, Any] = Field(default_factory=dict)
    data_policy: str | None = None
    reason: str = ""


class PlanAuthorizeRequest(BaseModel):
    plan_id: str = Field(min_length=1, max_length=120)
    goal: str = Field(min_length=1, max_length=500)
    subject: dict[str, Any] = Field(default_factory=dict)
    steps: list[PlanStep] = Field(min_length=1, max_length=50)


class PlanApproval(BaseModel):
    decision: Literal["approve", "reject"]
    plan_hash: str
    comment: str = ""


class PlanExtensionRequest(BaseModel):
    step: PlanStep
    reason: str = Field(min_length=1, max_length=500)


class PlanExtensionDecision(BaseModel):
    decision: Literal["approve", "reject"]
    comment: str = ""


class EmployeePlanExtensionDecision(BaseModel):
    decision: Literal["approve", "reject"]
    comment: str = ""


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
    <input id="adminKey" type="password" value="" autocomplete="off" placeholder="admin key">
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


def create_app(store: Store | None = None, keyring: KeyRing | None = None) -> FastAPI:
    if ENV == "production":
        check_production_config()
    app = FastAPI(title="WWGateWay", version="0.2.0")
    app.state.store = store or Store(STATE_PATH)
    if keyring is None:
        key_dir = KEY_DIR if store is None else Path(store.path).parent / "keys"
        keyring = KeyRing(key_dir)
    app.state.keyring = keyring
    rate_lock = threading.Lock()
    rate_windows: dict[str, list[float]] = {}

    def current_store() -> Store:
        return app.state.store

    def keys() -> KeyRing:
        return app.state.keyring

    # ------------------------------------------------------------------ authentication
    def require_admin(request: Request) -> None:
        if not secrets.compare_digest(request.headers.get("x-admin-key", ""), ADMIN_KEY):
            raise HTTPException(status_code=401, detail="admin key required")

    def rate_limit(agent_id: str) -> None:
        now = time.time()
        with rate_lock:
            window = [t for t in rate_windows.get(agent_id, []) if now - t < 60]
            if len(window) >= AGENT_RATE_LIMIT:
                rate_windows[agent_id] = window
                raise HTTPException(status_code=429, detail="agent rate limit exceeded")
            window.append(now)
            rate_windows[agent_id] = window

    async def verify_signed_request(request: Request, prefix: str, public_key_x: str, principal_id: str) -> None:
        h = request.headers
        try:
            ts = int(h.get(f"{prefix}-timestamp", ""))
        except ValueError:
            raise HTTPException(status_code=401, detail="signed request required") from None
        nonce, signature = h.get(f"{prefix}-nonce", ""), h.get(f"{prefix}-signature", "")
        if not nonce or not signature or len(nonce) > 128:
            raise HTTPException(status_code=401, detail="signed request required")
        if abs(time.time() - ts) > REQUEST_MAX_SKEW:
            raise HTTPException(status_code=401, detail="request timestamp outside allowed window")
        path = request.url.path + (f"?{request.url.query}" if request.url.query else "")
        payload = request_signing_payload(request.method, path, ts, nonce, await request.body())
        try:
            public_key_from_x(public_key_x).verify(unb64url(signature), payload)
        except Exception:
            raise HTTPException(status_code=401, detail="invalid request signature") from None
        if not current_store().use_nonce(f"{prefix}:{principal_id}:{nonce}", REQUEST_MAX_SKEW * 2):
            raise HTTPException(status_code=401, detail="replayed request")

    async def require_agent(request: Request) -> dict[str, Any]:
        agent_id = request.headers.get("x-agent-id", "")
        agent = current_store().get("agents", agent_id)
        if not agent or not agent.get("active"):
            raise HTTPException(status_code=401, detail="agent authentication failed")
        rate_limit(agent_id)
        if agent.get("public_key"):
            await verify_signed_request(request, "x-agent", agent["public_key"], agent_id)
            return agent
        if not ALLOW_LEGACY_AGENT_KEYS:
            raise HTTPException(status_code=401, detail="signed requests required")
        presented = request.headers.get("x-agent-key", "")
        stored_hash = agent.get("api_key_hash") or (hashlib.sha256(agent["api_key"].encode()).hexdigest() if agent.get("api_key") else "")
        if not stored_hash or not secrets.compare_digest(hashlib.sha256(presented.encode()).hexdigest(), stored_hash):
            raise HTTPException(status_code=401, detail="agent authentication failed")
        return agent

    async def require_employee(request: Request) -> dict[str, Any]:
        employee_id = request.headers.get("x-employee-id", "")
        employee = current_store().get("employees", employee_id)
        if not employee or not employee.get("active"):
            raise HTTPException(status_code=401, detail="employee authentication failed")
        await verify_signed_request(request, "x-employee", employee["public_key"], employee_id)
        return employee

    # ------------------------------------------------------------------ policy helpers
    def risk_tolerance() -> str:
        value = current_store().state.get("settings", {}).get("risk_tolerance", "high")
        return value if value in RISK_ORDER else "low"

    def effective_risk_tolerance(service: str | None = None) -> str:
        global_tolerance = risk_tolerance()
        if not service:
            return global_tolerance
        system_tolerance = current_store().state.get("settings", {}).get("system_risk_tolerances", {}).get(service)
        if system_tolerance not in RISK_ORDER:
            return global_tolerance
        return global_tolerance if RISK_ORDER[global_tolerance] <= RISK_ORDER[system_tolerance] else system_tolerance

    def blocked_reason(action_id: str, action: dict[str, Any], params: dict[str, Any]) -> str | None:
        amount = _number(params.get("amount"))
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
            if rule.get("min_amount") is not None and (amount is None or amount < rule["min_amount"]):
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
            number = _number(value)
            hit = (rule.get("gte") is not None and number is not None and number >= rule["gte"]) or (rule.get("equals") is not None and value == rule["equals"])
            candidate = rule.get("risk", risk)
            if hit and candidate in RISK_ORDER and RISK_ORDER[candidate] > RISK_ORDER[risk]:
                risk = candidate
        operation = action.get("operation", "")
        records = params.get("records") or params.get("record_count") or params.get("limit")
        if isinstance(operation, str) and operation.startswith("delete") and isinstance(records, int) and records >= 100:
            risk = "high" if RISK_ORDER[risk] < RISK_ORDER["high"] else risk
        return risk

    def canonical_plan(plan_id: str, goal: str, owner: str, agent_id: str, expires_at: int, steps: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "plan_id": plan_id,
            "goal": goal,
            "owner": owner,
            "agent_id": agent_id,
            "expires_at": expires_at,
            "steps": [{"id": s["id"], "action": s["action"], "params_hash": sha256_hex(s.get("params", {})), "data_policy": s.get("data_policy")} for s in steps],
        }

    def compute_plan_hash(plan: dict[str, Any]) -> str:
        return sha256_hex(canonical_plan(plan["id"], plan["goal"], plan["owner"], plan["agent_id"], plan["expires_at"], plan["steps"]))

    def subject_employee_id(subject: dict[str, Any]) -> str | None:
        value = subject.get("employee_id") or subject.get("user_id") or subject.get("id")
        return value if isinstance(value, str) and value else None

    def resolve_row_filters(filters: dict[str, Any], employee: dict[str, Any] | None) -> dict[str, Any]:
        resolved: dict[str, Any] = {}
        attributes = {**(employee or {}).get("attributes", {}), "employee_id": (employee or {}).get("id")}
        for table, conditions in filters.items():
            resolved[table] = {}
            for column, value in (conditions or {}).items():
                if isinstance(value, str) and value.startswith("subject."):
                    attr = value.split(".", 1)[1]
                    if attributes.get(attr) is None:
                        raise ValueError(f"row filter needs subject attribute '{attr}'")
                    resolved[table][column] = attributes[attr]
                else:
                    resolved[table][column] = value
        return resolved

    def plan_state_error(plan: dict[str, Any] | None) -> str | None:
        if plan is None:
            return "unknown_plan"
        if plan.get("status") == "cancelled":
            return "plan_cancelled"
        if plan.get("status") != "approved":
            return "plan_not_approved"
        if int(time.time()) >= plan.get("expires_at", 0):
            return "plan_expired"
        return None

    # ------------------------------------------------------------------ authorization core
    def authorize_one(body: GatewayRequest, agent: dict[str, Any], *, raise_on_deny: bool, dry_run: bool = False, plan_creation: bool = False, subject_override: dict[str, Any] | None = None) -> dict[str, Any]:
        store = current_store()
        action = store.get("actions", body.action)

        def deny(reason: str, status_code: int = 403, extra: dict[str, Any] | None = None) -> dict[str, Any]:
            event = {"decision": "deny", "agent_id": agent["id"], "action": body.action, "reason": reason, **(extra or {})}
            if not dry_run:
                store.audit(event)
            if raise_on_deny:
                raise HTTPException(status_code=status_code, detail=event)
            return event

        if action is None:
            return deny("unknown action")
        if body.action not in agent.get("allowed_actions", []):
            return deny("action not allowed for agent")

        plan = None
        plan_step = None
        if body.plan_id and not plan_creation:
            plan = store.get("plans", body.plan_id)
            error = plan_state_error(plan)
            if error:
                return deny(error, extra={"plan_id": body.plan_id, "required": "new_authorization"})
            if plan.get("agent_id") != agent["id"]:
                return deny("plan_belongs_to_another_agent", extra={"plan_id": body.plan_id})
            plan_step = next((s for s in plan["steps"] if s["id"] == body.step_id), None)
            if plan_step is None:
                return deny("outside_authorized_plan", extra={"plan_id": body.plan_id, "step_id": body.step_id, "required": "request_plan_extension"})
            if plan_step["action"] != body.action or sha256_hex(plan_step.get("params", {})) != sha256_hex(body.params) or plan_step.get("data_policy") != body.data_policy:
                return deny("plan_step_mismatch", extra={"plan_id": body.plan_id, "step_id": body.step_id, "required": "new_authorization"})
            issued = plan.setdefault("issuances", {}).get(plan_step["id"], 0)
            if issued >= MAX_STEP_ISSUANCES:
                return deny("step_issuance_limit", extra={"plan_id": body.plan_id, "step_id": body.step_id})

        # The subject is never taken from the agent when a plan exists: it is the employee who signed it.
        subject = subject_override if subject_override is not None else (plan["subject"] if plan else body.subject)
        employee_id = subject_employee_id(subject)
        employee = store.get("employees", employee_id) if employee_id else None
        if employee_id and (employee is None or not employee.get("active")):
            return deny("unknown_or_inactive_employee", extra={"employee_id": employee_id})

        missing = [field for field in action.get("required_fields", []) if field not in body.params]
        if missing:
            return deny("missing required fields", status_code=400, extra={"missing_fields": missing})
        amount = _number(body.params.get("amount"))
        if action.get("max_amount") is not None and amount is not None and amount > action["max_amount"]:
            return deny("amount limit exceeded")

        roles = set(action.get("allowed_roles", []))
        if roles:
            if employee is None:
                return deny("subject_not_verified", extra={"required": "employee_approved_plan"})
            claimed_role = body.subject.get("role")
            if claimed_role is not None and claimed_role != employee.get("role") and not plan:
                return deny("subject_role_mismatch")
            if employee.get("role") not in roles:
                return deny("subject role not allowed")

        block = blocked_reason(body.action, action, body.params)
        if block:
            return deny(block, extra={"blocked": True})
        risk_level = assess_risk(action, body.params)
        tolerance = effective_risk_tolerance(action.get("service"))
        if not risk_allowed(risk_level, tolerance):
            return deny("risk level exceeds gateway tolerance", extra={"risk_level": risk_level, "risk_tolerance": tolerance})

        needs_plan = bool(action.get("requires_plan")) or bool(roles) or RISK_ORDER[risk_level] > RISK_ORDER[DIRECT_MAX_RISK]
        if needs_plan and not plan and not plan_creation:
            return deny("employee_approved_plan_required", extra={"risk_level": risk_level, "required": "plan_approval"})

        policy = None
        resolved_filters: dict[str, Any] = {}
        if body.data_policy:
            policy = store.get("data_policies", body.data_policy)
            if policy is None or body.data_policy not in agent.get("allowed_data_policies", []):
                return deny("data policy not allowed")
            try:
                resolved_filters = resolve_row_filters(policy.get("row_filters", {}), employee)
            except ValueError as exc:
                return deny("row_filter_unresolved", extra={"detail": str(exc)})

        if dry_run:
            return {"decision": "allow", "action": body.action, "risk_level": risk_level, "dry_run": True}

        cnf = {"jkt": jwk_thumbprint({"kty": "OKP", "crv": "Ed25519", "x": agent["public_key"]})} if agent.get("public_key") else None
        common = {"aud": action["service"], "sub": agent["id"], "act_for": employee_id, "risk_level": risk_level, "service": action["service"], "agent_id": agent["id"]}
        if cnf:
            common["cnf"] = cnf
        action_claims = {**common, "action": body.action, "operation": action["operation"], "params_hash": sha256_hex(body.params)}
        if plan and plan_step:
            action_claims.update({"plan_id": plan["id"], "plan_hash": plan["plan_hash"], "step_id": plan_step["id"]})
            plan["issuances"][plan_step["id"]] = plan["issuances"].get(plan_step["id"], 0) + 1
            store.put("plans", plan["id"], plan)
        ttl = min(action["ttl_seconds"], 30) if amount is not None else action["ttl_seconds"]
        action_token = issue_token(keys(), "action", action_claims, ttl, ISSUER)
        response: dict[str, Any] = {"decision": "allow", "action": body.action, "risk_level": risk_level, "action_token": action_token, "expires_in": ttl, "sender_constrained": bool(cnf)}

        if policy is not None:
            data_claims = {**common, "policy_id": policy["id"], "tables": policy.get("tables", []), "columns": policy.get("columns", {}), "row_filters": resolved_filters}
            response["data_access_token"] = issue_token(keys(), "data_access", data_claims, policy["ttl_seconds"], ISSUER)
            response["data_expires_in"] = policy["ttl_seconds"]

        store.audit({"decision": "allow", "agent_id": agent["id"], "action": body.action, "risk_level": risk_level, "data_policy": body.data_policy, "plan_id": body.plan_id, "step_id": body.step_id, "act_for": employee_id})
        return response

    def apply_extension_decision(extension_id: str, decision: str, comment: str, actor: str, actor_type: str) -> dict[str, Any]:
        store = current_store()
        extension = store.get("plan_extensions", extension_id)
        if extension is None:
            raise HTTPException(status_code=404, detail="extension not found")
        if extension.get("status") != "pending":
            raise HTTPException(status_code=409, detail=f"extension is {extension.get('status')}")
        plan = store.get("plans", extension["plan_id"])
        error = plan_state_error(plan)
        if error:
            raise HTTPException(status_code=409, detail=error)
        extension.update({"status": "approved" if decision == "approve" else "rejected", "comment": comment, "decided_by": actor, "decided_by_type": actor_type, "decided_at": int(time.time())})
        if decision == "approve":
            plan["steps"].append(extension["step"])
            plan["plan_hash"] = compute_plan_hash(plan)
            store.put("plans", plan["id"], plan)
        store.put("plan_extensions", extension_id, extension)
        store.audit({"decision": "plan_extension_" + extension["status"], "op": "plan_extension.decision", "plan_id": plan["id"], "extension_id": extension_id, "actor": actor, "actor_type": actor_type, "plan_hash": plan["plan_hash"]})
        return {"extension": extension, "plan": public_plan(plan)}

    def public_plan(plan: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in plan.items() if k != "issuances"}

    # ------------------------------------------------------------------ public endpoints
    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "env": ENV}

    @app.get("/.well-known/jwks.json")
    def jwks() -> dict[str, Any]:
        return keys().jwks()

    @app.get("/v1/policy-snapshot")
    def policy_snapshot() -> dict[str, Any]:
        store = current_store()
        now = int(time.time())
        settings = store.state["settings"]
        revoked = [jti for jti, entry in store.state["revoked_tokens"].items() if entry.get("exp", now + 1) > now - 60]
        payload = {
            "iss": ISSUER,
            "iat": now,
            "exp": now + SNAPSHOT_TTL,
            "risk_tolerance": risk_tolerance(),
            "system_risk_tolerances": settings.get("system_risk_tolerances", {}),
            "revoked_jti": sorted(revoked),
            "revoked_agents": sorted(a["id"] for a in store.list("agents") if not a.get("active")),
            "revoked_plans": sorted(p["id"] for p in store.list("plans") if p.get("status") == "cancelled"),
        }
        kid, key = keys().signing_key()
        return {"snapshot": sign_jws(key, {"kid": kid, "typ": TYP["policy"]}, payload)}

    @app.get("/admin/ui", response_class=HTMLResponse)
    def admin_ui() -> str:
        return ADMIN_UI_HTML

    @app.post("/v1/authorize")
    async def authorize(body: GatewayRequest, request: Request) -> dict[str, Any]:
        agent = await require_agent(request)
        return authorize_one(body, agent, raise_on_deny=True)

    @app.post("/v1/authorize/batch")
    async def authorize_batch(body: GatewayBatchRequest, request: Request) -> dict[str, Any]:
        agent = await require_agent(request)
        results = [authorize_one(item, agent, raise_on_deny=False) for item in body.actions]
        allowed = sum(1 for item in results if item["decision"] == "allow")
        return {"decision": "partial_allow" if allowed != len(results) else "allow", "allowed": allowed, "denied": len(results) - allowed, "results": results}

    @app.post("/v1/plans")
    @app.post("/v1/plans/authorize")
    async def create_plan(body: PlanAuthorizeRequest, request: Request) -> dict[str, Any]:
        """Agent proposes a plan. No tokens are issued until the owning employee approves it."""
        agent = await require_agent(request)
        store = current_store()
        if store.get("plans", body.plan_id):
            raise HTTPException(status_code=409, detail="plan_id already exists")
        owner = subject_employee_id(body.subject)
        employee = store.get("employees", owner) if owner else None
        if not employee or not employee.get("active"):
            raise HTTPException(status_code=400, detail="plan_requires_active_employee_owner")
        if len({s.id for s in body.steps}) != len(body.steps):
            raise HTTPException(status_code=400, detail="duplicate step ids")
        steps = [step.model_dump() for step in body.steps]
        subject = {"employee_id": owner}
        checks = [authorize_one(GatewayRequest(action=s["action"], params=s["params"], data_policy=s.get("data_policy"), subject=subject), agent, raise_on_deny=False, dry_run=True, plan_creation=True, subject_override=subject) for s in steps]
        denied = [{"step_id": s["id"], **c} for s, c in zip(steps, checks) if c["decision"] != "allow"]
        plan = {"id": body.plan_id, "goal": body.goal, "agent_id": agent["id"], "owner": owner, "subject": subject, "steps": steps,
                "expires_at": int(time.time()) + PLAN_TTL, "status": "rejected" if denied else "pending_approval", "created_at": int(time.time()), "issuances": {}}
        plan["plan_hash"] = compute_plan_hash(plan)
        store.put("plans", plan["id"], plan)
        store.audit({"decision": "plan_" + plan["status"], "agent_id": agent["id"], "plan_id": plan["id"], "plan_hash": plan["plan_hash"], "owner": owner, "steps": len(steps), "denied_steps": [d["step_id"] for d in denied]})
        if denied:
            return {"decision": "rejected", "plan_id": plan["id"], "plan_hash": plan["plan_hash"], "denied_steps": denied}
        return {"decision": "requires_approval", "plan_id": plan["id"], "plan_hash": plan["plan_hash"], "approver": owner, "expires_at": plan["expires_at"], "steps": [{"id": s["id"], "action": s["action"], "risk_level": c["risk_level"]} for s, c in zip(steps, checks)]}

    @app.post("/v1/plans/{plan_id}/approval")
    async def approve_plan(plan_id: str, body: PlanApproval, request: Request) -> dict[str, Any]:
        """The owning employee approves the exact plan hash (signed request)."""
        employee = await require_employee(request)
        store = current_store()
        plan = store.get("plans", plan_id)
        if plan is None:
            raise HTTPException(status_code=404, detail="plan not found")
        if plan["owner"] != employee["id"]:
            raise HTTPException(status_code=403, detail="only the plan owner can approve it")
        if plan["status"] != "pending_approval":
            raise HTTPException(status_code=409, detail=f"plan is {plan['status']}")
        if int(time.time()) >= plan["expires_at"]:
            raise HTTPException(status_code=409, detail="plan_expired")
        if not secrets.compare_digest(body.plan_hash, plan["plan_hash"]):
            raise HTTPException(status_code=409, detail="plan_hash_mismatch")
        plan.update({"status": "approved" if body.decision == "approve" else "rejected", "approved_by": employee["id"], "decided_at": int(time.time()), "comment": body.comment})
        store.put("plans", plan_id, plan)
        store.audit({"decision": "plan_" + plan["status"], "op": "plan.approval", "plan_id": plan_id, "plan_hash": plan["plan_hash"], "employee_id": employee["id"]})
        return {"plan": public_plan(plan)}

    @app.get("/v1/plans/{plan_id}")
    def get_plan(plan_id: str, request: Request) -> dict[str, Any]:
        require_admin(request)
        plan = current_store().get("plans", plan_id)
        if plan is None:
            raise HTTPException(status_code=404, detail="plan not found")
        return {"plan": public_plan(plan)}

    @app.post("/v1/plans/{plan_id}/extensions")
    async def request_plan_extension(plan_id: str, body: PlanExtensionRequest, request: Request) -> dict[str, Any]:
        agent = await require_agent(request)
        store = current_store()
        plan = store.get("plans", plan_id)
        error = plan_state_error(plan)
        if error:
            raise HTTPException(status_code=409, detail=error)
        if plan["agent_id"] != agent["id"]:
            raise HTTPException(status_code=403, detail="plan_belongs_to_another_agent")
        if any(s["id"] == body.step.id for s in plan["steps"]):
            raise HTTPException(status_code=409, detail="step id already in plan")
        check = authorize_one(GatewayRequest(action=body.step.action, params=body.step.params, data_policy=body.step.data_policy, subject=plan["subject"]), agent, raise_on_deny=False, dry_run=True, plan_creation=True, subject_override=plan["subject"])
        if check["decision"] != "allow":
            store.audit({"decision": "plan_extension_denied", "agent_id": agent["id"], "plan_id": plan_id, "action": body.step.action, "reason": check.get("reason")})
            raise HTTPException(status_code=403, detail=check)
        extension_id = f"ext_{secrets.token_urlsafe(10)}"
        extension = {"id": extension_id, "plan_id": plan_id, "agent_id": agent["id"], "status": "pending", "step": body.step.model_dump(), "reason": body.reason, "risk_level": check["risk_level"]}
        store.put("plan_extensions", extension_id, extension)
        store.audit({"decision": "plan_extension_requested", "agent_id": agent["id"], "plan_id": plan_id, "extension_id": extension_id, "action": body.step.action})
        return {"decision": "requires_approval", "extension_id": extension_id, "plan_id": plan_id, "requested_step": extension["step"], "approver": plan["owner"]}

    @app.post("/admin/plans/extensions/{extension_id}/decision")
    def decide_plan_extension(extension_id: str, body: PlanExtensionDecision, request: Request) -> dict[str, Any]:
        require_admin(request)
        return apply_extension_decision(extension_id, body.decision, body.comment, request.headers.get("x-admin-actor", "admin"), "admin")

    @app.post("/v1/plans/extensions/{extension_id}/employee-decision")
    async def decide_plan_extension_by_employee(extension_id: str, body: EmployeePlanExtensionDecision, request: Request) -> dict[str, Any]:
        employee = await require_employee(request)
        extension = current_store().get("plan_extensions", extension_id)
        if extension is None:
            raise HTTPException(status_code=404, detail="extension not found")
        plan = current_store().get("plans", extension["plan_id"])
        if plan is None or plan.get("owner") != employee["id"]:
            raise HTTPException(status_code=403, detail="only the requesting employee can approve this extension")
        return apply_extension_decision(extension_id, body.decision, body.comment, employee["id"], "employee")

    # ------------------------------------------------------------------ gateway-side token inspection (admin only)
    @app.post("/v1/introspect")
    def introspect(body: IntrospectionRequest, request: Request) -> dict[str, Any]:
        require_admin(request)
        try:
            claims = verify_token(keys(), body.token, body.token_type, ISSUER)
        except TokenError as exc:
            return {"active": False, "reason": str(exc)}
        if claims["jti"] in current_store().state["revoked_tokens"]:
            return {"active": False, "reason": "revoked"}
        tolerance = effective_risk_tolerance(claims.get("aud"))
        if not risk_allowed(claims.get("risk_level", "critical"), tolerance):
            return {"active": False, "reason": "revoked_by_risk_tolerance", "risk_level": claims.get("risk_level"), "risk_tolerance": tolerance}
        return {"active": True, "claims": claims}

    # ------------------------------------------------------------------ admin
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
        return {"agents": [{k: v for k, v in a.items() if k not in ("api_key", "api_key_hash")} for a in current_store().list("agents")]}

    @app.post("/admin/agents")
    def upsert_agent(body: AgentUpsert, request: Request) -> dict[str, Any]:
        require_admin(request)
        if body.public_key:
            try:
                public_key_from_x(body.public_key)
            except Exception:
                raise HTTPException(status_code=400, detail="invalid Ed25519 public key") from None
        agent = body.model_dump(exclude={"api_key"})
        response: dict[str, Any] = {}
        if not body.public_key:
            if not ALLOW_LEGACY_AGENT_KEYS:
                raise HTTPException(status_code=400, detail="public_key required (legacy API keys are disabled)")
            api_key = body.api_key or secrets.token_urlsafe(32)
            agent["api_key_hash"] = hashlib.sha256(api_key.encode()).hexdigest()
            response["api_key"] = api_key
        current_store().put("agents", body.id, agent)
        current_store().audit({"decision": "admin_change", "op": "agent.upsert", "agent_id": body.id, "key_type": "ed25519" if body.public_key else "legacy"})
        return {"agent": {k: v for k, v in agent.items() if k != "api_key_hash"}, **response}

    @app.post("/admin/agents/{agent_id}/suspend")
    def suspend_agent(agent_id: str, request: Request) -> dict[str, Any]:
        require_admin(request)
        agent = current_store().get("agents", agent_id)
        if agent is None:
            raise HTTPException(status_code=404, detail="agent not found")
        agent["active"] = False
        current_store().put("agents", agent_id, agent)
        current_store().audit({"decision": "admin_change", "op": "agent.suspend", "agent_id": agent_id})
        return {"suspended": agent_id}

    @app.get("/admin/employees")
    def list_employees(request: Request) -> dict[str, Any]:
        require_admin(request)
        return {"employees": current_store().list("employees")}

    @app.post("/admin/employees")
    def upsert_employee(body: EmployeeUpsert, request: Request) -> dict[str, Any]:
        require_admin(request)
        try:
            public_key_from_x(body.public_key)
        except Exception:
            raise HTTPException(status_code=400, detail="invalid Ed25519 public key") from None
        employee = body.model_dump()
        current_store().put("employees", body.id, employee)
        current_store().audit({"decision": "admin_change", "op": "employee.upsert", "employee_id": body.id, "role": body.role})
        return {"employee": employee}

    @app.post("/admin/plans/{plan_id}/cancel")
    def cancel_plan(plan_id: str, request: Request) -> dict[str, Any]:
        require_admin(request)
        plan = current_store().get("plans", plan_id)
        if plan is None:
            raise HTTPException(status_code=404, detail="plan not found")
        plan["status"] = "cancelled"
        current_store().put("plans", plan_id, plan)
        current_store().audit({"decision": "admin_change", "op": "plan.cancel", "plan_id": plan_id})
        return {"cancelled": plan_id}

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
        jti, exp = body.jti, None
        if body.token:
            try:
                claims = verify_token(keys(), body.token, None, ISSUER, skew=10**9)
            except TokenError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            jti, exp = claims.get("jti"), claims.get("exp")
        if not jti:
            raise HTTPException(status_code=400, detail="token or jti required")
        current_store().state["revoked_tokens"][jti] = {"reason": body.reason, "exp": exp or int(time.time()) + 86400}
        current_store().save()
        current_store().audit({"decision": "admin_change", "op": "token.revoke", "jti": jti})
        return {"revoked": jti}

    @app.get("/admin/keys")
    def list_keys(request: Request) -> dict[str, Any]:
        require_admin(request)
        return {"keys": keys().meta}

    @app.post("/admin/keys/rotate")
    def rotate_keys(request: Request) -> dict[str, Any]:
        require_admin(request)
        kid = keys().rotate()
        current_store().audit({"decision": "admin_change", "op": "keys.rotate", "kid": kid})
        return {"active_kid": kid, "keys": keys().meta}

    @app.post("/admin/keys/{kid}/retire")
    def retire_key(kid: str, request: Request) -> dict[str, Any]:
        require_admin(request)
        if not keys().retire(kid):
            raise HTTPException(status_code=409, detail="key not found or still active")
        current_store().audit({"decision": "admin_change", "op": "keys.retire", "kid": kid})
        return {"retired": kid}

    @app.get("/admin/audit")
    def audit(request: Request, limit: int = 100) -> dict[str, Any]:
        require_admin(request)
        return {"events": current_store().state["audit"][-limit:]}

    @app.get("/admin/audit/verify")
    def audit_verify(request: Request) -> dict[str, Any]:
        require_admin(request)
        return current_store().verify_audit()

    @app.get("/admin/audit/export", response_class=PlainTextResponse)
    def audit_export(request: Request, since: int = 0) -> str:
        require_admin(request)
        return "".join(json.dumps(r, sort_keys=True) + "\n" for r in current_store().state["audit"] if r.get("seq", 0) > since)

    @app.exception_handler(JwsError)
    def token_error_handler(_: Request, exc: JwsError) -> JSONResponse:
        return JSONResponse({"error": str(exc)}, status_code=401)

    return app


def _number(value: Any) -> float | None:
    """Amounts may arrive as numbers or decimal strings ("12.50"); both count for limits and risk."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


app = create_app()
