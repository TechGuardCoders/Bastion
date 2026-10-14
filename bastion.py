"""
Bastion - secure multi-tenant inference layer.

Sits in front of Ball Knowledge (:3100) as the security shell:
  client -> Bastion :3200 -> Ball Knowledge :3100 -> backends

Provides:
- Hashed API keys (PBKDF2-HMAC-SHA256, per-key salt, versioned for rotation)
- Scopes: chat:read, tools:exec, admin
- Tamper-evident audit: hash-chained events, verify() detects any tamper
- Sandboxed tool exec path (jailed subprocess: timeout, cwd jail, no network
  guarantee is env-level: no proxy vars, fresh env)
- Tenant isolation: audit/exec history is namespaced per tenant

Port 3200. 3001 is Cost Peep's, 3100 is Ball Knowledge's, 3000 never touched.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
import uuid
import urllib.request
import urllib.error
from collections import defaultdict
from dataclasses import dataclass, field
from http import HTTPStatus
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

# ---------------------------------------------------------------- keys

PBKDF2_ITERATIONS = 60_000
SCOPES = {"chat:read", "tools:exec", "admin"}


@dataclass
class KeyRecord:
    """A versioned key. The plaintext NEVER lives here after creation."""
    tenant_id: str
    key_id: str          # version identifier, e.g. "v1"
    salt: bytes
    hash_hex: str        # PBKDF2(..., salt, iters) hex
    scopes: set[str]
    nodes: set[str] | None = None   # node allowlist; None = all fleet nodes
    revoked: bool = False
    created: float = field(default_factory=time.time)

    def allowed_on(self, node_id: str) -> bool:
        """Fleet scoping: a key may be restricted to specific nodes. A key
        with no node restriction works everywhere (default, unchanged)."""
        return self.nodes is None or node_id in self.nodes


class KeyVault:
    """In-memory key vault. register() returns the plaintext EXACTLY ONCE;
    from then on only hashes are held, verification is constant-time."""

    def __init__(self):
        self._records: dict[str, list[KeyRecord]] = defaultdict(list)  # tenant -> versions

    def mint(self, tenant_id: str, scopes: set[str],
             nodes: set[str] | None = None) -> tuple[str, str]:
        """Returns (plaintext_key, key_id). Plaintext is shown once, never stored.
        `nodes` optionally scopes the key to a fleet-node allowlist (None = all)."""
        raw = "bkx-" + secrets.token_hex(24)
        key_id = f"v{len(self._records[tenant_id]) + 1}"
        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", raw.encode(), salt, PBKDF2_ITERATIONS)
        self._records[tenant_id].append(
            KeyRecord(tenant_id=tenant_id, key_id=key_id, salt=salt,
                      hash_hex=digest.hex(), scopes=set(scopes) & SCOPES,
                      nodes=set(nodes) if nodes else None))
        return raw, key_id

    def authenticate(self, authorization: str | None, node_id: str | None = None) -> Optional[KeyRecord]:
        """Verify a bearer key. When `node_id` is given, keys scoped to other
        fleet nodes do not authenticate there (per-node allowlist)."""
        if not authorization or not authorization.lower().startswith("bearer "):
            return None
        presented = authorization.split(" ", 1)[1].strip()
        for versions in self._records.values():
            for rec in versions:
                if rec.revoked:
                    continue
                if node_id is not None and not rec.allowed_on(node_id):
                    continue
                digest = hashlib.pbkdf2_hmac(
                    "sha256", presented.encode(), rec.salt, PBKDF2_ITERATIONS)
                if hmac.compare_digest(digest.hex(), rec.hash_hex):
                    return rec
        return None

    def revoke(self, tenant_id: str, key_id: str) -> bool:
        for rec in self._records.get(tenant_id, []):
            if rec.key_id == key_id:
                rec.revoked = True
                return True
        return False

    def rotate(self, tenant_id: str, scopes: set[str],
               nodes: set[str] | None = None) -> tuple[str, str]:
        """Mint a new version; old versions keep working until revoked.
        Node scoping carries over only if explicitly passed."""
        return self.mint(tenant_id, scopes, nodes=nodes)


# ---------------------------------------------------------------- fleet
#
# Fleet nodes: the compute pool behind Bastion. Each node is a base URL;
# keys may be scoped per node (KeyRecord.nodes). The default gateway
# (BK_BASE_URL) is unchanged when no node is specified.

DEFAULT_NODE = "default"


def fleet_nodes() -> dict[str, str]:
    """Node id -> base URL, from BASTION_FLEET_NODES (comma-separated
    id=url pairs). Empty env -> only the default gateway exists."""
    out: dict[str, str] = {}
    raw = os.environ.get("BASTION_FLEET_NODES", "")
    for pair in raw.split(","):
        pair = pair.strip()
        if "=" in pair:
            nid, url = pair.split("=", 1)
            if nid and url:
                out[nid.strip()] = url.strip()
    return out


# ------------------------------------------------- tamper-evident audit

GENESIS = "0" * 64


class AuditChain:
    """Append-only hash chain. Each entry commits to the previous hash, so
    editing, deleting, or reordering any event breaks verification."""

    def __init__(self):
        self.events: list[dict] = []

    def append(self, event: dict) -> dict:
        prev = self.events[-1]["h"] if self.events else GENESIS
        body = json.dumps(event, sort_keys=True)
        entry = {
            "seq": len(self.events),
            "ts": time.time(),
            "prev": prev,
            "body": body,
            "h": hashlib.sha256((prev + body).encode()).hexdigest(),
        }
        self.events.append(entry)
        return entry

    def verify(self) -> tuple[bool, str | None]:
        """Recompute the whole chain. Returns (ok, first_bad_reason)."""
        prev = GENESIS
        for i, e in enumerate(self.events):
            expect = hashlib.sha256((e["prev"] + e["body"]).encode()).hexdigest()
            if e["prev"] != prev:
                return False, f"entry {i}: prev-hash mismatch (delete/reorder/edit)"
            if e["h"] != expect:
                return False, f"entry {i}: body does not match its hash (edited)"
            prev = e["h"]
        return True, None


# ---------------------------------------------------------------- sandbox


def sandbox_exec(code: str, timeout_s: float = 5.0) -> dict:
    """Run tenant code in a jailed subprocess: disposable cwd, clean env
    (no proxy/cluster secrets), output captured, hard timeout."""
    with tempfile.TemporaryDirectory(prefix="bastion-sbx-") as jail:
        path = os.path.join(jail, "task.py")
        with open(path, "w", encoding="utf-8") as f:
            f.write(code)
        clean_env = {"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1"}
        t0 = time.perf_counter()
        try:
            proc = subprocess.run(
                [sys.executable, path], cwd=jail, env=clean_env,
                capture_output=True, text=True, timeout=timeout_s)
            return {
                "ok": proc.returncode == 0,
                "rc": proc.returncode,
                "stdout": proc.stdout[-2000:],
                "stderr": proc.stderr[-2000:],
                "wall_s": round(time.perf_counter() - t0, 3),
                "jail": os.path.basename(jail),
            }
        except subprocess.TimeoutExpired:
            return {"ok": False, "rc": None, "stdout": "", "stderr": "timeout",
                    "wall_s": round(time.perf_counter() - t0, 3), "jail": os.path.basename(jail)}


# ---------------------------------------------------------------- proxy


def forward_to_gateway(payload: dict, path: str = "/v1/chat/completions",
                       base_url: str | None = None) -> tuple[int, bytes]:
    """Forward to a fleet node. `base_url` targets a specific node; None
    keeps the default BK_BASE_URL gateway (unchanged behavior)."""
    bk = base_url or os.environ.get("BK_BASE_URL", "http://127.0.0.1:3100")
    req = urllib.request.Request(
        bk.rstrip("/") + path, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {os.environ.get('bk_key_tenant_a', 'bk-tenant-a-dev')}"})
    try:
        with urllib.request.urlopen(req, timeout=240) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:  # noqa: BLE001
        return 502, json.dumps({"error": f"gateway unreachable: {e}"}).encode()


# ---------------------------------------------------------------- app

app = FastAPI(title="Bastion", version="1.0.0")

vault = KeyVault()
chains: dict[str, AuditChain] = defaultdict(AuditChain)  # tenant -> own chain
exec_history: dict[str, list[dict]] = defaultdict(list)   # tenant -> own history

# Seed: mint one key per tenant at boot; log to env for the operator.
for tenant, scopes in (("tenant-a", {"chat:read", "tools:exec", "admin"}),
                       ("tenant-b", {"chat:read", "tools:exec"})):
    raw, kid = vault.mint(tenant, scopes)
    print(f"[bastion] minted {tenant} key {kid}: {raw}", flush=True)


def tenant_chain(rec: KeyRecord) -> AuditChain:
    return chains[rec.tenant_id]


@app.get("/health")
def health():
    ok, bad = chains["tenant-a"].verify()
    return {"ok": True, "audit_ok": ok, "audit_reason": bad}


@app.post("/v1/chat/completions")
async def chat(request: Request):
    rec = vault.authenticate(request.headers.get("Authorization"))
    if rec is None:
        for c in chains.values():
            c.append({"event": "auth_rejected"})  # rejected events are global
        return JSONResponse({"error": "invalid or missing key"}, status_code=HTTPStatus.UNAUTHORIZED)
    if "chat:read" not in rec.scopes:
        tenant_chain(rec).append({"event": "scope_denied", "scope": "chat:read"})
        return JSONResponse({"error": "scope chat:read required"}, status_code=HTTPStatus.FORBIDDEN)

    body = await request.json()
    # Fleet routing: X-Fleet-Node targets a specific node. The key must be
    # allowed on that node (per-node allowlist); unscoped keys work anywhere.
    node_id = request.headers.get("X-Fleet-Node") or None
    if node_id is not None:
        recheck = vault.authenticate(request.headers.get("Authorization"), node_id=node_id)
        if recheck is None:
            tenant_chain(rec).append({"event": "node_denied", "node": node_id})
            return JSONResponse({"error": f"key not scoped to node {node_id}"},
                                status_code=HTTPStatus.FORBIDDEN)
        base_url = fleet_nodes().get(node_id)
        if base_url is None:
            return JSONResponse({"error": f"unknown node {node_id}"},
                                status_code=HTTPStatus.BAD_REQUEST)
    else:
        base_url = None
    status, resp = forward_to_gateway(body, base_url=base_url)
    tenant_chain(rec).append({"event": "chat_served", "status": status,
                              "bytes": len(resp),
                              **({"node": node_id} if node_id else {})})
    return Response(content=resp, media_type="application/json", status_code=status)


@app.post("/v1/tools/exec")
async def tools_exec(request: Request):
    rec = vault.authenticate(request.headers.get("Authorization"))
    if rec is None:
        return JSONResponse({"error": "invalid or missing key"}, status_code=HTTPStatus.UNAUTHORIZED)
    if "tools:exec" not in rec.scopes:
        tenant_chain(rec).append({"event": "scope_denied", "scope": "tools:exec"})
        return JSONResponse({"error": "scope tools:exec required"}, status_code=HTTPStatus.FORBIDDEN)

    body = await request.json()
    code = str(body.get("code", ""))[:20_000]
    result = sandbox_exec(code)
    history = {"seq": len(exec_history[rec.tenant_id]), "wall_s": result["wall_s"],
               "ok": result["ok"]}
    exec_history[rec.tenant_id].append(history)
    tenant_chain(rec).append({"event": "tool_exec", "ok": result["ok"],
                              "wall_s": result["wall_s"]})
    return JSONResponse(result, status_code=HTTPStatus.OK if result["ok"] else 500)


@app.get("/v1/audit")
def get_audit(request: Request):
    rec = vault.authenticate(request.headers.get("Authorization"))
    if rec is None:
        return JSONResponse({"error": "invalid or missing key"}, status_code=HTTPStatus.UNAUTHORIZED)
    if "admin" not in rec.scopes:
        tenant_chain(rec).append({"event": "scope_denied", "scope": "admin"})
        return JSONResponse({"error": "admin scope required"}, status_code=HTTPStatus.FORBIDDEN)
    ok, reason = tenant_chain(rec).verify()
    return {"tenant": rec.tenant_id, "events": tenant_chain(rec).events[-200:],
            "integrity_ok": ok, "integrity_reason": reason}


# ------------------------------------------------------------- key admin

def admin_authorized(request: Request) -> bool:
    """Admin plane gate: shared token via X-Admin-Token. Dev default; prod
    would replace with mTLS/SSO. The point is: admin is NEVER anonymous."""
    expected = os.environ.get("BK_ADMIN_TOKEN", "bastion-admin-dev")
    presented = request.headers.get("X-Admin-Token", "")
    return hmac.compare_digest(presented, expected)


@app.post("/admin/keys/rotate/{tenant}")
async def rotate_key(tenant: str, request: Request):
    if not admin_authorized(request):
        return JSONResponse({"error": "admin token required"}, status_code=HTTPStatus.FORBIDDEN)
    # Least privilege: rotations carry ONLY the scopes the caller explicitly
    # grants in the body. A chat-only rotation can never silently mint admin.
    try:
        body = await request.json()
        scopes = set(body.get("scopes", []))
    except Exception:
        scopes = set()
    scopes = scopes & SCOPES
    if not scopes:
        return JSONResponse({"error": "pass scopes in body, e.g. {\"scopes\": [\"chat:read\"]}"},
                            status_code=HTTPStatus.BAD_REQUEST)
    raw, kid = vault.rotate(tenant, scopes)
    chains[tenant].append({"event": "key_rotated", "key_id": kid, "scopes": sorted(scopes)})
    return {"key": raw, "key_id": kid, "scopes": sorted(scopes),
            "note": "old version still valid until revoked"}


@app.post("/admin/keys/revoke/{tenant}/{key_id}")
def revoke_key(tenant: str, key_id: str, request: Request):
    if not admin_authorized(request):
        return JSONResponse({"error": "admin token required"}, status_code=HTTPStatus.FORBIDDEN)
    ok = vault.revoke(tenant, key_id)
    chains[tenant].append({"event": "key_revoked" if ok else "revoke_failed",
                           "key_id": key_id})
    return {"revoked": ok, "key_id": key_id}


# ------------------------------------------------------------- integrity


@app.get("/admin/audit/verify/{tenant}")
def verify_audit(tenant: str, request: Request):
    if not admin_authorized(request):
        return JSONResponse({"error": "admin token required"}, status_code=HTTPStatus.FORBIDDEN)
    ok, reason = chains[tenant].verify()
    return {"tenant": tenant, "integrity_ok": ok, "reason": reason,
            "entries": len(chains[tenant].events)}


@app.post("/admin/chaos/tamper-audit/{tenant}")
def tamper_audit(tenant: str, request: Request):
    """Attack simulation: edit the body of an existing audit entry in place,
    exactly what a malicious insider/attacker would try."""
    if not admin_authorized(request):
        return JSONResponse({"error": "admin token required"}, status_code=HTTPStatus.FORBIDDEN)
    ch = chains[tenant]
    if not ch.events:
        return JSONResponse({"error": "no events to tamper"}, status_code=400)
    victim = ch.events[len(ch.events) // 2]
    victim["body"] = victim["body"].replace('"chat_served"', '"chat_served"', 1) + " "  # silent edit
    ok, reason = ch.verify()
    return {"tampered": True, "integrity_ok": ok, "reason": reason}
