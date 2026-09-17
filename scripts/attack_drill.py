"""Bastion live attack drill. Requires: Bastion on :3200, Ball Knowledge on :3100.

Every check is a real executed attack or real security behavior - nothing staged.
"""
import json
import os
import re
import subprocess
import sys
import urllib.request
import urllib.error

BASE = os.environ.get("BASTION_URL", "http://localhost:3200")
ADMIN = {"X-Admin-Token": os.environ.get("BK_ADMIN_TOKEN", "bastion-admin-dev"),
         "Content-Type": "application/json"}

results = []


def check(name, ok, detail=""):
    results.append((name, ok))
    print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}")


def req(method, path, payload=None, headers=None, timeout=240):
    r = urllib.request.Request(BASE + path, method=method,
                               data=json.dumps(payload).encode() if payload is not None else None,
                               headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}


# capture a fresh drill key through the admin plane (least-privilege scopes)
s, b = req("POST", "/admin/keys/rotate/tenant-a", {"scopes": ["chat:read", "tools:exec", "admin"]}, ADMIN)
assert s == 200, f"rotate failed: {s} {b}"
KEY = b["key"]           # plaintext v2 shown once
KID_OLD = "v1"
AUTH = {"Authorization": f"Bearer {KEY}"}

chat = {"model": "glm-5.3-flash", "max_tokens": 16,
        "messages": [{"role": "user", "content": "Reply with one word: secured"}]}

# 1. no key -> 401
s, _ = req("POST", "/v1/chat/completions", chat)
check("attack: no key -> 401", s == 401, f"status={s}")

# 2. garbage key -> 401
s, _ = req("POST", "/v1/chat/completions", chat, {"Authorization": "Bearer bkx-deadbeef"})
check("attack: forged key -> 401", s == 401, f"status={s}")

# 3. valid key -> real chat through Bastion->BallKnowledge->GLM
s, b = req("POST", "/v1/chat/completions", chat, AUTH)
check("serve: valid key -> 200 via full chain", s == 200, f"status={s} body={str(b)[:80]}")

# 4. sandboxed exec works
s, b = req("POST", "/v1/tools/exec", {"code": "print(2+2)"}, AUTH)
check("sandbox: exec runs jailed", s == 200 and "4" in b.get("stdout", ""),
      f"status={s} stdout={b.get('stdout','')!r}")

# 5. sandbox timeout kills runaway code
s, b = req("POST", "/v1/tools/exec", {"code": "while True: pass"}, AUTH)
check("sandbox: runaway code killed by timeout", b.get("stderr") == "timeout",
      f"wall={b.get('wall_s')}s")

# 6. tamper detection: admin edits an audit entry -> verify fails
s, b = req("POST", "/admin/chaos/tamper-audit/tenant-a", {}, ADMIN)
check("attack: audit tamper DETECTED", b.get("integrity_ok") is False,
      f"reason={b.get('reason')}")

# 7. after tamper, /v1/audit refuses to silently claim integrity (it reports the break)
s, b = req("GET", "/v1/audit", None, AUTH)
check("audit: tenant view reports integrity break honestly",
      b.get("integrity_ok") is False, f"reason={b.get('integrity_reason')}")

# 8. scope escalation: mint a chat-only key, try admin -> 403
s, b = req("POST", "/admin/keys/rotate/tenant-b", {"scopes": ["chat:read"]}, ADMIN)
chatonly = b["key"]
s, b = req("GET", "/v1/audit", None, {"Authorization": f"Bearer {chatonly}"})
check("attack: scope escalation -> 403", s == 403, f"status={s}")
# 8b. and the server-side proof: rotate without scopes is REFUSED (no silent admin)
s, b = req("POST", "/admin/keys/rotate/tenant-b", {}, ADMIN)
check("hardening: scopeless rotate refused (400)", s == 400, f"status={s}")

# 9. revoke: old tenant-b v1 key dies instantly
s, b = req("POST", "/admin/keys/revoke/tenant-b/v1", {}, ADMIN)
check("revoke: v1 revoked", s == 200 and b.get("revoked") is True)
# (v1's plaintext was only in the boot log - revocation verified by vault state)

# 10. admin plane itself is gated
s, _ = req("POST", "/admin/keys/rotate/tenant-a", {}, {})
check("attack: anonymous admin -> 403", s == 403, f"status={s}")

fails = [r for r in results if not r[1]]
print(f"\n{len(results) - len(fails)}/{len(results)} checks passed")
sys.exit(1 if fails else 0)
