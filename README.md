# Bastion

**Secure multi-tenant inference layer — the security shell in front of [Ball Knowledge](https://github.com/TechGuardCoders/ball-knowledge).**

One noisy neighbor or one leaked key ends the B2B deal. Bastion proves the countermeasures with executed attacks, not diagrams:

```
client -> Bastion :3200 -> Ball Knowledge :3100 -> glm-spark (vLLM, 2x DGX Spark)
```

## Security stack

| Layer | Mechanism |
|---|---|
| **Key storage** | PBKDF2-HMAC-SHA256 (60k iterations, per-key salt). Plaintext shown exactly once at mint; constant-time compare on auth |
| **Key lifecycle** | Versioned rotation (v1, v2, …) — rotate without downtime, revoke instantly, old versions die on revoke |
| **Scopes** | `chat:read` / `tools:exec` / `admin`. Chat-only keys get 403 on admin. Scopeless rotation is *refused* — no silent privilege minting |
| **Tamper-evident audit** | Per-tenant hash chains: each entry commits to the previous hash. Edit, delete, or reorder any entry and verification names the broken entry |
| **Sandboxed exec** | `/v1/tools/exec` runs tenant code in a jailed subprocess: disposable cwd, clean env, hard timeout (runaway code killed) |
| **Admin plane** | Never anonymous — token-gated (dev token; mTLS/SSO in prod) |

## Live attack drill (executed, `scripts/attack_drill.py`)

```
11/11 checks passed

PASS  attack: no key -> 401
PASS  attack: forged key -> 401
PASS  serve: valid key -> 200 via full chain        <- Bastion->Gateway->real GLM
PASS  sandbox: exec runs jailed                     <- print(2+2) -> "4"
PASS  sandbox: runaway code killed by timeout       <- while True killed at 5s
PASS  attack: audit tamper DETECTED                 <- entry 3: body does not match its hash
PASS  audit: tenant view reports integrity break honestly
PASS  attack: scope escalation -> 403
PASS  hardening: scopeless rotate refused (400)
PASS  revoke: v1 revoked
PASS  attack: anonymous admin -> 403
```

The tamper check is real: the drill *edits a live audit entry in place* (the insider attack), then verification catches it and names the entry.

## The drill caught a real bug

The first drill run failed check "scope escalation → 403" — because the rotate endpoint minted **full-scope keys regardless of request**. A security drill that only validates what you already believe is theater; this one found a genuine privilege-escalation path in my first implementation. Fix: rotations are least-privilege — they carry only explicitly granted scopes, and scopeless rotation returns 400. The drill now also asserts the refusal.

## Run it

```bash
# Ball Knowledge first (:3100), then Bastion
uv venv .venv && uv pip install -r requirements.txt
BK_ADMIN_TOKEN=<token> .venv/Scripts/python -m uvicorn bastion:app --port 3200

# drill
.venv/Scripts/python scripts/attack_drill.py
```

Port map: 3000 never · 3001 Cost Peep · 3100 Ball Knowledge · **3200 Bastion**.

## Tests

7 offline tests (`tests/test_bastion.py`): key mint/auth, plaintext-never-stored, hash strength, revoke+rotate, tamper evidence (edit/delete/reorder all detected), sandbox jail, timeout kill. CI-safe, no network.

## What's next

Per-tenant attribution from this stack fills **Cost Peep's BY TENANT tab** — cost per tenant with the security to trust who's who.

## Fleet mode (per-node scoped credentials)

Bastion keys can be scoped to specific fleet nodes. A key with no node restriction works everywhere (default, unchanged); a scoped key authenticates only on its allowlisted nodes.

```python
raw, kid = vault.mint("tenant-a", {"chat:read"}, nodes={"glm-head", "tensorfold"})
vault.authenticate(f"Bearer {raw}", node_id="tensorfold")  # ok
vault.authenticate(f"Bearer {raw}", node_id="bonsai")      # None -> 403
```

Routing: `POST /v1/chat/completions` with header `X-Fleet-Node: <id>` forwards to that node (from `BASTION_FLEET_NODES`, comma-separated `id=url` pairs). Keys not scoped to the target node get 403, and the denial is audit-logged.
