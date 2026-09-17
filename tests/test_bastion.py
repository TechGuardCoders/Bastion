"""Offline tests for Bastion security primitives - no network, no servers."""
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from bastion import (AuditChain, KeyVault, PBKDF2_ITERATIONS,  # noqa: E402
                     sandbox_exec)


def test_key_mint_and_auth():
    v = KeyVault()
    raw, kid = v.mint("t1", {"chat:read"})
    assert raw.startswith("bkx-") and kid == "v1"
    rec = v.authenticate(f"Bearer {raw}")
    assert rec is not None and rec.tenant_id == "t1" and rec.scopes == {"chat:read"}
    assert v.authenticate("Bearer wrong-key") is None
    assert v.authenticate(None) is None


def test_plaintext_never_stored():
    v = KeyVault()
    raw, _ = v.mint("t1", {"chat:read"})
    # after minting, no record anywhere holds the plaintext
    dumped = json.dumps(v._records, default=str)
    assert raw not in dumped
    assert raw.encode() not in dumped.encode()


def test_hash_strength():
    v = KeyVault()
    raw, _ = v.mint("t1", {"chat:read"})
    rec = v._records["t1"][0]
    # PBKDF2 with real iterations: not a bare sha256 of the key
    import hashlib
    assert rec.hash_hex != hashlib.sha256(raw.encode()).hexdigest()
    assert PBKDF2_ITERATIONS >= 50_000


def test_revoke_and_rotate():
    v = KeyVault()
    raw1, kid1 = v.mint("t1", {"chat:read"})
    assert v.authenticate(f"Bearer {raw1}") is not None
    raw2, kid2 = v.rotate("t1", {"chat:read"})
    assert kid2 == "v2" and raw2 != raw1
    # rotation: both work until revoke
    assert v.authenticate(f"Bearer {raw1}") is not None
    assert v.revoke("t1", kid1) is True
    assert v.authenticate(f"Bearer {raw1}") is None      # revoked = dead
    assert v.authenticate(f"Bearer {raw2}") is not None  # new version alive


def test_audit_chain_tamper_evidence():
    ch = AuditChain()
    ch.append({"event": "a"})
    ch.append({"event": "b"})
    ch.append({"event": "c"})
    ok, _ = ch.verify()
    assert ok

    # edit an entry body -> detect
    ch.events[1]["body"] = json.dumps({"event": "EVIL"})
    ok, reason = ch.verify()
    assert not ok and "entry 1" in reason

    # delete an entry -> prev mismatch downstream
    ch2 = AuditChain()
    for e in ("a", "b", "c"):
        ch2.append({"event": e})
    del ch2.events[1]
    ok, reason = ch2.verify()
    assert not ok

    # reorder -> detected
    ch3 = AuditChain()
    for e in ("a", "b", "c"):
        ch3.append({"event": e})
    ch3.events[0], ch3.events[2] = ch3.events[2], ch3.events[0]
    ok, reason = ch3.verify()
    assert not ok


def test_sandbox_exec_runs_and_jails():
    r = sandbox_exec("print('hello from jail')", timeout_s=10)
    assert r["ok"] and "hello from jail" in r["stdout"]
    # cannot read outside its disposable cwd via relative trickery
    r2 = sandbox_exec(
        "import os; print(sorted(os.listdir('.')))", timeout_s=10)
    assert r2["ok"] and r2["stdout"].strip() in ("[]", "['task.py']")


def test_sandbox_timeout():
    t0 = time.perf_counter()
    r = sandbox_exec("while True: pass", timeout_s=2)
    assert not r["ok"] and r["stderr"] == "timeout"
    assert time.perf_counter() - t0 < 8
