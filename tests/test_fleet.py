"""Fleet tests: per-node scoped credentials and allowlists. No network."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from bastion import KeyVault, fleet_nodes  # noqa: E402


def test_unscoped_key_works_everywhere():
    """Default behavior unchanged: no node restriction = all nodes."""
    v = KeyVault()
    raw, _ = v.mint("t1", {"chat:read"})
    assert v.authenticate(f"Bearer {raw}", node_id="node-a") is not None
    assert v.authenticate(f"Bearer {raw}", node_id="node-b") is not None
    assert v.authenticate(f"Bearer {raw}") is not None


def test_node_scoped_key_only_authenticates_on_its_node():
    v = KeyVault()
    raw, _ = v.mint("t1", {"chat:read"}, nodes={"node-a"})
    assert v.authenticate(f"Bearer {raw}", node_id="node-a") is not None
    assert v.authenticate(f"Bearer {raw}", node_id="node-b") is None, \
        "scoped key must not authenticate on a foreign node"
    # without a node context (default path), scoped key still verifies
    assert v.authenticate(f"Bearer {raw}") is not None


def test_scoped_rotate_carries_allowlist():
    v = KeyVault()
    raw, kid = v.rotate("t1", {"chat:read"}, nodes={"node-b"})
    rec = v.authenticate(f"Bearer {raw}", node_id="node-b")
    assert rec is not None and rec.key_id == kid
    assert v.authenticate(f"Bearer {raw}", node_id="node-a") is None


def test_revoked_scoped_key_dead_everywhere():
    v = KeyVault()
    raw, kid = v.mint("t1", {"chat:read"}, nodes={"node-a"})
    v.revoke("t1", kid)
    assert v.authenticate(f"Bearer {raw}", node_id="node-a") is None
    assert v.authenticate(f"Bearer {raw}") is None


def test_allowed_on_helper():
    v = KeyVault()
    _, _ = v.mint("t1", {"chat:read"}, nodes={"node-a", "node-c"})
    rec = v._records["t1"][0]
    assert rec.allowed_on("node-a") and rec.allowed_on("node-c")
    assert not rec.allowed_on("node-b")
    unscoped, _ = v.mint("t2", {"chat:read"})
    assert v._records["t2"][0].allowed_on("anything")


def test_fleet_nodes_env_parsing(monkeypatch=None):
    import os
    old = os.environ.pop("BASTION_FLEET_NODES", None)
    try:
        assert fleet_nodes() == {}
        os.environ["BASTION_FLEET_NODES"] = " n1=http://x:8421 , n2=http://y:8422 "
        nodes = fleet_nodes()
        assert nodes == {"n1": "http://x:8421", "n2": "http://y:8422"}
    finally:
        if old is not None:
            os.environ["BASTION_FLEET_NODES"] = old
        else:
            os.environ.pop("BASTION_FLEET_NODES", None)
