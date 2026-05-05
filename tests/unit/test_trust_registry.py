"""Unit tests for :mod:`darkmesh.trust_registry`."""

from __future__ import annotations

import json
import os
import time

import pytest

from darkmesh.trust_registry import (
    TrustRegistry,
    TrustRegistryError,
    load_trust_registry_from_env,
    write_trust_registry,
)


def _entry(keypair, *, sub="darkmesh-node@test", capabilities=("relay.publish",)):
    return {
        "thumbprint": keypair["thumbprint"],
        "sub": sub,
        "iss": "https://darkmesh.local",
        "public_jwk": keypair["public_jwk"],
        "capabilities": list(capabilities),
    }


def test_load_and_lookup(trust_registry_with, es256_keypair):
    registry, _path = trust_registry_with([_entry(es256_keypair)])
    entry = registry.lookup_by_thumbprint(es256_keypair["thumbprint"])
    assert entry is not None
    assert entry["sub"] == "darkmesh-node@test"
    assert entry["capabilities"] == ("relay.publish",)


def test_permits_exact_and_wildcard(trust_registry_with, es256_keypair, second_keypair):
    registry, _ = trust_registry_with(
        [
            _entry(es256_keypair, sub="a", capabilities=("relay.publish", "relay.pull")),
            _entry(second_keypair, sub="b", capabilities=("*",)),
        ]
    )
    assert registry.permits(es256_keypair["thumbprint"], "relay.publish")
    assert not registry.permits(es256_keypair["thumbprint"], "node.ingest")
    assert registry.permits(second_keypair["thumbprint"], "anything.at.all")


def test_unknown_thumbprint_returns_none(trust_registry_with, es256_keypair):
    registry, _ = trust_registry_with([_entry(es256_keypair)])
    assert registry.lookup_by_thumbprint("not-a-real-thumbprint") is None
    assert registry.permits("not-a-real-thumbprint", "relay.publish") is False


def test_missing_file_required_raises(tmp_path):
    missing = tmp_path / "missing.json"
    with pytest.raises(TrustRegistryError):
        TrustRegistry(str(missing))


def test_missing_file_allow_missing_ok(tmp_path):
    missing = tmp_path / "missing.json"
    registry = TrustRegistry(str(missing), allow_missing=True)
    assert len(registry) == 0
    assert registry.lookup_by_thumbprint("anything") is None


def test_private_key_material_rejected(trust_file_factory, es256_keypair):
    bad = {
        "thumbprint": es256_keypair["thumbprint"],
        "sub": "bad",
        "iss": "https://darkmesh.local",
        "public_jwk": dict(es256_keypair["private_jwk"]),
        "capabilities": [],
    }
    path = trust_file_factory([bad])
    with pytest.raises(TrustRegistryError):
        TrustRegistry(str(path))


def test_hot_reload_on_mtime_change(trust_registry_with, es256_keypair, second_keypair):
    registry, path = trust_registry_with([_entry(es256_keypair, sub="orig")])
    assert registry.lookup_by_thumbprint(es256_keypair["thumbprint"])["sub"] == "orig"

    # Rewrite the file with a different entry; bump mtime so the
    # stat-based reload picks up the change even if the write lands in
    # the same second as the initial load.
    new_entries = [_entry(second_keypair, sub="swapped")]
    path.write_text(json.dumps({"version": 1, "agents": new_entries}, indent=2))
    os.utime(path, (time.time() + 2, time.time() + 2))

    assert registry.lookup_by_thumbprint(es256_keypair["thumbprint"]) is None
    entry = registry.lookup_by_thumbprint(second_keypair["thumbprint"])
    assert entry is not None
    assert entry["sub"] == "swapped"


def test_reload_keeps_old_snapshot_on_parse_error(trust_registry_with, es256_keypair):
    registry, path = trust_registry_with([_entry(es256_keypair, sub="good")])
    path.write_text("{not: valid json")
    os.utime(path, (time.time() + 2, time.time() + 2))
    entry = registry.lookup_by_thumbprint(es256_keypair["thumbprint"])
    assert entry is not None
    assert entry["sub"] == "good"


def test_load_from_env(monkeypatch, trust_file_factory, es256_keypair):
    path = trust_file_factory([_entry(es256_keypair)])
    monkeypatch.setenv("DARKMESH_TRUSTED_AGENTS_FILE", str(path))
    registry = load_trust_registry_from_env()
    assert len(registry) == 1


def test_load_from_env_absent_returns_empty(monkeypatch):
    monkeypatch.delenv("DARKMESH_TRUSTED_AGENTS_FILE", raising=False)
    registry = load_trust_registry_from_env()
    assert len(registry) == 0


def test_write_trust_registry_roundtrip(tmp_path, es256_keypair):
    target = tmp_path / "out" / "trusted_agents.json"
    write_trust_registry(
        str(target),
        [_entry(es256_keypair, sub="roundtrip", capabilities=("relay.publish",))],
    )
    data = json.loads(target.read_text())
    assert data["version"] == 1
    assert data["agents"][0]["sub"] == "roundtrip"
    # Reload via registry and confirm we can look the key up.
    registry = TrustRegistry(str(target))
    assert registry.lookup_by_thumbprint(es256_keypair["thumbprint"]) is not None
