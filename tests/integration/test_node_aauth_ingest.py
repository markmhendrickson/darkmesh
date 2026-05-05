"""Integration test: AAuth-authed ingest into a Darkmesh node.

Builds an in-process Darkmesh node (via :func:`darkmesh.service.create_app`)
configured with ``auth_mode="either"`` and a trust registry containing
a connector-scoped public key. A call to the node's ``/darkmesh/ingest``
endpoint signed by that key must succeed and increment the contact
count; an unsigned call with a wrong HMAC node-key must fail.

.. note::

    Capability scoping in this file is the **Darkmesh-internal** trust
    registry (``config/trusted_agents.json``, loaded by
    :class:`darkmesh.trust_registry.TrustRegistry`). Capabilities here
    are Phase-3 strings like ``node.ingest`` and ``relay.publish`` and
    are unrelated to Neotoma's ``agent_grant`` capabilities (``op`` ×
    ``entity_types``). Do not collapse the two: the trust registry
    governs node ↔ relay ↔ peer authorization on the Darkmesh wire,
    while Neotoma grants govern what the same identity may write or
    retrieve from the Neotoma entity graph. See
    ``docs/neotoma_integration.md`` for the grants playbook.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import pytest
from fastapi.testclient import TestClient

from darkmesh.aauth_signer import SignerConfig


def _trust_entry(keypair: Dict[str, Any], *, sub: str, capabilities):
    return {
        "thumbprint": keypair["thumbprint"],
        "sub": sub,
        "iss": "https://darkmesh.local",
        "public_jwk": keypair["public_jwk"],
        "capabilities": list(capabilities),
    }


def _write_trust(path: Path, entries) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"version": 1, "agents": list(entries)}))
    return path


def _build_node_config(tmp_path: Path, *, auth_mode: str, trust_file: Path) -> Path:
    cfg = {
        "node_id": "mark_local",
        "vault_path": str(tmp_path / "vault"),
        "self_identifiers": ["mark@example.com"],
        "pseudonym_id": "p_mark_local",
        "capabilities": ["warm_intro_v1"],
        "dev_mode": True,
        "port": 8001,
        "listen_url": "http://node.local:8001",
        "relay_url": "",
        "node_key": "dev-node-key",
        "auth_mode": auth_mode,
        "trusted_agents_file": str(trust_file),
        "required_integrations": ["contacts", "interactions"],
    }
    cfg_path = tmp_path / "node_config.json"
    cfg_path.write_text(json.dumps(cfg))
    return cfg_path


@pytest.fixture
def connector_keypair(es256_keypair):
    return es256_keypair


def test_aauth_ingest_via_connector_sub(
    tmp_path, monkeypatch, connector_keypair, signed_transport
):
    from darkmesh.aauth_signer import signed_post
    from darkmesh.service import create_app, load_config

    trust_path = _write_trust(
        tmp_path / "trust" / "trusted_agents.json",
        [
            _trust_entry(
                connector_keypair,
                sub="connector-csv-contacts@mark_local",
                capabilities=["node.ingest"],
            )
        ],
    )
    cfg_path = _build_node_config(tmp_path, auth_mode="either", trust_file=trust_path)
    monkeypatch.setenv("DARKMESH_CONFIG", str(cfg_path))

    app = create_app()
    client = TestClient(app)
    node_base = "http://node.local:8001"
    signed_transport.register(node_base, client)

    signer = SignerConfig(
        private_jwk=connector_keypair["private_jwk"],
        sub="connector-csv-contacts@mark_local",
        iss="https://darkmesh.local",
        token_ttl_sec=120,
    )

    resp = signed_post(
        f"{node_base}/darkmesh/ingest",
        {
            "dataset": "contacts",
            "records": [
                {
                    "name": "Alice",
                    "email": "alice@example.com",
                    "strength": 0.8,
                }
            ],
        },
        config=signer,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"dataset": "contacts", "count": 1}


def test_aauth_ingest_rejects_missing_capability(
    tmp_path, monkeypatch, connector_keypair, signed_transport
):
    """A trusted key with node.query (but no node.ingest) must fail."""
    from darkmesh.aauth_signer import signed_post
    from darkmesh.service import create_app

    trust_path = _write_trust(
        tmp_path / "trust" / "trusted_agents.json",
        [
            _trust_entry(
                connector_keypair,
                sub="observer@mark_local",
                capabilities=["node.query"],
            )
        ],
    )
    cfg_path = _build_node_config(tmp_path, auth_mode="either", trust_file=trust_path)
    monkeypatch.setenv("DARKMESH_CONFIG", str(cfg_path))

    app = create_app()
    client = TestClient(app)
    node_base = "http://node.local:8011"
    signed_transport.register(node_base, client)

    signer = SignerConfig(
        private_jwk=connector_keypair["private_jwk"],
        sub="observer@mark_local",
        iss="https://darkmesh.local",
        token_ttl_sec=120,
    )

    resp = signed_post(
        f"{node_base}/darkmesh/ingest",
        {"dataset": "contacts", "records": [{"email": "x@example.com"}]},
        config=signer,
    )
    assert resp.status_code == 403, resp.text
    assert "node.ingest" in resp.text


def test_hmac_ingest_still_works_in_either_mode(tmp_path, monkeypatch, connector_keypair):
    from darkmesh.service import create_app

    trust_path = _write_trust(
        tmp_path / "trust" / "trusted_agents.json",
        [
            _trust_entry(
                connector_keypair,
                sub="connector-csv-contacts@mark_local",
                capabilities=["node.ingest"],
            )
        ],
    )
    cfg_path = _build_node_config(tmp_path, auth_mode="either", trust_file=trust_path)
    monkeypatch.setenv("DARKMESH_CONFIG", str(cfg_path))

    app = create_app()
    client = TestClient(app)

    resp = client.post(
        "/darkmesh/ingest",
        json={"dataset": "contacts", "records": [{"email": "hmac@example.com"}]},
        headers={"X-Darkmesh-Key": "dev-node-key"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["count"] >= 1


def test_aauth_only_mode_rejects_hmac(tmp_path, monkeypatch, connector_keypair):
    from darkmesh.service import create_app

    trust_path = _write_trust(
        tmp_path / "trust" / "trusted_agents.json",
        [
            _trust_entry(
                connector_keypair,
                sub="connector-csv-contacts@mark_local",
                capabilities=["node.ingest"],
            )
        ],
    )
    cfg_path = _build_node_config(tmp_path, auth_mode="aauth", trust_file=trust_path)
    monkeypatch.setenv("DARKMESH_CONFIG", str(cfg_path))

    app = create_app()
    client = TestClient(app)

    resp = client.post(
        "/darkmesh/ingest",
        json={"dataset": "contacts", "records": [{"email": "hmac@example.com"}]},
        headers={"X-Darkmesh-Key": "dev-node-key"},
    )
    assert resp.status_code == 401, resp.text
