"""End-to-end AAuth round-trip against an in-process Darkmesh relay.

Exercises :func:`darkmesh.aauth_signer.signed_post` against a real
:mod:`darkmesh_relay.service` FastAPI app via the
``signed_transport`` fixture (see :mod:`tests.integration.conftest`).
This is the same path two live Darkmesh nodes would use to register,
publish a warm-intro post, and pull new posts — just without the
network hop.
"""

from __future__ import annotations

from typing import Any, Dict

import pytest
from fastapi.testclient import TestClient

from darkmesh.aauth_signer import SignerConfig


def _build_relay_app(
    tmp_path_factory,
    *,
    auth_mode: str,
    trust_entries,
    relay_key: str = "dev-relay-key",
    monkeypatch=None,
):
    """Build a relay FastAPI app with an isolated trust file on disk."""
    import json
    from pathlib import Path

    tmp_dir: Path = tmp_path_factory.mktemp("relay")
    trust_file = tmp_dir / "trusted_agents.json"
    trust_file.write_text(json.dumps({"version": 1, "agents": list(trust_entries)}))

    monkeypatch.setenv("DARKMESH_RELAY_AUTH_MODE", auth_mode)
    monkeypatch.setenv("DARKMESH_RELAY_TRUSTED_AGENTS_FILE", str(trust_file))
    monkeypatch.setenv("DARKMESH_RELAY_KEY", relay_key)

    from darkmesh_relay.service import create_app

    app = create_app()
    return app, trust_file


def _trust_entry(keypair: Dict[str, Any], *, sub: str, capabilities):
    return {
        "thumbprint": keypair["thumbprint"],
        "sub": sub,
        "iss": "https://darkmesh.local",
        "public_jwk": keypair["public_jwk"],
        "capabilities": list(capabilities),
    }


@pytest.fixture
def node_a_keypair(es256_keypair):
    return es256_keypair


@pytest.fixture
def node_b_keypair(second_keypair):
    return second_keypair


@pytest.fixture
def node_a_signer(node_a_keypair) -> SignerConfig:
    return SignerConfig(
        private_jwk=node_a_keypair["private_jwk"],
        sub="darkmesh-node@mark_local",
        iss="https://darkmesh.local",
        token_ttl_sec=120,
    )


@pytest.fixture
def node_b_signer(node_b_keypair) -> SignerConfig:
    return SignerConfig(
        private_jwk=node_b_keypair["private_jwk"],
        sub="darkmesh-node@node_b",
        iss="https://darkmesh.local",
        token_ttl_sec=120,
    )


def test_aauth_relay_roundtrip(
    tmp_path_factory,
    monkeypatch,
    node_a_keypair,
    node_b_keypair,
    node_a_signer,
    node_b_signer,
    signed_transport,
):
    from darkmesh.aauth_signer import signed_post

    entries = [
        _trust_entry(
            node_a_keypair,
            sub="darkmesh-node@mark_local",
            capabilities=["relay.register", "relay.publish", "relay.pull"],
        ),
        _trust_entry(
            node_b_keypair,
            sub="darkmesh-node@node_b",
            capabilities=["relay.register", "relay.publish", "relay.pull"],
        ),
    ]
    app, _ = _build_relay_app(
        tmp_path_factory,
        auth_mode="aauth",
        trust_entries=entries,
        monkeypatch=monkeypatch,
    )
    client = TestClient(app)
    relay_base = "http://relay.local:9000"
    signed_transport.register(relay_base, client)

    register_resp = signed_post(
        f"{relay_base}/darkmesh/relay/nodes/register",
        {
            "node_id": "mark_local",
            "url": "http://node-a.local:8001",
            "capabilities": ["warm_intro_v1"],
        },
        config=node_a_signer,
    )
    assert register_resp.status_code == 200, register_resp.text
    assert register_resp.json()["node"]["node_id"] == "mark_local"

    # Node B publishes a warm-intro post.
    publish_resp = signed_post(
        f"{relay_base}/darkmesh/relay/posts",
        {
            "request_id": "req-aauth-1",
            "requester_id": "node_b",
            "requester_url": "http://node-b.local:8002",
            "template": "warm_intro_v1",
            "target": {"email": "alice@example.com"},
            "psi": {},
            "constraints": {},
            "response_token": "tok-aauth-1",
        },
        config=node_b_signer,
    )
    assert publish_resp.status_code == 200, publish_resp.text
    assert publish_resp.json()["ok"] is True
    published_seq = publish_resp.json()["seq"]

    # Node A pulls and should see the new post (different requester_id,
    # matching capability).
    pull_resp = signed_post(
        f"{relay_base}/darkmesh/relay/posts/pull",
        {
            "node_id": "mark_local",
            "capabilities": ["warm_intro_v1"],
            "cursor": 0,
            "limit": 10,
        },
        config=node_a_signer,
    )
    assert pull_resp.status_code == 200, pull_resp.text
    body = pull_resp.json()
    assert body["cursor"] == published_seq
    assert len(body["posts"]) == 1
    assert body["posts"][0]["request_id"] == "req-aauth-1"


def test_aauth_relay_rejects_mismatched_node_id(
    tmp_path_factory,
    monkeypatch,
    node_a_keypair,
    node_a_signer,
    signed_transport,
):
    """An agent with ``sub=darkmesh-node@mark_local`` should not be able
    to claim ``node_id=node_b`` at registration."""
    from darkmesh.aauth_signer import signed_post

    entries = [
        _trust_entry(
            node_a_keypair,
            sub="darkmesh-node@mark_local",
            capabilities=["relay.register", "relay.publish", "relay.pull"],
        ),
    ]
    app, _ = _build_relay_app(
        tmp_path_factory,
        auth_mode="aauth",
        trust_entries=entries,
        monkeypatch=monkeypatch,
    )
    client = TestClient(app)
    relay_base = "http://relay.local:9100"
    signed_transport.register(relay_base, client)

    resp = signed_post(
        f"{relay_base}/darkmesh/relay/nodes/register",
        {
            "node_id": "node_b",  # squatting another operator's node_id
            "url": "http://evil.local:8001",
            "capabilities": ["warm_intro_v1"],
        },
        config=node_a_signer,
    )
    assert resp.status_code == 403, resp.text
    assert "does not match node_id" in resp.text


def test_relay_either_mode_accepts_hmac_clients(
    tmp_path_factory, monkeypatch, node_a_keypair
):
    """`auth_mode=either` should keep legacy HMAC clients working."""
    entries = [
        _trust_entry(
            node_a_keypair,
            sub="darkmesh-node@mark_local",
            capabilities=["relay.register"],
        ),
    ]
    app, _ = _build_relay_app(
        tmp_path_factory,
        auth_mode="either",
        trust_entries=entries,
        relay_key="dev-relay-key",
        monkeypatch=monkeypatch,
    )
    client = TestClient(app)

    resp = client.post(
        "/darkmesh/relay/nodes/register",
        json={
            "node_id": "hmac_only_node",
            "url": "http://hmac-client.local:8003",
            "capabilities": ["warm_intro_v1"],
            "relay_key": "dev-relay-key",
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["node"]["node_id"] == "hmac_only_node"


def test_relay_either_mode_rejects_wrong_hmac(
    tmp_path_factory, monkeypatch, node_a_keypair
):
    entries = [
        _trust_entry(
            node_a_keypair,
            sub="darkmesh-node@mark_local",
            capabilities=["relay.register"],
        ),
    ]
    app, _ = _build_relay_app(
        tmp_path_factory,
        auth_mode="either",
        trust_entries=entries,
        relay_key="dev-relay-key",
        monkeypatch=monkeypatch,
    )
    client = TestClient(app)

    resp = client.post(
        "/darkmesh/relay/nodes/register",
        json={
            "node_id": "hmac_only_node",
            "url": "http://hmac-client.local:8004",
            "capabilities": ["warm_intro_v1"],
            "relay_key": "wrong-key",
        },
    )
    assert resp.status_code == 403


def test_relay_aauth_mode_rejects_missing_capability(
    tmp_path_factory,
    monkeypatch,
    node_a_keypair,
    node_a_signer,
    signed_transport,
):
    from darkmesh.aauth_signer import signed_post

    # Grant relay.register but NOT relay.publish, then attempt to publish.
    entries = [
        _trust_entry(
            node_a_keypair,
            sub="darkmesh-node@mark_local",
            capabilities=["relay.register"],
        ),
    ]
    app, _ = _build_relay_app(
        tmp_path_factory,
        auth_mode="aauth",
        trust_entries=entries,
        monkeypatch=monkeypatch,
    )
    client = TestClient(app)
    relay_base = "http://relay.local:9200"
    signed_transport.register(relay_base, client)

    resp = signed_post(
        f"{relay_base}/darkmesh/relay/posts",
        {
            "request_id": "req-nocap-1",
            "requester_id": "mark_local",
            "requester_url": "http://node-a.local:8001",
            "template": "warm_intro_v1",
            "target": {"email": "alice@example.com"},
            "response_token": "tok-nocap-1",
        },
        config=node_a_signer,
    )
    assert resp.status_code == 403, resp.text
    assert "relay.publish" in resp.text
