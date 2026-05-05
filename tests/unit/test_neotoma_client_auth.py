"""Unit tests for :class:`darkmesh.neotoma_client.NeotomaClient` auth modes.

Covers the Phase-2.5 read-path changes:

- bearer mode still emits ``Authorization: Bearer ...``
- AAuth mode signs ``POST /entities/query`` and ``GET /entities/{id}/relationships``
- missing signer config for ``auth_mode='aauth'`` fails clearly
- default (``auto``) resolves to bearer when no signer env vars are set and
  to AAuth when a :class:`SignerConfig` is injected explicitly
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Tuple
from unittest.mock import patch

import pytest
import requests
from requests.structures import CaseInsensitiveDict

from darkmesh.aauth_signer import SignerConfig
from darkmesh.neotoma_client import (
    AUTH_MODE_AAUTH,
    AUTH_MODE_AUTO,
    AUTH_MODE_BEARER,
    NeotomaClient,
    NeotomaClientConfigError,
)


class _FakeResponse:
    """Minimal ``requests.Response``-like stand-in for the transport."""

    def __init__(self, body: Any = None, status_code: int = 200) -> None:
        self._body = body if body is not None else {}
        self.status_code = status_code
        self.text = json.dumps(self._body)

    def json(self) -> Any:
        return self._body

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(f"status={self.status_code}")


@pytest.fixture(autouse=True)
def _isolate_aauth_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clear AAuth env so ``auto`` falls back to bearer unless a fixture
    re-enables it. Keeps tests hermetic regardless of developer shells.
    """
    for var in (
        "DARKMESH_AAUTH_PRIVATE_JWK",
        "DARKMESH_AAUTH_PRIVATE_JWK_PATH",
        "DARKMESH_AAUTH_SUB",
        "DARKMESH_NODE_ID",
        "DARKMESH_AAUTH_ISS",
        "DARKMESH_AAUTH_KID",
    ):
        monkeypatch.delenv(var, raising=False)


def _capture_requests_request(
    func: Callable[[], Any],
) -> Tuple[List[Dict[str, Any]], Any]:
    """Run ``func`` with ``requests.request`` patched, capturing each call.

    Returns ``(calls, result)`` where each call is ``{method, url, json,
    params, headers, timeout}``.
    """
    calls: List[Dict[str, Any]] = []

    def _fake_request(method: str, url: str, **kwargs: Any) -> _FakeResponse:
        calls.append({"method": method, "url": url, **kwargs})
        return _FakeResponse({"entities": []})

    with patch("darkmesh.neotoma_client.requests.request", _fake_request):
        result = func()
    return calls, result


def _capture_signed_requests(
    func: Callable[[], Any],
) -> Tuple[List[Dict[str, Any]], Any]:
    """Run ``func`` with ``requests.Session.send`` patched.

    AAuth signing routes through ``Session.send`` after preparing the
    request, so this is the only hook that sees the post-sign wire form.
    """
    calls: List[Dict[str, Any]] = []

    def _fake_send(self, prepared, **_kwargs):  # noqa: ARG001
        calls.append(
            {
                "method": prepared.method,
                "url": prepared.url,
                "headers": CaseInsensitiveDict(prepared.headers),
                "body": prepared.body or b"",
            }
        )
        return _FakeResponse({"entities": []})

    with patch("requests.Session.send", _fake_send):
        result = func()
    return calls, result


def test_bearer_mode_emits_authorization_header() -> None:
    client = NeotomaClient(
        base_url="http://neotoma.test",
        token="secret-token",
        auth_mode=AUTH_MODE_BEARER,
        max_entities=10,
    )
    assert client.resolved_auth_mode == AUTH_MODE_BEARER

    calls, _ = _capture_requests_request(lambda: client.query_entities())
    assert len(calls) == 1
    call = calls[0]
    assert call["method"] == "POST"
    assert call["url"] == "http://neotoma.test/entities/query"
    assert call["headers"]["authorization"] == "Bearer secret-token"
    assert call["json"]["entity_type"] == "contact"


def test_bearer_mode_get_relationships_uses_requests_layer() -> None:
    client = NeotomaClient(
        base_url="http://neotoma.test",
        token="secret-token",
        auth_mode=AUTH_MODE_BEARER,
    )

    calls, _ = _capture_requests_request(
        lambda: client.get_relationships("ent_abc")
    )
    call = calls[0]
    assert call["method"] == "GET"
    assert call["url"].endswith("/entities/ent_abc/relationships")
    assert call["headers"]["authorization"] == "Bearer secret-token"


def test_aauth_mode_signs_query_entities(signer_config: SignerConfig) -> None:
    client = NeotomaClient(
        base_url="http://neotoma.test",
        auth_mode=AUTH_MODE_AAUTH,
        signer_config=signer_config,
        max_entities=10,
    )
    assert client.resolved_auth_mode == AUTH_MODE_AAUTH

    calls, _ = _capture_signed_requests(lambda: client.query_entities())
    assert len(calls) == 1
    call = calls[0]
    assert call["method"] == "POST"
    assert call["url"].endswith("/entities/query")
    headers = call["headers"]
    # AAuth-signed reads carry an RFC 9421 signature and the agent JWT.
    assert "Signature" in headers
    assert "Signature-Input" in headers
    assert headers["Signature-Key"].startswith('aasig=jwt;jwt="')
    # And crucially they do NOT fall back to the bearer header.
    assert "Authorization" not in headers
    assert "authorization" not in headers
    # Content digest covers the JSON body.
    assert headers["content-type"] == "application/json"
    assert headers["content-digest"].startswith("sha-256=:")


def test_aauth_mode_signs_get_relationships(signer_config: SignerConfig) -> None:
    client = NeotomaClient(
        base_url="http://neotoma.test",
        auth_mode=AUTH_MODE_AAUTH,
        signer_config=signer_config,
    )

    calls, _ = _capture_signed_requests(
        lambda: client.get_relationships("ent_abc")
    )
    call = calls[0]
    assert call["method"] == "GET"
    assert call["url"].endswith("/entities/ent_abc/relationships")
    headers = call["headers"]
    assert "Signature" in headers
    assert headers["Signature-Key"].startswith('aasig=jwt;jwt="')
    # Bodyless requests must not carry a content-digest.
    assert "content-digest" not in {k.lower() for k in headers}
    # And no bearer fallback.
    assert "Authorization" not in headers


def test_aauth_mode_without_signer_fails_clearly() -> None:
    with pytest.raises(NeotomaClientConfigError) as exc:
        NeotomaClient(
            base_url="http://neotoma.test",
            auth_mode=AUTH_MODE_AAUTH,
        )
    assert "DARKMESH_AAUTH_PRIVATE_JWK" in str(exc.value)


def test_invalid_auth_mode_rejected() -> None:
    with pytest.raises(NeotomaClientConfigError):
        NeotomaClient(base_url="http://neotoma.test", auth_mode="basic")


def test_auto_defaults_to_bearer_when_signer_env_absent() -> None:
    client = NeotomaClient(
        base_url="http://neotoma.test",
        token="bearer-token",
        auth_mode=AUTH_MODE_AUTO,
    )
    assert client.resolved_auth_mode == AUTH_MODE_BEARER


def test_auto_prefers_aauth_when_signer_injected(signer_config: SignerConfig) -> None:
    client = NeotomaClient(
        base_url="http://neotoma.test",
        token="bearer-token",
        auth_mode=AUTH_MODE_AUTO,
        signer_config=signer_config,
    )
    assert client.resolved_auth_mode == AUTH_MODE_AAUTH

    # And actually signs the outbound request rather than falling through
    # to the bearer layer.
    calls, _ = _capture_signed_requests(lambda: client.query_entities())
    headers = calls[0]["headers"]
    assert "Signature" in headers
    assert "Authorization" not in headers


def test_default_auth_mode_is_bearer_for_backward_compatibility() -> None:
    """Existing call sites that pass no ``auth_mode`` must keep working.

    This guards against accidentally flipping the default to ``auto`` /
    ``aauth`` and silently breaking deployments without AAuth provisioned.
    """
    client = NeotomaClient(base_url="http://neotoma.test", token="t")
    assert client.auth_mode == AUTH_MODE_BEARER
    assert client.resolved_auth_mode == AUTH_MODE_BEARER


def test_darkmesh_config_defaults_to_auto_read_auth_mode() -> None:
    """``DarkmeshConfig`` should default to ``auto`` so AAuth-provisioned
    nodes pick it up automatically while bare deployments keep using
    bearer.
    """
    from darkmesh.service import DarkmeshConfig

    raw = {
        "node_id": "test",
        "vault_path": "data/test",
        "auth_mode": "hmac",
        "node_key": "k",
        "relay_key": "k",
    }
    config = DarkmeshConfig(raw)
    assert config.neotoma_read_auth_mode == "auto"


def test_darkmesh_config_rejects_invalid_read_auth_mode() -> None:
    from darkmesh.service import DarkmeshConfig

    raw = {
        "node_id": "test",
        "vault_path": "data/test",
        "auth_mode": "hmac",
        "node_key": "k",
        "relay_key": "k",
        "neotoma_read_auth_mode": "nope",
    }
    with pytest.raises(ValueError, match="neotoma_read_auth_mode"):
        DarkmeshConfig(raw)
