"""Integration-test harness shared across AAuth + relay scenarios.

Provides a ``patch_signed_transport`` fixture that reroutes
``requests.Session.send`` (used internally by
:func:`darkmesh.aauth_signer.signed_post`) into one or more FastAPI
``TestClient`` instances keyed by hostname. This lets us exercise real
signed requests against an in-process relay + node without binding
sockets.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Dict, Iterator
from unittest.mock import patch
from urllib.parse import urlparse

import pytest
from fastapi.testclient import TestClient


# darkmesh_relay.service creates its FastAPI app at import time via a
# module-level ``app = create_app()`` (for uvicorn). Give it safe defaults
# so a test that never uses the default relay can still import the
# module cleanly; individual tests monkeypatch these to per-test values
# before calling ``create_app()`` a second time.
os.environ.setdefault("DARKMESH_RELAY_KEY", "tests-default-relay-key")
os.environ.setdefault("DARKMESH_RELAY_AUTH_MODE", "either")


class _SignedTransportRouter:
    def __init__(self) -> None:
        self._clients: Dict[str, TestClient] = {}

    def register(self, base_url: str, client: TestClient) -> None:
        """Register ``client`` for the authority implied by ``base_url``.

        We rebind ``client.base_url`` to the signed authority so the
        starlette-in-httpx TestClient does not rewrite the ``Host``
        header to ``testserver`` — that would invalidate the
        ``@authority`` covered component on every signed request.
        """
        parsed = urlparse(base_url)
        host = parsed.hostname or ""
        port = parsed.port
        key = f"{host}:{port}" if port else host
        client.base_url = base_url.rstrip("/")
        self._clients[key] = client

    def _client_for(self, url: str) -> TestClient:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port
        key = f"{host}:{port}" if port else host
        if key not in self._clients:
            # Fallback: match on hostname alone (useful when a config
            # advertises a bare host without an explicit port).
            candidates = [k for k in self._clients if k.startswith(f"{host}:")]
            if len(candidates) == 1:
                key = candidates[0]
            else:
                raise RuntimeError(
                    f"No TestClient registered for {url!r}; "
                    f"registered keys: {list(self._clients)}"
                )
        return self._clients[key]

    def send_impl(self, prepared, **_kwargs):
        client = self._client_for(prepared.url)
        parsed = urlparse(prepared.url)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        # Normalise headers to plain dict[str, str] preserving every
        # field the signer produced. ``requests.CaseInsensitiveDict``
        # returns lowercase keys on iteration which httpx/TestClient
        # accepts but can collide with duplicates — we flatten before
        # forwarding.
        headers = {}
        for key, value in prepared.headers.items():
            headers[str(key)] = str(value)
        body = prepared.body or b""
        if isinstance(body, str):
            body = body.encode("utf-8")
        method = (prepared.method or "GET").upper()
        # Preserve the signed `Host` header by passing via the
        # ``base_url`` + path combo; TestClient otherwise rewrites
        # ``Host`` to ``testserver``, which invalidates the signed
        # ``@authority`` component.
        response = client.request(
            method,
            path,
            headers=headers,
            content=body,
        )

        class _WrappedResponse:
            def __init__(self, status_code: int, content: bytes, json_fn) -> None:
                self.status_code = status_code
                self._content = content
                self.text = content.decode("utf-8", errors="replace")
                self._json_fn = json_fn
                self.ok = 200 <= status_code < 400

            def json(self):
                return self._json_fn()

            def raise_for_status(self):
                if self.status_code >= 400:
                    from requests import HTTPError

                    raise HTTPError(
                        f"{self.status_code} for {prepared.url}: {self.text}"
                    )

        def _json_fn():
            try:
                return response.json()
            except Exception:
                return {}

        return _WrappedResponse(response.status_code, response.content, _json_fn)


@pytest.fixture
def signed_transport() -> Iterator[_SignedTransportRouter]:
    router = _SignedTransportRouter()

    def _send(session_self, prepared, **kwargs):  # noqa: ARG001
        return router.send_impl(prepared, **kwargs)

    with patch("requests.Session.send", new=_send):
        yield router


@contextmanager
def patch_requests_post_to(client: TestClient):
    """Route ``requests.post`` calls into a TestClient, preserving headers.

    Connectors use ``requests.post`` directly (for the HMAC path). This
    helper lets unsigned tests drive a FastAPI app without binding.
    """
    import requests as requests_module

    original_post = requests_module.post

    def _post(url: str, json=None, headers=None, timeout=None, **_kwargs):
        parsed = urlparse(url)
        path = parsed.path or "/"
        response = client.post(path, json=json, headers=headers or {})

        class _WrappedResponse:
            def __init__(self, status_code: int, content: bytes, json_fn) -> None:
                self.status_code = status_code
                self._content = content
                self.text = content.decode("utf-8", errors="replace")
                self._json_fn = json_fn
                self.ok = 200 <= status_code < 400

            def json(self):
                return self._json_fn()

            def raise_for_status(self):
                if self.status_code >= 400:
                    from requests import HTTPError

                    raise HTTPError(f"{self.status_code} for {url}: {self.text}")

        def _json_fn():
            try:
                return response.json()
            except Exception:
                return {}

        return _WrappedResponse(response.status_code, response.content, _json_fn)

    try:
        requests_module.post = _post
        yield
    finally:
        requests_module.post = original_post
