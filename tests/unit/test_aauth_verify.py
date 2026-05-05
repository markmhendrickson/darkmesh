"""Unit tests for :mod:`darkmesh.aauth_verify`.

Uses the real signer from :mod:`darkmesh.aauth_signer` against an
in-process transport adapter so the tests exercise the exact wire
format the verifier will see from a live Darkmesh peer. We never hit
the network: :func:`_capture_signed_request` grabs the prepared
request out of the signer's requests.Session before it is sent.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import Any, Dict, Tuple
from unittest.mock import patch

import pytest

from darkmesh.aauth_signer import (
    SignerConfig,
    _content_digest,
    mint_agent_token_jwt,
    signed_post,
)
from darkmesh.aauth_verify import (
    AAuthVerifyError,
    has_aauth_headers,
    verify_request,
)
from darkmesh.trust_registry import TrustRegistry


def _entry(keypair, *, sub="darkmesh-test@unit", capabilities=("relay.publish",)):
    return {
        "thumbprint": keypair["thumbprint"],
        "sub": sub,
        "iss": "https://darkmesh.local",
        "public_jwk": keypair["public_jwk"],
        "capabilities": list(capabilities),
    }


def _build_registry(trust_file_factory, *entries_args):
    path = trust_file_factory(list(entries_args))
    return TrustRegistry(str(path)), path


def _capture_signed_request(
    url: str, payload: Dict[str, Any], *, config: SignerConfig
) -> Tuple[str, str, Dict[str, str], bytes]:
    """Run :func:`signed_post` without touching the network.

    Returns ``(method, url, headers, body)`` shaped exactly as the
    server would see it after ASGI framing.
    """
    captured: Dict[str, Any] = {}

    class _FakeResponse:
        status_code = 204
        text = ""

        def json(self):
            return {}

    def _fake_send(self, prepared, **_kwargs):  # noqa: ARG001 -- Session.send signature
        captured["method"] = prepared.method
        captured["url"] = prepared.url
        captured["headers"] = dict(prepared.headers)
        captured["body"] = prepared.body or b""
        return _FakeResponse()

    with patch("requests.Session.send", _fake_send):
        signed_post(url, payload, config=config)

    body = captured["body"]
    if isinstance(body, str):
        body = body.encode("utf-8")
    return captured["method"], captured["url"], captured["headers"], body


def test_has_aauth_headers_detects_signature(es256_keypair):
    assert has_aauth_headers({"Signature": "x"})
    assert has_aauth_headers({"signature-input": "x"})
    assert has_aauth_headers({"SIGNATURE-KEY": "x"})
    assert not has_aauth_headers({"x-darkmesh-key": "x"})


def test_valid_signature_roundtrip(
    trust_file_factory, es256_keypair, signer_config
):
    registry, _ = _build_registry(
        trust_file_factory,
        _entry(es256_keypair, sub=signer_config.sub, capabilities=("relay.publish",)),
    )
    method, url, headers, body = _capture_signed_request(
        "http://relay.test/darkmesh/relay/posts",
        {"request_id": "abc", "template": "warm_intro_v1"},
        config=signer_config,
    )
    result = verify_request(
        method=method,
        url=url,
        headers=headers,
        body=body,
        trust_registry=registry,
    )
    assert result.sub == signer_config.sub
    assert result.iss == signer_config.iss
    assert result.thumbprint == es256_keypair["thumbprint"]
    assert "relay.publish" in result.capabilities
    assert result.has_capability("relay.publish")
    assert not result.has_capability("node.ingest")


def test_tampered_body_rejected(
    trust_file_factory, es256_keypair, signer_config
):
    registry, _ = _build_registry(
        trust_file_factory, _entry(es256_keypair, sub=signer_config.sub)
    )
    method, url, headers, body = _capture_signed_request(
        "http://relay.test/darkmesh/relay/posts",
        {"request_id": "abc"},
        config=signer_config,
    )
    tampered_body = body.replace(b"abc", b"xyz")
    assert tampered_body != body
    with pytest.raises(AAuthVerifyError) as exc:
        verify_request(
            method=method,
            url=url,
            headers=headers,
            body=tampered_body,
            trust_registry=registry,
        )
    # Either the content-digest check fires (mismatch) or the signature
    # check fires on the covered ``content-digest`` header — both are
    # acceptable outcomes for a tampered body.
    assert exc.value.reason in {"content_digest_mismatch", "signature_invalid"}


def test_tampered_digest_header_breaks_signature(
    trust_file_factory, es256_keypair, signer_config
):
    registry, _ = _build_registry(
        trust_file_factory, _entry(es256_keypair, sub=signer_config.sub)
    )
    method, url, headers, body = _capture_signed_request(
        "http://relay.test/darkmesh/relay/posts",
        {"request_id": "abc"},
        config=signer_config,
    )
    # Rewrite the digest to still match a body (so the hash check
    # passes) but diverge from what the signature covered.
    fresh_digest = _content_digest(b"something-else")
    headers_lower = {k.lower(): v for k, v in headers.items()}
    headers_lower["content-digest"] = fresh_digest
    # Also actually change the body to match so content-digest check
    # passes and we isolate the signature-base mismatch.
    new_body = b"something-else"
    with pytest.raises(AAuthVerifyError) as exc:
        verify_request(
            method=method,
            url=url,
            headers=headers_lower,
            body=new_body,
            trust_registry=registry,
        )
    assert exc.value.reason == "signature_invalid"


def test_unknown_thumbprint_rejected(
    trust_file_factory, es256_keypair, second_keypair
):
    # Registry has ONLY the second keypair; the signer uses the first.
    registry, _ = _build_registry(trust_file_factory, _entry(second_keypair))
    cfg = SignerConfig(
        private_jwk=es256_keypair["private_jwk"],
        sub="darkmesh-node@unknown",
        iss="https://darkmesh.local",
        token_ttl_sec=120,
    )
    method, url, headers, body = _capture_signed_request(
        "http://relay.test/darkmesh/relay/posts",
        {"x": 1},
        config=cfg,
    )
    with pytest.raises(AAuthVerifyError) as exc:
        verify_request(
            method=method,
            url=url,
            headers=headers,
            body=body,
            trust_registry=registry,
        )
    assert exc.value.reason == "unknown_thumbprint"


def test_expired_jwt_rejected(
    trust_file_factory, es256_keypair
):
    registry, _ = _build_registry(trust_file_factory, _entry(es256_keypair, sub="expired@test"))
    # Mint a token with a tiny TTL, then wait past its exp + skew.
    cfg = SignerConfig(
        private_jwk=es256_keypair["private_jwk"],
        sub="expired@test",
        iss="https://darkmesh.local",
        token_ttl_sec=30,
    )
    method, url, headers, body = _capture_signed_request(
        "http://relay.test/darkmesh/relay/posts",
        {"x": 1},
        config=cfg,
    )
    # Skip real sleep — fast-forward the verifier's clock instead so the
    # test stays sub-second.
    future_now = int(time.time()) + 10_000
    with pytest.raises(AAuthVerifyError) as exc:
        verify_request(
            method=method,
            url=url,
            headers=headers,
            body=body,
            trust_registry=registry,
            now=future_now,
        )
    assert exc.value.reason == "jwt_expired"


def test_wrong_typ_rejected(
    trust_file_factory, es256_keypair, signer_config, monkeypatch
):
    registry, _ = _build_registry(
        trust_file_factory, _entry(es256_keypair, sub=signer_config.sub)
    )

    # Monkeypatch the signer's JWT minter to emit a token with a bogus
    # ``typ`` so the rest of the wire format stays identical.
    real_mint = mint_agent_token_jwt

    def _bad_mint(config):
        token = real_mint(config)
        # Replace the header segment's typ field.
        header_b64, payload_b64, sig_b64 = token.split(".")

        def _fix(segment):
            padding = 4 - (len(segment) % 4)
            if padding != 4:
                segment = segment + "=" * padding
            return json.loads(base64.urlsafe_b64decode(segment.encode("ascii")))

        header = _fix(header_b64)
        header["typ"] = "application/jwt"
        new_header = (
            base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
            .rstrip(b"=")
            .decode("ascii")
        )
        # Don't bother re-signing — the HTTP signature covers the whole
        # ``signature-key`` header so verification stops at typ check
        # before it gets to RSA math.
        return f"{new_header}.{payload_b64}.{sig_b64}"

    monkeypatch.setattr("darkmesh.aauth_signer.mint_agent_token_jwt", _bad_mint)
    method, url, headers, body = _capture_signed_request(
        "http://relay.test/darkmesh/relay/posts",
        {"x": 1},
        config=signer_config,
    )
    with pytest.raises(AAuthVerifyError) as exc:
        verify_request(
            method=method,
            url=url,
            headers=headers,
            body=body,
            trust_registry=registry,
        )
    assert exc.value.reason == "jwt_typ_invalid"


def test_replay_outside_max_age_rejected(
    trust_file_factory, es256_keypair, signer_config
):
    """A captured + delayed request must be rejected once its `created`
    timestamp falls outside the configured freshness window.

    Rather than stalling the test for 10+ seconds to outlast the
    library's 5s clock-skew tolerance, we shift the clock forward by
    monkeypatching the ``datetime.datetime`` the signatures module
    consults when computing ``now``.
    """
    registry, _ = _build_registry(
        trust_file_factory, _entry(es256_keypair, sub=signer_config.sub)
    )
    method, url, headers, body = _capture_signed_request(
        "http://relay.test/darkmesh/relay/posts",
        {"x": 1},
        config=signer_config,
    )
    import datetime as _dt
    import http_message_signatures.signatures as sigmod

    real_datetime = sigmod.datetime.datetime
    shift = _dt.timedelta(seconds=3600)

    class _ShiftedDatetime(real_datetime):
        @classmethod
        def now(cls, tz=None):
            return real_datetime.now(tz) + shift

        @classmethod
        def fromtimestamp(cls, ts, tz=None):
            return real_datetime.fromtimestamp(ts, tz)

    with patch.object(sigmod.datetime, "datetime", _ShiftedDatetime):
        with pytest.raises(AAuthVerifyError) as exc:
            verify_request(
                method=method,
                url=url,
                headers=headers,
                body=body,
                trust_registry=registry,
                max_age_sec=60,
            )
    assert exc.value.reason == "signature_invalid"


def test_sub_mismatch_against_registry(
    trust_file_factory, es256_keypair
):
    # Registry entry pins sub="darkmesh-node@registered" but the client
    # claims sub="darkmesh-node@other".
    registry, _ = _build_registry(
        trust_file_factory,
        _entry(es256_keypair, sub="darkmesh-node@registered"),
    )
    cfg = SignerConfig(
        private_jwk=es256_keypair["private_jwk"],
        sub="darkmesh-node@other",
        iss="https://darkmesh.local",
        token_ttl_sec=120,
    )
    method, url, headers, body = _capture_signed_request(
        "http://relay.test/darkmesh/relay/posts",
        {"x": 1},
        config=cfg,
    )
    with pytest.raises(AAuthVerifyError) as exc:
        verify_request(
            method=method,
            url=url,
            headers=headers,
            body=body,
            trust_registry=registry,
        )
    assert exc.value.reason == "sub_mismatch"


def test_missing_signature_key_header(trust_file_factory, es256_keypair):
    registry, _ = _build_registry(trust_file_factory, _entry(es256_keypair))
    body = b"{}"
    digest = _content_digest(body)
    headers = {
        "content-type": "application/json",
        "content-digest": digest,
        # No signature-key!
        "signature-input": 'aasig=("@method")',
        "signature": "aasig=:AAAA:",
    }
    with pytest.raises(AAuthVerifyError) as exc:
        verify_request(
            method="POST",
            url="http://relay.test/darkmesh/relay/posts",
            headers=headers,
            body=body,
            trust_registry=registry,
        )
    assert exc.value.reason == "signature_key_missing"


def test_content_digest_mismatch_reported_specifically(
    trust_file_factory, es256_keypair, signer_config
):
    registry, _ = _build_registry(
        trust_file_factory, _entry(es256_keypair, sub=signer_config.sub)
    )
    method, url, headers, body = _capture_signed_request(
        "http://relay.test/darkmesh/relay/posts",
        {"x": 1},
        config=signer_config,
    )
    # Change the body *after* signing but leave the digest header alone;
    # verify_request should flag the digest-vs-body mismatch explicitly
    # (not fall through to signature_invalid first).
    new_body = body + b" "
    with pytest.raises(AAuthVerifyError) as exc:
        verify_request(
            method=method,
            url=url,
            headers=headers,
            body=new_body,
            trust_registry=registry,
        )
    assert exc.value.reason == "content_digest_mismatch"
