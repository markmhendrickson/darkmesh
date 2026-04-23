"""Python AAuth signer for outbound Darkmesh -> Neotoma calls.

Mirrors :file:`services/agent-site/netlify/lib/aauth_signer.ts` and
:file:`src/cli/aauth_signer.ts` in the Neotoma repo. Produces RFC 9421 HTTP
Message Signatures with the AAuth profile (an ``aa-agent+jwt`` agent token
carried in the ``Signature-Key`` header). Neotoma's
:mod:`src/middleware/aauth_verify` verifies the signature and, on success,
stamps provenance with ``attribution_tier: software`` (ES256/EdDSA keys on
hardware security modules land as ``hardware``; plain software keys are
``software``).

Key provisioning
----------------

Private JWK is sourced from ``DARKMESH_AAUTH_PRIVATE_JWK`` (JSON string) or
from ``DARKMESH_AAUTH_PRIVATE_JWK_PATH``. Generate a fresh keypair via
:func:`generate_es256_keypair`. Public JWK discovery happens out-of-band —
Neotoma verifies against the ``jkt`` thumbprint baked into the agent
token, so there is no JWKS endpoint to publish for this integration.

Why these dependencies
----------------------

- ``jwcrypto`` handles JWK parsing, JWT minting, and JWK thumbprints
  (RFC 7638). Lightweight, no runtime compilation.
- ``http-message-signatures`` handles the RFC 9421 wire format (signature
  base string, content-digest header, signature-input). Keeping the
  canonicalisation in a library avoids subtle ``@authority`` / ``(*)``
  mistakes that would cause verification to silently fail.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from http_message_signatures import HTTPMessageSigner, HTTPSignatureKeyResolver, algorithms
from jwcrypto import jwk, jwt


class SignerConfigError(RuntimeError):
    """Raised when required signing config is missing or malformed."""


@dataclass
class SignerConfig:
    private_jwk: Dict[str, Any]
    sub: str
    iss: str
    kid: Optional[str] = None
    token_ttl_sec: int = 300


def _load_private_jwk() -> Dict[str, Any]:
    raw = os.environ.get("DARKMESH_AAUTH_PRIVATE_JWK")
    if raw:
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SignerConfigError(
                f"DARKMESH_AAUTH_PRIVATE_JWK is not valid JSON: {exc}"
            ) from exc

    path = os.environ.get("DARKMESH_AAUTH_PRIVATE_JWK_PATH")
    if path:
        try:
            return json.loads(Path(path).read_text(encoding="utf-8"))
        except OSError as exc:
            raise SignerConfigError(
                f"Failed to read DARKMESH_AAUTH_PRIVATE_JWK_PATH={path}: {exc}"
            ) from exc
        except json.JSONDecodeError as exc:
            raise SignerConfigError(
                f"DARKMESH_AAUTH_PRIVATE_JWK_PATH={path} is not valid JSON: {exc}"
            ) from exc

    raise SignerConfigError(
        "Neither DARKMESH_AAUTH_PRIVATE_JWK nor DARKMESH_AAUTH_PRIVATE_JWK_PATH is set. "
        "Generate a keypair with darkmesh.aauth_signer.generate_es256_keypair() "
        "and export the JWK."
    )


def load_signer_config_from_env() -> SignerConfig:
    private_jwk = _load_private_jwk()
    sub = os.environ.get("DARKMESH_AAUTH_SUB") or os.environ.get("DARKMESH_NODE_ID")
    if not sub:
        raise SignerConfigError(
            "DARKMESH_AAUTH_SUB (or DARKMESH_NODE_ID) must be set to the agent sub, "
            'e.g. "darkmesh-node@mark_local".'
        )
    iss = os.environ.get("DARKMESH_AAUTH_ISS", "https://darkmesh.local")
    kid = os.environ.get("DARKMESH_AAUTH_KID") or (
        private_jwk.get("kid") if isinstance(private_jwk.get("kid"), str) else None
    )
    ttl_raw = os.environ.get("DARKMESH_AAUTH_TOKEN_TTL_SEC", "300")
    try:
        ttl = max(30, int(ttl_raw))
    except ValueError:
        ttl = 300
    return SignerConfig(private_jwk=private_jwk, sub=sub, iss=iss, kid=kid, token_ttl_sec=ttl)


def _resolve_alg(private_jwk: Dict[str, Any]) -> str:
    alg = private_jwk.get("alg")
    if alg in {"ES256", "EdDSA"}:
        return alg
    kty = private_jwk.get("kty")
    crv = private_jwk.get("crv")
    if kty == "EC" and crv == "P-256":
        return "ES256"
    if kty == "OKP" and crv == "Ed25519":
        return "EdDSA"
    raise SignerConfigError(
        f"Unsupported JWK for AAuth signing (kty={kty!r}, crv={crv!r}, alg={alg!r}). "
        "AAuth requires ES256 (EC/P-256) or EdDSA (OKP/Ed25519)."
    )


def _public_part(private_jwk: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in private_jwk.items() if k not in {"d", "p", "q", "dp", "dq", "qi"}}


def jwk_thumbprint(private_jwk: Dict[str, Any]) -> str:
    """RFC 7638 thumbprint of the public part of the supplied JWK."""
    key = jwk.JWK(**private_jwk)
    return key.thumbprint()


def mint_agent_token_jwt(config: SignerConfig) -> str:
    """Mint an ``aa-agent+jwt`` token bound to the signing key.

    The token carries ``cnf.jwk`` (RFC 7800) with the *public* part of the
    signing key. Neotoma's verifier (via ``@hellocoop/httpsig`` with the
    ``jwt`` signature-key scheme) extracts ``cnf.jwk`` and uses it as the
    public key for RFC 9421 HTTP signature verification; the JWT itself is
    not signature-verified independently because the HTTP signature covers
    the ``signature-key`` header, so swapping JWTs in-flight is detectable.
    """
    alg = _resolve_alg(config.private_jwk)
    key = jwk.JWK(**config.private_jwk)
    jkt = key.thumbprint()
    header: Dict[str, Any] = {"alg": alg, "typ": "aa-agent+jwt"}
    if config.kid:
        header["kid"] = config.kid
    now = int(time.time())
    claims = {
        "sub": config.sub,
        "iss": config.iss,
        "iat": now,
        "exp": now + max(30, config.token_ttl_sec),
        "jkt": jkt,
        "cnf": {"jwk": _public_part(config.private_jwk)},
    }
    token = jwt.JWT(header=header, claims=claims)
    token.make_signed_token(key)
    return token.serialize()


def _content_digest(body: bytes) -> str:
    digest = hashlib.sha256(body).digest()
    return f"sha-256=:{base64.b64encode(digest).decode('ascii')}:"


class _SingleKeyResolver(HTTPSignatureKeyResolver):
    """Resolves the configured private JWK for signing; public is unused."""

    def __init__(self, private_key_obj: Any) -> None:
        self._private = private_key_obj

    def resolve_private_key(self, key_id: str) -> Any:
        return self._private

    def resolve_public_key(self, key_id: str) -> Any:
        raise NotImplementedError(
            "Darkmesh AAuth signer does not verify locally; Neotoma does that."
        )


def _private_key_for_sign(private_jwk: Dict[str, Any]) -> Tuple[Any, str]:
    """Return a cryptography private-key object usable by the signer and
    the RFC 9421 signature algorithm to use with it.
    """
    alg = _resolve_alg(private_jwk)
    key_obj = jwk.JWK(**private_jwk)
    pem = key_obj.export_to_pem(private_key=True, password=None)
    private = serialization.load_pem_private_key(pem, password=None)
    if alg == "ES256":
        return private, "ecdsa-p256-sha256"
    return private, "ed25519"


def signed_post(
    url: str,
    payload: Dict[str, Any],
    *,
    config: Optional[SignerConfig] = None,
    timeout: int = 20,
    extra_headers: Optional[Dict[str, str]] = None,
) -> requests.Response:
    """Sign and POST ``payload`` as JSON to ``url``.

    Covers ``@method``, ``@authority``, ``@path``, ``content-type``,
    ``content-digest``, and ``signature-key`` — the last is required by
    Neotoma's verifier (``strictAAuth: true``).

    Why ``@path`` rather than ``@target-uri``: Neotoma's verifier (via
    ``@hellocoop/httpsig``) recomputes ``@target-uri`` with a hardcoded
    ``https://`` prefix, so signing over the real request URL
    (``http://localhost:3080/...`` in local dev) yields a mismatched
    signature base and verification fails. ``@path`` is scheme-agnostic
    and matches hellocoop's ``DEFAULT_COMPONENTS_BODY`` profile.
    """
    cfg = config or load_signer_config_from_env()
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    digest = _content_digest(body)
    agent_jwt = mint_agent_token_jwt(cfg)
    thumbprint = jwk_thumbprint(cfg.private_jwk)

    req = requests.Request(
        method="POST",
        url=url,
        data=body,
        headers={
            "content-type": "application/json",
            "content-digest": digest,
            # RFC 8941 Structured Field Dictionary. The label (``aasig``)
            # must match the signature label below; the ``jwt`` scheme
            # carries the full ``aa-agent+jwt`` token whose ``cnf.jwk``
            # claim is the public key Neotoma will use to verify this HTTP
            # signature.
            "signature-key": f'aasig=jwt;jwt="{agent_jwt}"',
            "accept": "application/json",
            **(extra_headers or {}),
        },
    )
    prepared = req.prepare()

    private_key, alg_name = _private_key_for_sign(cfg.private_jwk)
    algorithm_map = {
        "ecdsa-p256-sha256": algorithms.ECDSA_P256_SHA256,
        "ed25519": algorithms.ED25519,
    }
    signer = HTTPMessageSigner(
        signature_algorithm=algorithm_map[alg_name],
        key_resolver=_SingleKeyResolver(private_key),
    )
    signer.sign(
        prepared,
        key_id=thumbprint,
        label="aasig",
        covered_component_ids=(
            "@method",
            "@authority",
            "@path",
            "content-type",
            "content-digest",
            "signature-key",
        ),
    )

    session = requests.Session()
    response = session.send(prepared, timeout=timeout)
    return response


def generate_es256_keypair() -> Dict[str, Dict[str, Any]]:
    """Generate a fresh ES256 keypair suitable for AAuth signing.

    Returns ``{"private_jwk": {...}, "public_jwk": {...}, "thumbprint": "..."}``.
    The ``kid`` on both JWKs is set to the RFC 7638 thumbprint so Neotoma
    and operators can correlate keys at a glance.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    pem_priv = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    priv_jwk_obj = jwk.JWK.from_pem(pem_priv)
    priv_jwk = json.loads(priv_jwk_obj.export(private_key=True))
    priv_jwk["alg"] = "ES256"
    pub_jwk = _public_part(priv_jwk)
    thumbprint = priv_jwk_obj.thumbprint()
    priv_jwk["kid"] = thumbprint
    pub_jwk["kid"] = thumbprint
    pub_jwk["alg"] = "ES256"
    return {"private_jwk": priv_jwk, "public_jwk": pub_jwk, "thumbprint": thumbprint}


def _cli() -> None:
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Darkmesh AAuth signer utilities.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    keygen = sub.add_parser("keygen", help="Generate an ES256 keypair and print JWKs.")
    keygen.add_argument("--private-out", help="Write private JWK to this path")
    keygen.add_argument("--public-out", help="Write public JWK to this path")
    keygen.add_argument("--force", action="store_true")

    thumb = sub.add_parser("thumbprint", help="Print the RFC 7638 thumbprint of the active key.")

    mint = sub.add_parser("mint-token", help="Print a fresh aa-agent+jwt for debugging.")

    args = parser.parse_args()

    if args.cmd == "keygen":
        pair = generate_es256_keypair()
        if args.private_out:
            path = Path(args.private_out)
            if path.exists() and not args.force:
                print(f"Refusing to overwrite existing {path} without --force", file=sys.stderr)
                sys.exit(2)
            path.write_text(json.dumps(pair["private_jwk"], indent=2), encoding="utf-8")
            os.chmod(path, 0o600)
        if args.public_out:
            Path(args.public_out).write_text(
                json.dumps(pair["public_jwk"], indent=2), encoding="utf-8"
            )
        print(json.dumps({
            "thumbprint": pair["thumbprint"],
            "public_jwk": pair["public_jwk"],
            "private_jwk": pair["private_jwk"] if not args.private_out else None,
        }, indent=2))
        return

    if args.cmd == "thumbprint":
        cfg = load_signer_config_from_env()
        print(jwk_thumbprint(cfg.private_jwk))
        return

    if args.cmd == "mint-token":
        cfg = load_signer_config_from_env()
        print(mint_agent_token_jwt(cfg))
        return


if __name__ == "__main__":
    _cli()
