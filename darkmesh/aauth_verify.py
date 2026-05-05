"""Python AAuth verifier for inbound Darkmesh requests.

Mirrors Neotoma's ``src/middleware/aauth_verify.ts`` but targets the same
RFC 9421 + AAuth profile that :mod:`darkmesh.aauth_signer` produces. The
two profiles are deliberately symmetric:

- Covered components: ``@method``, ``@authority``, ``@path``,
  ``content-type``, ``content-digest``, ``signature-key``.
- Signature label: ``aasig`` (matches the signer).
- ``Signature-Key`` carries a single dictionary entry
  ``aasig=jwt;jwt="<aa-agent+jwt>"``. The verifier extracts ``cnf.jwk``
  (RFC 7800) from the JWT and treats it as the public key; the JWT itself
  is not independently signature-verified because the HTTP signature
  already covers ``signature-key``, so swapping JWTs in-flight is
  detectable.

Why ``@path`` (not ``@target-uri``): Neotoma's verifier recomputes
``@target-uri`` with a hardcoded ``https://`` prefix, and Darkmesh's
signer works around that by signing ``@path`` only. The verifier here
matches the signer's covered-component set so the same wire form round-
trips cleanly.

Trust boundary: verification succeeds only when the JWK thumbprint
matches an entry in :mod:`darkmesh.trust_registry`. Unknown thumbprints
raise :class:`AAuthVerifyError` — there is no fall-through to anonymous.
Capability enforcement happens at the call site, via
:meth:`TrustRegistry.permits` / :class:`VerifiedAgent.has_capability`.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from http_message_signatures import HTTPMessageVerifier, HTTPSignatureKeyResolver, algorithms
from http_message_signatures.exceptions import HTTPMessageSignaturesException
from jwcrypto import jwk
from requests.structures import CaseInsensitiveDict as _CaseInsensitiveDict


# Signature-Input / Signature / Signature-Key all denote an AAuth-signed
# request. Presence of any of them routes the request through the
# verifier; absence short-circuits to the HMAC fallback (or outright
# rejection when ``auth_mode == "aauth"``).
AAUTH_HEADERS: Tuple[str, ...] = ("signature", "signature-input", "signature-key")

# Maximum iat/exp skew the verifier will tolerate on the agent-token JWT,
# in seconds. Matches Neotoma's 60s default. Replay protection on the
# HTTP signature itself is handled by ``max_age`` on HTTPMessageVerifier.
DEFAULT_JWT_CLOCK_SKEW_SEC = 60

# Default RFC 9421 ``created`` freshness window. Five minutes is
# comfortably above the agent-token TTL floor (30s) and the signer's
# default TTL (300s).
DEFAULT_MAX_AGE_SEC = 300

_COVERED_COMPONENTS: Tuple[str, ...] = (
    "@method",
    "@authority",
    "@path",
    "content-type",
    "content-digest",
    "signature-key",
)


class AAuthVerifyError(Exception):
    """Raised when an AAuth-signed request fails verification.

    The :attr:`reason` attribute is a stable machine-readable code
    (``signature_invalid``, ``jwt_expired``, ``unknown_thumbprint`` …)
    suitable for logs and HTTP error envelopes. Humans should surface
    the full exception message; callers that gate rollouts on a specific
    failure class should match on :attr:`reason`.
    """

    def __init__(self, reason: str, message: Optional[str] = None) -> None:
        super().__init__(message or reason)
        self.reason = reason


@dataclass
class VerifiedAgent:
    """Result of a successful AAuth verification.

    Callers attach this to the request-local state so downstream
    handlers (and provenance stamps) can read ``sub`` / ``iss`` /
    ``thumbprint`` without re-parsing headers.
    """

    sub: str
    iss: str
    thumbprint: str
    public_jwk: Dict[str, Any]
    algorithm: str
    capabilities: Tuple[str, ...] = ()
    jwt_iat: Optional[int] = None
    jwt_exp: Optional[int] = None

    def has_capability(self, capability: str) -> bool:
        # Capability names are hierarchical: a registry entry with
        # ``relay.*`` or the exact string matches. Wildcards are resolved
        # by :class:`TrustRegistry`, which normalises them to a flat list
        # when it loads the file, so the check here is a simple membership
        # test plus ``*`` as an explicit god-mode entry.
        if "*" in self.capabilities:
            return True
        return capability in self.capabilities


def has_aauth_headers(headers: Mapping[str, str]) -> bool:
    """Return True when any AAuth-identifying header is present.

    Case-insensitive; callers typically pass a Starlette
    ``request.headers`` which already lowercases keys.
    """
    lowered = {k.lower() for k in headers.keys()}
    return any(h in lowered for h in AAUTH_HEADERS)


def _b64url_decode(data: str) -> bytes:
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data = data + ("=" * padding)
    return base64.urlsafe_b64decode(data.encode("ascii"))


def _decode_jwt_unverified(token: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    parts = token.split(".")
    if len(parts) != 3:
        raise AAuthVerifyError("jwt_malformed", f"JWT must have 3 parts, got {len(parts)}")
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, json.JSONDecodeError) as exc:
        raise AAuthVerifyError("jwt_decode_failed", f"JWT decode failed: {exc}") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise AAuthVerifyError("jwt_malformed", "JWT header/payload is not an object")
    return header, payload


def _parse_signature_key_header(raw: str) -> str:
    """Extract the ``jwt`` parameter from a ``Signature-Key`` header.

    The signer emits ``aasig=jwt;jwt="<token>"`` (RFC 8941 structured
    dictionary). We parse by hand here — the ``http_sfv`` helpers are
    overkill for a single-entry dictionary and would drag another bit
    of surface into the verifier.
    """
    raw = (raw or "").strip()
    if not raw:
        raise AAuthVerifyError("signature_key_missing", "Signature-Key header missing")
    # Strip off the label up to '=', then look for ;jwt="..." parameter.
    # We accept either ``aasig=jwt;jwt="..."`` or a bare
    # ``jwt=;jwt="..."`` — any label is fine so long as the ``jwt=``
    # parameter exists, because the verifier binds by label from the
    # ``Signature`` header below.
    lowered = raw.lower()
    marker = "jwt="
    idx = lowered.find(marker + '"')
    if idx < 0:
        # Also accept a backtick-quoted / unquoted form just in case.
        idx = lowered.find(marker)
        if idx < 0:
            raise AAuthVerifyError(
                "signature_key_malformed",
                "Signature-Key header has no jwt=... parameter",
            )
        start = idx + len(marker)
        token = raw[start:].split(";", 1)[0].strip().strip('"')
    else:
        start = idx + len(marker) + 1
        end = raw.find('"', start)
        if end < 0:
            raise AAuthVerifyError(
                "signature_key_malformed",
                "Signature-Key header has unterminated quoted jwt",
            )
        token = raw[start:end]
    if not token:
        raise AAuthVerifyError("signature_key_malformed", "Signature-Key jwt parameter is empty")
    return token


def _public_key_from_jwk(public_jwk: Dict[str, Any]) -> Tuple[Any, str]:
    """Return (cryptography public-key, RFC 9421 algorithm name)."""
    try:
        key_obj = jwk.JWK(**public_jwk)
    except Exception as exc:  # noqa: BLE001 -- jwcrypto raises various things
        raise AAuthVerifyError("cnf_jwk_malformed", f"cnf.jwk is not a valid JWK: {exc}") from exc
    try:
        pem = key_obj.export_to_pem(private_key=False)
    except Exception as exc:  # noqa: BLE001
        raise AAuthVerifyError(
            "cnf_jwk_not_public",
            f"cnf.jwk does not expose a public key: {exc}",
        ) from exc
    public = serialization.load_pem_public_key(pem)

    kty = public_jwk.get("kty")
    crv = public_jwk.get("crv")
    alg = public_jwk.get("alg")
    if kty == "EC" and crv == "P-256":
        return public, "ecdsa-p256-sha256"
    if kty == "OKP" and crv == "Ed25519":
        return public, "ed25519"
    raise AAuthVerifyError(
        "cnf_jwk_unsupported",
        f"Unsupported JWK (kty={kty!r}, crv={crv!r}, alg={alg!r}); "
        "AAuth accepts ES256 (EC/P-256) or EdDSA (OKP/Ed25519).",
    )


def _compute_jwk_thumbprint(public_jwk: Dict[str, Any]) -> str:
    try:
        return jwk.JWK(**public_jwk).thumbprint()
    except Exception as exc:  # noqa: BLE001
        raise AAuthVerifyError("thumbprint_failed", f"thumbprint() failed: {exc}") from exc


def _verify_content_digest(headers: Mapping[str, str], body: bytes) -> None:
    # Header lookup is case-insensitive; we accept the Starlette
    # lower-case convention without being strict about it.
    digest_value = None
    for key, value in headers.items():
        if key.lower() == "content-digest":
            digest_value = value
            break
    if not digest_value:
        raise AAuthVerifyError(
            "content_digest_missing",
            "content-digest header missing; the signer always emits one",
        )
    # ``sha-256=:<base64>:`` structured-field item.
    raw = digest_value.strip()
    prefix = "sha-256=:"
    if not raw.lower().startswith(prefix):
        raise AAuthVerifyError(
            "content_digest_unsupported",
            f"content-digest must start with {prefix!r}; got {raw[:32]!r}",
        )
    end = raw.find(":", len(prefix))
    if end < 0:
        raise AAuthVerifyError("content_digest_malformed", "content-digest missing closing ':'")
    encoded = raw[len(prefix):end]
    try:
        expected = base64.b64decode(encoded.encode("ascii"))
    except Exception as exc:  # noqa: BLE001
        raise AAuthVerifyError("content_digest_malformed", f"content-digest b64 decode failed: {exc}") from exc
    actual = hashlib.sha256(body).digest()
    if expected != actual:
        raise AAuthVerifyError(
            "content_digest_mismatch",
            "content-digest does not match sha-256 of request body",
        )


class _SingleKeyResolver(HTTPSignatureKeyResolver):
    """Resolves a single public key for verification.

    RFC 9421 requires a ``keyid`` in the ``Signature-Input`` params; the
    signer uses the JWK thumbprint, so the verifier ignores ``key_id``
    (we already pinned the key via the JWT's ``cnf.jwk``) and returns the
    one key we care about.
    """

    def __init__(self, public_key: Any) -> None:
        self._public = public_key

    def resolve_public_key(self, key_id: str) -> Any:
        return self._public

    def resolve_private_key(self, key_id: str) -> Any:
        raise NotImplementedError("verifier resolver does not sign")


class _VerifyMessage:
    """Minimal message adapter for HTTPMessageVerifier.

    The verifier expects an object with ``.method`` (str), ``.url``
    (str-stringifiable), and ``.headers`` (mapping). It uses
    ``urlsplit(str(url)).path`` to derive ``@path`` and ``.netloc`` for
    ``@authority``.
    """

    def __init__(self, *, method: str, url: str, headers: Mapping[str, str]) -> None:
        self.method = method.upper()
        self.url = url
        # HTTPMessageVerifier does case-sensitive lookups against the
        # message's ``headers`` mapping (e.g. ``"Signature-Input" in
        # headers``). Starlette — and therefore the FastAPI middleware
        # that calls into us — normalises incoming headers to lowercase
        # per ASGI, so a plain ``dict(headers)`` silently misses the
        # signature fields. Wrap in ``requests.CaseInsensitiveDict`` so
        # lookups succeed regardless of input casing.
        self.headers = _CaseInsensitiveDict(headers)


def verify_request(
    *,
    method: str,
    url: str,
    headers: Mapping[str, str],
    body: bytes,
    trust_registry: "TrustRegistryProtocol",
    max_age_sec: int = DEFAULT_MAX_AGE_SEC,
    clock_skew_sec: int = DEFAULT_JWT_CLOCK_SKEW_SEC,
    now: Optional[int] = None,
) -> VerifiedAgent:
    """Verify an RFC 9421 + AAuth-profile HTTP signature.

    ``url`` should be the full request URL as the server sees it,
    including scheme, host, and port — the ``@authority`` component is
    derived from ``urlsplit(url).netloc``. Passing only a path will
    cause signature verification to fail.

    Raises :class:`AAuthVerifyError` on any failure (missing headers,
    JWT expired, thumbprint not in trust registry, signature mismatch).
    """
    now = int(now if now is not None else time.time())

    # ----- Stage 1: parse Signature-Key header + JWT (cheap, rejects
    # malformed requests before we spend CPU on signature math) -----
    signature_key_header: Optional[str] = None
    for key, value in headers.items():
        if key.lower() == "signature-key":
            signature_key_header = value
            break
    if not signature_key_header:
        raise AAuthVerifyError(
            "signature_key_missing",
            "Signature-Key header required for AAuth profile",
        )
    agent_jwt = _parse_signature_key_header(signature_key_header)
    jwt_header, jwt_payload = _decode_jwt_unverified(agent_jwt)

    typ = jwt_header.get("typ")
    if typ != "aa-agent+jwt":
        raise AAuthVerifyError("jwt_typ_invalid", f"Unexpected JWT typ: {typ!r}")

    sub = jwt_payload.get("sub")
    iss = jwt_payload.get("iss")
    if not isinstance(sub, str) or not sub:
        raise AAuthVerifyError("jwt_sub_missing", "JWT missing sub claim")
    if not isinstance(iss, str) or not iss:
        raise AAuthVerifyError("jwt_iss_missing", "JWT missing iss claim")

    iat = jwt_payload.get("iat") if isinstance(jwt_payload.get("iat"), int) else None
    exp = jwt_payload.get("exp") if isinstance(jwt_payload.get("exp"), int) else None
    if iat is not None and iat - clock_skew_sec > now:
        raise AAuthVerifyError("jwt_iat_future", f"JWT iat={iat} is in the future")
    if exp is not None and exp + clock_skew_sec < now:
        raise AAuthVerifyError("jwt_expired", f"JWT exp={exp} is in the past")

    cnf = jwt_payload.get("cnf")
    if not isinstance(cnf, dict) or not isinstance(cnf.get("jwk"), dict):
        raise AAuthVerifyError(
            "cnf_jwk_missing",
            "JWT must carry cnf.jwk (RFC 7800) with the signing key",
        )
    public_jwk: Dict[str, Any] = dict(cnf["jwk"])
    if "d" in public_jwk or any(k in public_jwk for k in ("p", "q", "dp", "dq", "qi")):
        raise AAuthVerifyError(
            "cnf_jwk_private",
            "cnf.jwk must not contain private key material",
        )

    # ----- Stage 2: trust-registry lookup by thumbprint. We do this
    # BEFORE signature verification so we can reject unknown keys
    # quickly (and without surfacing a key-parse error path attackers
    # could probe). -----
    thumbprint = _compute_jwk_thumbprint(public_jwk)
    declared_jkt = jwt_payload.get("jkt")
    if isinstance(declared_jkt, str) and declared_jkt and declared_jkt != thumbprint:
        raise AAuthVerifyError(
            "jwt_jkt_mismatch",
            "JWT jkt does not match cnf.jwk thumbprint",
        )

    entry = trust_registry.lookup_by_thumbprint(thumbprint)
    if entry is None:
        raise AAuthVerifyError(
            "unknown_thumbprint",
            f"JWK thumbprint {thumbprint!r} is not in the trust registry",
        )

    # Optional sub/iss pinning. Most deployments pin sub in the registry
    # so a stolen key cannot claim a different identity; iss pinning is
    # looser because many deployments share ``https://darkmesh.local``.
    if entry.get("sub") and entry["sub"] != sub:
        raise AAuthVerifyError(
            "sub_mismatch",
            f"JWT sub={sub!r} does not match registered sub for thumbprint",
        )
    if entry.get("iss") and entry["iss"] != iss:
        raise AAuthVerifyError(
            "iss_mismatch",
            f"JWT iss={iss!r} does not match registered iss for thumbprint",
        )

    # ----- Stage 3: content-digest integrity (cheap hash) -----
    _verify_content_digest(headers, body)

    # ----- Stage 4: RFC 9421 signature verification -----
    public_key_obj, alg_name = _public_key_from_jwk(public_jwk)
    algorithm_map = {
        "ecdsa-p256-sha256": algorithms.ECDSA_P256_SHA256,
        "ed25519": algorithms.ED25519,
    }
    verifier = HTTPMessageVerifier(
        signature_algorithm=algorithm_map[alg_name],
        key_resolver=_SingleKeyResolver(public_key_obj),
    )
    message = _VerifyMessage(method=method, url=url, headers=headers)
    try:
        import datetime as _dt
        results = verifier.verify(
            message,
            max_age=_dt.timedelta(seconds=max_age_sec),
        )
    except HTTPMessageSignaturesException as exc:
        raise AAuthVerifyError("signature_invalid", f"Signature verification failed: {exc}") from exc
    except Exception as exc:  # noqa: BLE001 -- defensive; library can raise ValueError etc.
        raise AAuthVerifyError("signature_invalid", f"Signature verification error: {exc}") from exc

    if not results:
        raise AAuthVerifyError(
            "signature_missing",
            "Signature header present but no verifiable signatures found",
        )

    # Check covered-component coverage matches the AAuth profile. If the
    # signer stripped a required component (e.g. ``signature-key``), the
    # server MUST reject — otherwise an attacker could omit
    # ``content-digest`` and tamper with the body. Equivalent to
    # Neotoma's ``strictAAuth: true``.
    missing: List[str] = []
    aasig_result = None
    for result in results:
        covered = _collect_covered_component_ids(result)
        for comp in _COVERED_COMPONENTS:
            if comp not in covered:
                missing.append(f"{getattr(result, 'label', '?')}:{comp}")
        if getattr(result, "label", None) == "aasig" and not missing:
            aasig_result = result
    if missing:
        raise AAuthVerifyError(
            "signature_covered_components_incomplete",
            f"Required covered components missing: {sorted(set(missing))}",
        )
    # If the signer used a different label we still accept the first
    # complete result — label binding is cosmetic for single-signature
    # requests, but we prefer ``aasig`` for diagnostic consistency.
    if aasig_result is None:
        aasig_result = results[0]

    capabilities = tuple(entry.get("capabilities") or ())
    return VerifiedAgent(
        sub=sub,
        iss=iss,
        thumbprint=thumbprint,
        public_jwk=public_jwk,
        algorithm=alg_name,
        capabilities=capabilities,
        jwt_iat=iat,
        jwt_exp=exp,
    )


def _collect_covered_component_ids(result: Any) -> Iterable[str]:
    """Pull covered-component identifiers off a VerifyResult.

    The http-message-signatures library exposes them as a list of
    ``http_sfv.InnerList`` items under ``result.covered_components`` on
    some versions and ``result.signature_input`` on others. We try both
    and fall back to parsing the raw ``Signature-Input`` header value
    the library stashes.
    """
    covered = getattr(result, "covered_components", None)
    if covered is None:
        covered = getattr(result, "signature_input", None)
    ids: List[str] = []
    if covered is None:
        return ids
    # covered may be a dict-like with .keys() of Item objects or a list
    # of Item objects.
    try:
        iterable = covered.keys() if hasattr(covered, "keys") else covered
    except Exception:  # noqa: BLE001
        iterable = []
    for item in iterable:
        value = getattr(item, "value", item)
        text = str(value)
        # The library serialises keys with their RFC 8941 sf-string
        # quoting intact (``"@method"``). Strip a single layer of
        # double quotes so the caller can compare against bare
        # component ids (``@method``).
        if len(text) >= 2 and text.startswith('"') and text.endswith('"'):
            text = text[1:-1]
        ids.append(text)
    return ids


class TrustRegistryProtocol:  # pragma: no cover -- duck-typed interface
    """Structural typing shim for :class:`darkmesh.trust_registry.TrustRegistry`.

    Kept as a bare class instead of :class:`typing.Protocol` so the
    verifier module is importable without pulling ``typing_extensions``
    on older Pythons and so test fakes can subclass it for clarity.
    """

    def lookup_by_thumbprint(self, thumbprint: str) -> Optional[Dict[str, Any]]:
        raise NotImplementedError


__all__ = [
    "AAUTH_HEADERS",
    "AAuthVerifyError",
    "DEFAULT_JWT_CLOCK_SKEW_SEC",
    "DEFAULT_MAX_AGE_SEC",
    "TrustRegistryProtocol",
    "VerifiedAgent",
    "has_aauth_headers",
    "verify_request",
]
