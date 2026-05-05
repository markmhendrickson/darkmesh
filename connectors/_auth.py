"""Shared auth helper for Darkmesh connectors.

Each connector (``contacts_csv``, ``interactions_csv``, ``openclaw_sync``,
``neotoma_sync``) posts to a Darkmesh node's ``/darkmesh/ingest`` route.
Phase 3 lets operators run those connectors with either the legacy
HMAC node key or an AAuth-signed request so new operators no longer
need to cut a shared secret over a side channel.

This module centralises the picker:

* ``hmac`` — attach ``X-Darkmesh-Key`` from the connector's CLI flag /
  env var.
* ``aauth`` — sign the request with :func:`darkmesh.aauth_signer.signed_post`
  using the connector-specific ``sub`` (e.g. ``connector-csv-contacts@mark_local``).
* ``either`` (default) — use AAuth when the ``DARKMESH_AAUTH_PRIVATE_JWK``
  env material is present; otherwise fall back to HMAC.

Connectors accept a distinct sub so Darkmesh's trust registry can
authorise or revoke a connector without touching the node's own key.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import requests


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


from darkmesh.aauth_signer import (  # noqa: E402
    SignerConfig,
    SignerConfigError,
    load_signer_config_from_env,
)
from darkmesh.aauth_signer import signed_post as _signed_post  # noqa: E402


VALID_AUTH_MODES = ("hmac", "aauth", "either")


def add_auth_arguments(
    parser: argparse.ArgumentParser, *, default_sub: Optional[str] = None
) -> None:
    """Register the shared ``--node-key`` / ``--auth-mode`` / AAuth flags."""
    parser.add_argument(
        "--node-key",
        default=os.environ.get("DARKMESH_NODE_KEY", ""),
        help="Darkmesh node HMAC key (or set DARKMESH_NODE_KEY)",
    )
    parser.add_argument(
        "--auth-mode",
        choices=VALID_AUTH_MODES,
        default=os.environ.get("DARKMESH_AUTH_MODE", "either"),
        help=(
            "'hmac' keeps the pre-Phase-3 shared-secret path; 'aauth' "
            "requires DARKMESH_AAUTH_PRIVATE_JWK(_PATH) + sub; 'either' "
            "(default) uses AAuth when configured and falls back to HMAC."
        ),
    )
    parser.add_argument(
        "--aauth-private-jwk",
        default=os.environ.get("DARKMESH_AAUTH_PRIVATE_JWK_PATH", ""),
        help=(
            "Path to the connector's AAuth private JWK. Overrides "
            "DARKMESH_AAUTH_PRIVATE_JWK_PATH when provided."
        ),
    )
    parser.add_argument(
        "--aauth-sub",
        default=os.environ.get("DARKMESH_AAUTH_SUB", default_sub or ""),
        help=(
            "AAuth sub to mint into the agent token. Defaults to the "
            "connector's canonical sub (e.g. connector-csv-contacts@<operator>)."
        ),
    )
    parser.add_argument(
        "--aauth-iss",
        default=os.environ.get("DARKMESH_AAUTH_ISS", "https://darkmesh.local"),
        help="AAuth iss claim; defaults to https://darkmesh.local",
    )


class ConnectorAuth:
    """Resolve the auth scheme from parsed CLI args and expose a
    uniform ``post()`` helper for connectors.

    Constructing this object does a best-effort signer load. When
    ``auth_mode == "aauth"`` a load failure is fatal; when ``"either"``
    it is logged to stderr and the object silently drops back to HMAC.
    """

    def __init__(
        self,
        *,
        node_key: str,
        auth_mode: str,
        aauth_private_jwk_path: str,
        aauth_sub: str,
        aauth_iss: str,
        default_sub: Optional[str] = None,
    ) -> None:
        mode = (auth_mode or "either").lower()
        if mode not in VALID_AUTH_MODES:
            raise SystemExit(
                f"auth-mode must be one of {VALID_AUTH_MODES}; got {mode!r}"
            )
        self._mode = mode
        self._node_key = (node_key or "").strip()
        self._signer: Optional[SignerConfig] = None

        if mode != "hmac":
            try:
                if aauth_private_jwk_path:
                    os.environ["DARKMESH_AAUTH_PRIVATE_JWK_PATH"] = aauth_private_jwk_path
                sub = (aauth_sub or default_sub or "").strip()
                if sub:
                    os.environ["DARKMESH_AAUTH_SUB"] = sub
                if aauth_iss:
                    os.environ["DARKMESH_AAUTH_ISS"] = aauth_iss
                self._signer = load_signer_config_from_env()
            except SignerConfigError as exc:
                if mode == "aauth":
                    raise SystemExit(
                        f"auth-mode='aauth' requires a valid signer config: {exc}"
                    )
                self._signer = None

        if self._signer is None and mode != "aauth":
            # Fall back to HMAC — require the node-key in that case.
            if not self._node_key:
                raise SystemExit(
                    "node-key is required when AAuth is not configured "
                    "(pass --node-key, set DARKMESH_NODE_KEY, or configure "
                    "AAuth env vars)"
                )

    @classmethod
    def from_args(
        cls,
        args: argparse.Namespace,
        *,
        default_sub: Optional[str] = None,
    ) -> "ConnectorAuth":
        return cls(
            node_key=getattr(args, "node_key", ""),
            auth_mode=getattr(args, "auth_mode", "either"),
            aauth_private_jwk_path=getattr(args, "aauth_private_jwk", ""),
            aauth_sub=getattr(args, "aauth_sub", "") or (default_sub or ""),
            aauth_iss=getattr(args, "aauth_iss", "https://darkmesh.local"),
            default_sub=default_sub,
        )

    @property
    def mode_in_effect(self) -> str:
        """Returns ``'aauth'`` when a signer was loaded, else ``'hmac'``."""
        return "aauth" if self._signer is not None else "hmac"

    def post(
        self,
        url: str,
        payload: Dict[str, Any],
        *,
        timeout: int = 10,
    ) -> requests.Response:
        if self._signer is not None:
            return _signed_post(url, payload, config=self._signer, timeout=timeout)
        return requests.post(
            url,
            json=payload,
            headers={"X-Darkmesh-Key": self._node_key},
            timeout=timeout,
        )
