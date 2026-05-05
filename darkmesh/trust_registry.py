"""Darkmesh AAuth trust registry.

A trust registry is a JSON file that pins which public keys — identified
by RFC 7638 thumbprint — are allowed to call a given Darkmesh endpoint.
Each entry carries ``sub``, ``iss``, the full public JWK (for auditing
and thumbprint recomputation), and a list of capability strings used by
:meth:`TrustRegistry.permits` to gate routes.

Rationale
---------

We deliberately sidestep a JWKS ``.well-known`` endpoint for Phase 3.
Darkmesh nodes pair 1:1 with operators today; the trust-list size is
O(nodes-you-pair-with), which comfortably fits in a JSON file you can
inspect and edit by hand. A JWKS endpoint buys auto-discovery at the
cost of pushing key rotation onto a cache TTL, which is more moving
parts than the current fleet needs. :file:`docs/aauth_relay.md`
documents the upgrade path to a JWKS endpoint when that becomes worth
doing.

File shape
----------

.. code-block:: json

    {
      "version": 1,
      "agents": [
        {
          "thumbprint": "abc123...",
          "sub": "darkmesh-node@mark_local",
          "iss": "https://darkmesh.local",
          "public_jwk": {...},
          "capabilities": [
            "relay.register", "relay.publish", "relay.pull",
            "node.ingest", "node.callback", "node.query"
          ]
        }
      ]
    }

Wildcard capability (``*``) is allowed for first-party operator agents
that should reach every endpoint; see :meth:`permits`.

Hot reload
----------

:class:`TrustRegistry` watches the file's mtime on every lookup and
re-parses when it changes. An operator editing the trust list never
needs to restart the relay / node — they edit the file, save, and the
next inbound request sees the update. If the file is malformed the
old-good registry is retained and a warning is logged; this prevents a
fat-finger edit from locking the operator out of their own endpoints.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


logger = logging.getLogger(__name__)


class TrustRegistryError(RuntimeError):
    """Raised on unrecoverable trust-registry problems (missing file on
    explicit load, malformed schema at startup)."""


def _normalize_capabilities(raw: Any) -> Tuple[str, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, (list, tuple)):
        raise TrustRegistryError(
            f"capabilities must be a list, got {type(raw).__name__}"
        )
    out: List[str] = []
    for item in raw:
        if not isinstance(item, str):
            raise TrustRegistryError(
                f"capability entries must be strings, got {item!r}"
            )
        trimmed = item.strip()
        if trimmed:
            out.append(trimmed)
    return tuple(out)


def _normalize_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    thumbprint = entry.get("thumbprint")
    if not isinstance(thumbprint, str) or not thumbprint:
        raise TrustRegistryError("trust entry missing thumbprint")
    sub = entry.get("sub") or ""
    iss = entry.get("iss") or ""
    public_jwk = entry.get("public_jwk") or {}
    if not isinstance(public_jwk, dict):
        raise TrustRegistryError(
            f"trust entry {thumbprint!r} public_jwk must be an object"
        )
    capabilities = _normalize_capabilities(entry.get("capabilities"))
    # Disallow private-key material in the trust file; easy mistake to
    # paste a full JWK instead of the public part.
    if any(k in public_jwk for k in ("d", "p", "q", "dp", "dq", "qi")):
        raise TrustRegistryError(
            f"trust entry {thumbprint!r} public_jwk must not contain private key material"
        )
    return {
        "thumbprint": thumbprint,
        "sub": sub,
        "iss": iss,
        "public_jwk": public_jwk,
        "capabilities": capabilities,
        "label": entry.get("label") or sub or thumbprint,
    }


def _parse_registry(raw: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    if not isinstance(raw, dict):
        raise TrustRegistryError("trust registry root must be an object")
    agents = raw.get("agents")
    if agents is None:
        raise TrustRegistryError("trust registry missing `agents` array")
    if not isinstance(agents, list):
        raise TrustRegistryError("trust registry `agents` must be an array")
    by_thumbprint: Dict[str, Dict[str, Any]] = {}
    for entry in agents:
        if not isinstance(entry, dict):
            raise TrustRegistryError("agent entries must be objects")
        normalized = _normalize_entry(entry)
        by_thumbprint[normalized["thumbprint"]] = normalized
    return by_thumbprint


class TrustRegistry:
    """Thread-safe, hot-reloadable trust registry backed by a JSON file.

    Reads are O(1) (dict lookup) and lock-free once the registry has
    been parsed; writes by the file watcher are serialised under a lock
    so a concurrent reload cannot leave callers staring at a half-built
    dict.
    """

    def __init__(
        self,
        path: str,
        *,
        allow_missing: bool = False,
    ) -> None:
        self._path = os.path.abspath(path)
        self._allow_missing = allow_missing
        self._lock = threading.Lock()
        self._entries: Dict[str, Dict[str, Any]] = {}
        self._loaded_mtime: float = -1.0
        self._load(required=not allow_missing)

    @classmethod
    def empty(cls) -> "TrustRegistry":
        """Construct an empty registry (tests, AAuth-disabled nodes)."""
        obj = cls.__new__(cls)
        obj._path = ""
        obj._allow_missing = True
        obj._lock = threading.Lock()
        obj._entries = {}
        obj._loaded_mtime = -1.0
        return obj

    @property
    def path(self) -> str:
        return self._path

    def _load(self, *, required: bool) -> None:
        if not self._path:
            return
        try:
            stat = os.stat(self._path)
        except FileNotFoundError:
            if required:
                raise TrustRegistryError(
                    f"trust registry file not found: {self._path}"
                )
            logger.info("Trust registry file not present (yet): %s", self._path)
            with self._lock:
                self._entries = {}
                self._loaded_mtime = -1.0
            return
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            if required:
                raise TrustRegistryError(
                    f"Failed to load trust registry {self._path}: {exc}"
                ) from exc
            # Retain previous good registry; swallow for hot-reload.
            logger.warning(
                "Trust registry %s failed to reload; keeping previous snapshot: %s",
                self._path,
                exc,
            )
            return
        try:
            parsed = _parse_registry(raw)
        except TrustRegistryError as exc:
            if required:
                raise
            logger.warning(
                "Trust registry %s invalid; keeping previous snapshot: %s",
                self._path,
                exc,
            )
            return
        with self._lock:
            self._entries = parsed
            self._loaded_mtime = stat.st_mtime

    def _maybe_reload(self) -> None:
        if not self._path:
            return
        try:
            stat = os.stat(self._path)
        except FileNotFoundError:
            # If the file disappears after initial load we keep the
            # previous snapshot — losing the trust list is strictly
            # worse than serving stale-but-authorised traffic.
            return
        if stat.st_mtime != self._loaded_mtime:
            self._load(required=False)

    def reload(self) -> None:
        """Force a reload regardless of mtime (for SIGHUP handlers / tests)."""
        self._load(required=False)

    def lookup_by_thumbprint(self, thumbprint: str) -> Optional[Dict[str, Any]]:
        """Return the normalised entry for a thumbprint, or ``None``.

        Triggers a mtime-based reload if the underlying file has
        changed, so operators editing the JSON never need to bounce the
        process.
        """
        self._maybe_reload()
        with self._lock:
            entry = self._entries.get(thumbprint)
        if entry is None:
            return None
        # Return a shallow copy so callers cannot mutate the cached
        # dict and silently alter future lookups.
        return {
            "thumbprint": entry["thumbprint"],
            "sub": entry["sub"],
            "iss": entry["iss"],
            "public_jwk": dict(entry["public_jwk"]),
            "capabilities": entry["capabilities"],
            "label": entry["label"],
        }

    def permits(self, thumbprint: str, capability: str) -> bool:
        entry = self.lookup_by_thumbprint(thumbprint)
        if entry is None:
            return False
        caps: Sequence[str] = entry.get("capabilities") or ()
        if "*" in caps:
            return True
        return capability in caps

    def all_entries(self) -> List[Dict[str, Any]]:
        self._maybe_reload()
        with self._lock:
            return [
                {
                    "thumbprint": e["thumbprint"],
                    "sub": e["sub"],
                    "iss": e["iss"],
                    "public_jwk": dict(e["public_jwk"]),
                    "capabilities": e["capabilities"],
                    "label": e["label"],
                }
                for e in self._entries.values()
            ]

    def __len__(self) -> int:
        self._maybe_reload()
        with self._lock:
            return len(self._entries)


def load_trust_registry_from_env(
    env_var: str = "DARKMESH_TRUSTED_AGENTS_FILE",
    *,
    default_path: Optional[str] = None,
    allow_missing: bool = True,
) -> TrustRegistry:
    """Load a :class:`TrustRegistry` from an env-var path.

    ``allow_missing=True`` makes a missing file a soft failure so a node
    running in ``auth_mode=hmac`` can boot without a trust file.
    """
    path = os.environ.get(env_var) or default_path or ""
    if not path:
        return TrustRegistry.empty()
    return TrustRegistry(path, allow_missing=allow_missing)


def write_trust_registry(path: str, entries: Iterable[Dict[str, Any]]) -> None:
    """Persist ``entries`` to ``path``, normalising each entry.

    Used by :file:`scripts/darkmesh_trust_add.py`; collected here so the
    CLI helper and tests share a single serialisation path.
    """
    normalized = [_normalize_entry(dict(e)) for e in entries]
    payload = {
        "version": 1,
        "agents": [
            {
                "thumbprint": e["thumbprint"],
                "sub": e["sub"],
                "iss": e["iss"],
                "public_jwk": e["public_jwk"],
                "capabilities": list(e["capabilities"]),
                **({"label": e["label"]} if e.get("label") else {}),
            }
            for e in normalized
        ],
    }
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=False)
        f.write("\n")
    os.replace(tmp, target)


__all__ = [
    "TrustRegistry",
    "TrustRegistryError",
    "load_trust_registry_from_env",
    "write_trust_registry",
]
