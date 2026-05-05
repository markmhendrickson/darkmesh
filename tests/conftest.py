"""Shared pytest fixtures for Darkmesh unit + integration tests.

Keeps signer setup, trust-registry builders, and the Darkmesh/relay
test-harness wiring in one place so each test file can focus on its
assertion instead of boilerplate.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, Tuple

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture
def es256_keypair() -> Dict[str, Any]:
    from darkmesh.aauth_signer import generate_es256_keypair

    return generate_es256_keypair()


@pytest.fixture
def second_keypair() -> Dict[str, Any]:
    from darkmesh.aauth_signer import generate_es256_keypair

    return generate_es256_keypair()


@pytest.fixture
def signer_config(es256_keypair: Dict[str, Any]):
    from darkmesh.aauth_signer import SignerConfig

    return SignerConfig(
        private_jwk=es256_keypair["private_jwk"],
        sub="darkmesh-test@unit",
        iss="https://darkmesh.local",
        token_ttl_sec=120,
    )


def _write_trust_file(
    path: Path,
    entries: Any,
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"version": 1, "agents": list(entries)}, indent=2))
    return path


@pytest.fixture
def trust_file_factory(tmp_path: Path):
    def _factory(entries: Any, *, name: str = "trusted_agents.json") -> Path:
        return _write_trust_file(tmp_path / name, entries)

    return _factory


@pytest.fixture
def trust_registry_with(trust_file_factory):
    from darkmesh.trust_registry import TrustRegistry

    def _build(entries: Any) -> Tuple[TrustRegistry, Path]:
        path = trust_file_factory(entries)
        return TrustRegistry(str(path)), path

    return _build
