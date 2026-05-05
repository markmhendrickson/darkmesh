"""Unit tests for :mod:`scripts.neotoma_grants_provision`.

Covers the five admission-release scenarios called out in
``docs/neotoma_integration.md`` and the Darkmesh grants migration plan:

1. **create**   — first-run provisioning with no existing grant.
2. **noop**     — rerun against an already-up-to-date grant.
3. **update**   — capability diff between seed and stored grant.
4. **bearer rejection** — Neotoma returns 401/403 on the operator's token.
5. **404 from /agents/grants** — pre-admission Neotoma still on <0.9.

The unit tests stub :mod:`requests` so we never touch the network and
never require a real Neotoma instance. The script is invoked through
its public :func:`provision` entry point so we can assert structured
result dicts rather than parsing stdout.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import patch

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "neotoma_grants_provision.py"


def _load_module():
    """Import the provisioning script as a module without polluting sys.path."""
    spec = importlib.util.spec_from_file_location(
        "neotoma_grants_provision", SCRIPT_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


provision_module = _load_module()
provision = provision_module.provision
ProvisionError = provision_module.ProvisionError


SEED_BODY: Dict[str, Any] = {
    "_neotoma_min_version": "0.9.0",
    "agents": {
        "darkmesh-node@mark_local": {
            "match": {
                "sub": "darkmesh-node@mark_local",
                "iss": "https://darkmesh.local",
            },
            "capabilities": [
                {
                    "op": "store_structured",
                    "entity_types": ["warm_intro_reveal", "warm_intro_request"],
                },
                {"op": "retrieve", "entity_types": ["contact"]},
            ],
        }
    },
}


@pytest.fixture
def seed_path(tmp_path: Path) -> Path:
    path = tmp_path / "neotoma_agent_capabilities.json"
    path.write_text(json.dumps(SEED_BODY))
    return path


class _FakeResponse:
    """Minimal stand-in for ``requests.Response`` used by the script."""

    def __init__(
        self,
        *,
        status_code: int = 200,
        body: Optional[Dict[str, Any]] = None,
        url: str = "http://neotoma.test/agents/grants",
        text: str = "",
    ) -> None:
        self.status_code = status_code
        self._body = body or {}
        self.url = url
        self.text = text or json.dumps(self._body)

    def json(self) -> Any:
        return self._body


def _identity() -> Dict[str, str]:
    return {
        "sub": "darkmesh-node@mark_local",
        "iss": "https://darkmesh.local",
        "thumbprint": "thumb_abc",
    }


def _stub_requests(
    monkeypatch: pytest.MonkeyPatch,
    *,
    get: Optional[List[_FakeResponse]] = None,
    post: Optional[List[_FakeResponse]] = None,
    patch_resp: Optional[List[_FakeResponse]] = None,
) -> Dict[str, List[Tuple[str, Dict[str, Any]]]]:
    """Patch ``requests.get/post/patch`` with deterministic queues.

    Returns a recorder dict the test can assert on.
    """
    recorder: Dict[str, List[Tuple[str, Dict[str, Any]]]] = {
        "GET": [],
        "POST": [],
        "PATCH": [],
    }
    queues = {
        "GET": list(get or []),
        "POST": list(post or []),
        "PATCH": list(patch_resp or []),
    }

    def _factory(method: str):
        def _impl(url: str, **kwargs: Any) -> _FakeResponse:
            recorder[method].append((url, kwargs))
            queue = queues[method]
            if not queue:
                raise AssertionError(
                    f"unexpected {method} {url}; no more stubbed responses"
                )
            return queue.pop(0)

        return _impl

    monkeypatch.setattr(provision_module.requests, "get", _factory("GET"))
    monkeypatch.setattr(provision_module.requests, "post", _factory("POST"))
    monkeypatch.setattr(provision_module.requests, "patch", _factory("PATCH"))
    return recorder


def _provision(seed_path: Path, **overrides: Any) -> Dict[str, Any]:
    ident = _identity()
    base_kwargs: Dict[str, Any] = {
        "seed_path": str(seed_path),
        "base_url": "http://neotoma.test",
        "token": "test-bearer",
        "sub": ident["sub"],
        "iss": ident["iss"],
        "thumbprint": ident["thumbprint"],
        "user_id": None,
        "label_override": None,
        "allow_create": False,
        "allow_update": False,
        "dry_run": False,
    }
    base_kwargs.update(overrides)
    return provision(**base_kwargs)


def test_create_when_no_existing_grant(
    monkeypatch: pytest.MonkeyPatch, seed_path: Path
) -> None:
    recorder = _stub_requests(
        monkeypatch,
        get=[_FakeResponse(body={"grants": []})],
        post=[
            _FakeResponse(
                status_code=201,
                body={
                    "grant": {
                        "grant_id": "ent_grant_new",
                        "match_sub": "darkmesh-node@mark_local",
                        "match_iss": "https://darkmesh.local",
                        "match_thumbprint": "thumb_abc",
                    }
                },
            )
        ],
    )
    result = _provision(seed_path, allow_create=True)

    assert result["action"] == "create"
    assert result["applied"] is True
    assert result["grant_id"] == "ent_grant_new"
    assert recorder["GET"][0][0] == "http://neotoma.test/agents/grants"
    assert recorder["POST"][0][0] == "http://neotoma.test/agents/grants"
    posted = json.loads(recorder["POST"][0][1]["data"])
    assert posted["match_sub"] == "darkmesh-node@mark_local"
    assert posted["match_iss"] == "https://darkmesh.local"
    assert posted["match_thumbprint"] == "thumb_abc"
    assert {"op": "retrieve", "entity_types": ["contact"]} in posted["capabilities"]


def test_create_dry_run_skips_post(
    monkeypatch: pytest.MonkeyPatch, seed_path: Path
) -> None:
    recorder = _stub_requests(
        monkeypatch,
        get=[_FakeResponse(body={"grants": []})],
    )
    result = _provision(seed_path, allow_create=True, dry_run=True)

    assert result["action"] == "create"
    assert result["applied"] is False
    assert recorder["POST"] == []


def test_noop_when_grant_matches_seed(
    monkeypatch: pytest.MonkeyPatch, seed_path: Path
) -> None:
    existing = {
        "grant_id": "ent_grant_existing",
        "label": "Darkmesh node darkmesh-node@mark_local",
        "match_sub": "darkmesh-node@mark_local",
        "match_iss": "https://darkmesh.local",
        "match_thumbprint": "thumb_abc",
        "capabilities": [
            {
                "op": "store_structured",
                "entity_types": ["warm_intro_reveal", "warm_intro_request"],
            },
            {"op": "retrieve", "entity_types": ["contact"]},
        ],
        "status": "active",
    }
    recorder = _stub_requests(
        monkeypatch, get=[_FakeResponse(body={"grants": [existing]})]
    )
    result = _provision(seed_path, allow_create=True, allow_update=True)

    assert result["action"] == "noop"
    assert result["applied"] is True
    assert result["grant_id"] == "ent_grant_existing"
    assert recorder["POST"] == []
    assert recorder["PATCH"] == []


def test_update_when_capabilities_diverge(
    monkeypatch: pytest.MonkeyPatch, seed_path: Path
) -> None:
    existing = {
        "grant_id": "ent_grant_existing",
        "label": "Darkmesh node darkmesh-node@mark_local",
        "match_sub": "darkmesh-node@mark_local",
        "match_iss": "https://darkmesh.local",
        "match_thumbprint": "thumb_abc",
        "capabilities": [
            {"op": "store_structured", "entity_types": ["warm_intro_reveal"]},
            {"op": "retrieve", "entity_types": ["contact"]},
        ],
        "status": "active",
    }
    updated = {**existing, "capabilities": SEED_BODY["agents"]["darkmesh-node@mark_local"]["capabilities"]}
    recorder = _stub_requests(
        monkeypatch,
        get=[_FakeResponse(body={"grants": [existing]})],
        patch_resp=[_FakeResponse(status_code=200, body={"grant": updated})],
    )
    result = _provision(seed_path, allow_update=True)

    assert result["action"] == "update"
    assert result["applied"] is True
    assert "capabilities" in result["diff"]
    assert recorder["PATCH"][0][0] == (
        "http://neotoma.test/agents/grants/ent_grant_existing"
    )
    body = json.loads(recorder["PATCH"][0][1]["data"])
    assert any(
        cap["op"] == "store_structured"
        and "warm_intro_request" in cap["entity_types"]
        for cap in body["capabilities"]
    )


def test_update_dry_run_returns_diff_without_patch(
    monkeypatch: pytest.MonkeyPatch, seed_path: Path
) -> None:
    existing = {
        "grant_id": "ent_grant_existing",
        "label": "Darkmesh node darkmesh-node@mark_local",
        "match_sub": "darkmesh-node@mark_local",
        "match_iss": "https://darkmesh.local",
        "match_thumbprint": "thumb_abc",
        "capabilities": [{"op": "retrieve", "entity_types": ["contact"]}],
        "status": "active",
    }
    recorder = _stub_requests(
        monkeypatch,
        get=[_FakeResponse(body={"grants": [existing]})],
    )
    result = _provision(seed_path, allow_update=True, dry_run=True)

    assert result["action"] == "update"
    assert result["applied"] is False
    assert recorder["PATCH"] == []


def test_bearer_rejection_surfaces_friendly_error(
    monkeypatch: pytest.MonkeyPatch, seed_path: Path
) -> None:
    _stub_requests(
        monkeypatch,
        get=[_FakeResponse(status_code=401, text="Unauthorized")],
    )
    with pytest.raises(ProvisionError) as info:
        _provision(seed_path, allow_create=True)
    msg = str(info.value)
    assert "Bearer" in msg
    assert "Inspector" in msg


def test_pre_admission_neotoma_404(
    monkeypatch: pytest.MonkeyPatch, seed_path: Path
) -> None:
    _stub_requests(
        monkeypatch,
        get=[
            _FakeResponse(
                status_code=404,
                text="Not Found",
                url="http://neotoma.test/agents/grants",
            )
        ],
    )
    with pytest.raises(ProvisionError) as info:
        _provision(seed_path, allow_create=True)
    msg = str(info.value)
    assert "Stronger AAuth Admission" in msg
    assert ">= 0.9.0" in msg


def test_seed_missing_entry_for_sub(
    monkeypatch: pytest.MonkeyPatch, seed_path: Path
) -> None:
    _stub_requests(monkeypatch)
    with pytest.raises(ProvisionError) as info:
        _provision(seed_path, sub="darkmesh-node@unknown")
    assert "no entry for sub" in str(info.value)


def test_capability_normalization_is_order_insensitive(
    monkeypatch: pytest.MonkeyPatch, seed_path: Path
) -> None:
    # Same caps, different order on each side: should be a noop.
    existing = {
        "grant_id": "ent_grant_existing",
        "label": "Darkmesh node darkmesh-node@mark_local",
        "match_sub": "darkmesh-node@mark_local",
        "match_iss": "https://darkmesh.local",
        "match_thumbprint": "thumb_abc",
        "capabilities": [
            {"op": "retrieve", "entity_types": ["contact"]},
            {
                "op": "store_structured",
                "entity_types": ["warm_intro_request", "warm_intro_reveal"],
            },
        ],
        "status": "active",
    }
    _stub_requests(
        monkeypatch, get=[_FakeResponse(body={"grants": [existing]})]
    )
    result = _provision(seed_path, allow_update=True)
    assert result["action"] == "noop"
