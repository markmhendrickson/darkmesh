import argparse
import os
import sys
from pathlib import Path

import uvicorn


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument(
        "--relay-key",
        default=os.environ.get("DARKMESH_RELAY_KEY", ""),
        help=(
            "Shared HMAC relay key. Required when --auth-mode is 'hmac' or "
            "'either'; ignored when --auth-mode is 'aauth'."
        ),
    )
    parser.add_argument(
        "--auth-mode",
        choices=("hmac", "aauth", "either"),
        default=os.environ.get("DARKMESH_RELAY_AUTH_MODE", "either"),
        help=(
            "'hmac' preserves the pre-Phase-3 shared-secret flow; "
            "'aauth' requires every request to carry an RFC 9421 + "
            "aa-agent+jwt signature whose thumbprint is in the trust "
            "registry; 'either' (default) accepts both and is the "
            "recommended migration mode."
        ),
    )
    parser.add_argument(
        "--trusted-agents-file",
        default=os.environ.get("DARKMESH_RELAY_TRUSTED_AGENTS_FILE")
        or os.environ.get("DARKMESH_TRUSTED_AGENTS_FILE", ""),
        help=(
            "Path to a JSON trust registry "
            "(see config/trusted_agents.example.json). Required when "
            "--auth-mode is 'aauth'; optional otherwise."
        ),
    )
    args = parser.parse_args()

    auth_mode = (args.auth_mode or "either").lower()
    relay_key = args.relay_key.strip()
    trusted_agents = (args.trusted_agents_file or "").strip()

    if auth_mode in {"hmac", "either"} and not relay_key:
        raise SystemExit(
            "relay-key is required when auth-mode is 'hmac' or 'either'"
        )
    if auth_mode == "aauth" and not trusted_agents:
        raise SystemExit(
            "trusted-agents-file is required when auth-mode is 'aauth'"
        )
    if trusted_agents and not Path(trusted_agents).exists():
        raise SystemExit(
            f"trusted-agents-file not found: {trusted_agents}"
        )

    if relay_key:
        os.environ["DARKMESH_RELAY_KEY"] = relay_key
    os.environ["DARKMESH_RELAY_AUTH_MODE"] = auth_mode
    if trusted_agents:
        os.environ["DARKMESH_RELAY_TRUSTED_AGENTS_FILE"] = trusted_agents

    uvicorn.run(
        "darkmesh_relay.service:app",
        host=args.host,
        port=args.port,
        env_file=None,
        log_level="info",
        reload=False,
        factory=False,
        proxy_headers=False,
        lifespan="on",
        loop="auto",
        http="auto",
    )


if __name__ == "__main__":
    main()
