import argparse
import json
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
    parser.add_argument("--port", type=int)
    parser.add_argument("--config", required=True)
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = (REPO_ROOT / config_path).resolve()

    os.environ["DARKMESH_CONFIG"] = str(config_path)
    port = args.port
    if port is None:
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            port = int(payload.get("port", 8001))
        except (OSError, ValueError, json.JSONDecodeError):
            port = 8001
    os.environ["DARKMESH_PORT"] = str(port)

    uvicorn.run(
        "darkmesh.service:app",
        host=args.host,
        port=port,
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
