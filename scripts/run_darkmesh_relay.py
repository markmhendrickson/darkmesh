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
    parser.add_argument("--relay-key", default="")
    args = parser.parse_args()

    os.environ["DARKMESH_RELAY_KEY"] = args.relay_key

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
