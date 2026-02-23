import argparse
import json
import os
from typing import List


def parse_identifiers(value: str) -> List[str]:
    if not value:
        return []
    parts = [v.strip().lower() for v in value.split(",")]
    return [v for v in parts if v]


def parse_csv_list(value: str) -> List[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--node-id", default="node_local")
    parser.add_argument("--output", default="config/node_local.json")
    parser.add_argument("--port", type=int, default=8001)
    parser.add_argument("--listen-url")
    parser.add_argument("--relay-url", default="http://localhost:9000")
    parser.add_argument("--relay-key", default="")
    parser.add_argument("--pseudonym-id")
    parser.add_argument("--self-identifiers", default="")
    parser.add_argument("--required-integrations", default="contacts,interactions")
    parser.add_argument("--response-wait-seconds", type=float, default=5.0)
    parser.add_argument("--post-ttl-seconds", type=int, default=30)
    parser.add_argument("--dev-mode", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    if os.path.exists(args.output) and not args.force:
        raise SystemExit(f"Config exists: {args.output}. Use --force to overwrite.")

    pseudonym_id = args.pseudonym_id or f"p_{args.node_id}"
    self_identifiers = parse_identifiers(args.self_identifiers)
    required_integrations = parse_csv_list(args.required_integrations)
    vault_path = os.path.join("data", args.node_id)
    listen_url = (args.listen_url or f"http://localhost:{args.port}").rstrip("/")

    os.makedirs(os.path.dirname(args.output), exist_ok=True)

    payload = {
        "node_id": args.node_id,
        "vault_path": vault_path,
        "self_identifiers": self_identifiers,
        "pseudonym_id": pseudonym_id,
        "capabilities": ["warm_intro_v1"],
        "dev_mode": bool(args.dev_mode),
        "port": args.port,
        "listen_url": listen_url,
        "relay_url": args.relay_url.rstrip("/"),
        "relay_key": args.relay_key,
        "response_wait_seconds": args.response_wait_seconds,
        "post_ttl_seconds": args.post_ttl_seconds,
        "required_integrations": required_integrations,
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=True)

    print(f"Wrote config: {args.output}")


if __name__ == "__main__":
    main()
