import argparse
import json


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--include-relay-key", action="store_true")
    args = parser.parse_args()

    with open(args.config, "r", encoding="utf-8") as f:
        config = json.load(f)

    card = {
        "node_id": config["node_id"],
        "pseudonym_id": config.get("pseudonym_id", config["node_id"]),
        "url": config.get("listen_url", f"http://localhost:{int(config.get('port', 8001))}"),
        "capabilities": config.get("capabilities", ["warm_intro_v1"]),
        "relay_url": config.get("relay_url", ""),
    }

    payload = {"card": card}
    if args.include_relay_key:
        payload["relay_key"] = config.get("relay_key", "")

    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
