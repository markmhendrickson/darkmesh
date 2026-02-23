---
name: darkmesh
description: Turnkey setup and operation of Darkmesh with relay/listener nodes for opt-in private data sharing. Use when installing, starting, stopping, checking integration readiness, syncing OpenClaw data sources (including autodiscovery), or running warm-intro requests across OpenClaw nodes.
---

# Darkmesh Skill

## Fast path
- Run `python3 scripts/darkmesh_setup.py`.
- Run `python3 scripts/darkmesh_up.py --mode demo --relay-key demo-relay-key`.
- Run `export DARKMESH_NODE_KEY=demo-relay-key`.
- Run `python3 scripts/darkmesh_demo.py`.
- Run `python3 scripts/darkmesh_down.py`.

## Node setup
- Create config:
`python3 scripts/darkmesh_init.py --node-id my_node --self-identifiers me@domain.com --relay-url http://relay-host:9000 --relay-key <shared_relay_key> --output config/my_node.json`
- Start node + listener:
`python3 scripts/darkmesh_up.py --mode join --config config/my_node.json`

## Data ingestion options
- Set node auth key:
`export DARKMESH_NODE_KEY=<shared_relay_key_or_node_key>`
- CSV connector path:
`python3 connectors/contacts_csv.py --url http://localhost:8001 --file /path/to/contacts.csv --node-key $DARKMESH_NODE_KEY`
`python3 connectors/interactions_csv.py --url http://localhost:8001 --file /path/to/interactions.csv --node-key $DARKMESH_NODE_KEY`
- OpenClaw autodiscovery path:
`export OPENCLAW_TOKEN=<token>`
`python3 connectors/openclaw_sync.py --url http://localhost:8001 --autodiscover --openclaw-base-url http://localhost:3000 --self-identifier me@domain.com --node-key $DARKMESH_NODE_KEY`
- Direct events URL fallback:
`python3 connectors/openclaw_sync.py --url http://localhost:8001 --events-url http://localhost:3000/api/events --events-header "Authorization=Bearer <token>" --self-identifier me@domain.com --node-key $DARKMESH_NODE_KEY`

## Readiness checks
- Node and relay health:
`python3 scripts/darkmesh_status.py --config config/my_node.json`
- Required integrations:
`python3 scripts/darkmesh_integrations_check.py --url http://localhost:8001 --strict --node-key $DARKMESH_NODE_KEY`

## Warm-intro flow
- Request candidates:
`curl -sS -X POST http://localhost:8001/darkmesh/skills/warm-intro/request -H 'Content-Type: application/json' -H "X-Darkmesh-Key: $DARKMESH_NODE_KEY" -d '{"template":"warm_intro_v1","target":{"company":"Company B","role":"Business Development"},"constraints":{"max_candidates":3,"min_strength":0.5}}'`
- Reveal top candidate after consent:
`curl -sS -X POST http://localhost:8001/darkmesh/skills/warm-intro/consent -H 'Content-Type: application/json' -H "X-Darkmesh-Key: $DARKMESH_NODE_KEY" -d '{"request_id":"<request_id>","consent_id":"<consent_id>"}'`

## Files
- Encrypted data and local state: `data/<node_id>/`.
- Runtime PID/log files: `.darkmesh/`.

## Safety
- Keep relay and nodes on private networks for this prototype.
- Use non-empty relay keys and node keys in every environment.
- Do not commit `.darkmesh/`, `data/**/vault.key`, or encrypted vault files.
