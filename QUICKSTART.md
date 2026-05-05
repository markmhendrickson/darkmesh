# Darkmesh Quickstart

Shortest path to run Darkmesh.

> Looking for the Neotoma-backed setup (live contact store + AAuth
> writeback)? See [docs/neotoma_integration.md](docs/neotoma_integration.md).
> The quickstart below runs the default vault-backed node, which still
> works identically in this fork.
>
> **Already running Neotoma <0.9?** Read the
> [Upgrading from Neotoma <0.9 to ≥0.9](docs/neotoma_integration.md#upgrading-from-neotoma-09-to-09)
> runbook before bumping Neotoma — the legacy
> `NEOTOMA_AGENT_CAPABILITIES_*` env vars are now a hard-fail on boot
> and Darkmesh nodes need an `agent_grant` provisioned before they can
> read or write.

## Demo in 9 commands

OpenClaw is **not** required for this local demo.

```bash
git clone https://github.com/anandiyer/darkmesh.git
cd darkmesh
python3 scripts/darkmesh_setup.py
python3 scripts/darkmesh_down.py
rm -f data/node_a/*.enc data/node_b/*.enc data/node_a/darkmesh_listener.cursor data/node_b/darkmesh_listener.cursor
python3 scripts/darkmesh_up.py --mode demo --relay-key demo-relay-key
export DARKMESH_NODE_KEY=demo-relay-key
python3 scripts/darkmesh_demo.py
python3 scripts/darkmesh_status.py --relay-url http://localhost:9000
```

Stop everything:

```bash
python3 scripts/darkmesh_down.py
```

## Real network in 5 steps

1. Start one relay host:

```bash
python3 scripts/run_darkmesh_relay.py --host 0.0.0.0 --port 9000 --relay-key <shared_relay_key>
```

2. Create node config on each node:

```bash
python3 scripts/darkmesh_init.py \
  --node-id <node_id> \
  --self-identifiers <email@domain.com> \
  --relay-url http://<relay-host>:9000 \
  --relay-key <shared_relay_key> \
  --output config/<node_id>.json
```

3. Start Darkmesh node + listener on each node:

```bash
python3 scripts/darkmesh_up.py --mode join --config config/<node_id>.json
```

4. Load integrations (pick one):

Set node auth key:

```bash
export DARKMESH_NODE_KEY=<shared_relay_key_or_node_key>
```

CSV path:

```bash
python3 connectors/contacts_csv.py --url http://localhost:8001 --file /path/to/contacts.csv --node-key $DARKMESH_NODE_KEY
python3 connectors/interactions_csv.py --url http://localhost:8001 --file /path/to/interactions.csv --node-key $DARKMESH_NODE_KEY
```

> **Phase 3 (AAuth-signed connector ingest).** All four connectors
> (`contacts_csv`, `interactions_csv`, `openclaw_sync`, `neotoma_sync`)
> share an `--auth-mode hmac|aauth|either` flag. With
> `DARKMESH_AAUTH_PRIVATE_JWK*` exported (see
> `scripts/aauth_env.sh`) and the connector's public JWK added to the
> trust registry (`scripts/darkmesh_trust_add.py --capabilities node.ingest`),
> ingest is signed instead of relying on `--node-key`. See
> [docs/aauth_relay.md → Connector AAuth](docs/aauth_relay.md#connector-aauth-connectors_authpy).

OpenClaw autodiscovery path:

```bash
export OPENCLAW_TOKEN=<token>
python3 connectors/openclaw_sync.py \
  --url http://localhost:8001 \
  --autodiscover \
  --openclaw-base-url http://localhost:3000 \
  --self-identifier <email@domain.com> \
  --node-key $DARKMESH_NODE_KEY
```

5. Verify integrations are loaded:

```bash
python3 scripts/darkmesh_integrations_check.py --url http://localhost:8001 --strict --node-key $DARKMESH_NODE_KEY
```

Use from OpenClaw:

```text
Use $darkmesh to autodiscover OpenClaw integrations and ingest them into my node.
```
