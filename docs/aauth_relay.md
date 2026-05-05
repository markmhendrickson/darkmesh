# AAuth at the Darkmesh network layer (Phase 3)

This fork extends AAuth (RFC 9421 HTTP Message Signatures + the
`aa-agent+jwt` agent token) from Darkmesh → Neotoma writeback to every
inter-Darkmesh hop: node ↔ relay, node ↔ peer callbacks, and
connector ↔ node. The goal is to retire the pre-shared
`DARKMESH_RELAY_KEY` / `X-Darkmesh-Key` handoff without breaking
interop with upstream Darkmesh during migration.

## Why

The upstream Darkmesh trust model relies on operators cutting a shared
secret over a side channel (Signal / email / "I'll text you the key")
before any two nodes can talk. That friction is the reason most
onboarding conversations stall out — and it's a secret-handling
anti-pattern given how loosely it ends up in chat logs and
screenshots.

AAuth replaces the handoff with something strictly better on both
axes:

- **No secrets in flight.** Each side publishes its *public* JWK. The
  thumbprint (RFC 7638) is all the other operator needs to decide
  whether to trust it.
- **Per-edge attribution.** Every signed request carries a `sub` /
  `iss` claim and a thumbprint. A compromised connector key can be
  revoked without rotating the node's own keypair; a peer that
  misbehaves can be pulled from the trust registry by thumbprint.
- **Capabilities, not knowledge-of-secret.** Publishing ≠ pulling ≠
  registering. A connector that only needs `node.ingest` never has
  permission to `relay.publish`.

## Threat model

| Attacker capability                         | HMAC world                         | AAuth world                                                |
|---------------------------------------------|------------------------------------|------------------------------------------------------------|
| Reads one Signal message with the relay key | Full access to every relay endpoint | Nothing. Public JWK shared there grants no authority.      |
| Steals a connector's keypair                | Full node-key access               | Only whatever capabilities that connector's entry has.     |
| Rebinds a relay DNS name                    | Still works (knowledge-of-secret)  | Signed `@authority` no longer matches; signatures reject.  |
| Replays a captured request                  | Trivially replays                  | Rejected outside `max_age` (default 300s) and with replay-safe `@path`. |
| Reorders or mutates the JSON body           | Undetectable                       | `content-digest` is a covered component; mutation fails verification. |

AAuth is *not* a privacy improvement over HMAC — payload content is
still visible to the relay. Confidentiality of warm-intro content is
handled separately by the PSI and reveal-token flows.

## Trust registry

Each node and relay reads a trust registry JSON file that maps
thumbprints → `{sub, iss, public_jwk, capabilities}`. The file is
hot-reloaded on mtime change, so adding a peer does not require a
restart.

Example shape:

```json
{
  "version": 1,
  "agents": [
    {
      "label": "mark_local node",
      "thumbprint": "D0fEOXgZj...",
      "sub": "darkmesh-node@mark_local",
      "iss": "https://darkmesh.local",
      "public_jwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "...", "kid": "..." },
      "capabilities": [
        "relay.register",
        "relay.publish",
        "relay.pull",
        "node.ingest",
        "node.callback.consent",
        "node.callback.reveal"
      ]
    }
  ]
}
```

Point nodes / relays at it via:

- `DARKMESH_TRUSTED_AGENTS_FILE` (node inbound middleware)
- `DARKMESH_RELAY_TRUSTED_AGENTS_FILE` (relay; falls back to the
  generic env var when unset)
- `trusted_agents_file` in `config/<node>_local.json`

See `config/trusted_agents.example.json` for a runnable template.

### Rejecting private key material

`darkmesh/trust_registry.py` refuses to load any entry whose
`public_jwk` contains `d`, `p`, `q`, `dp`, `dq`, or `qi` — a common
mistake when pasting a JWK out of `jwcrypto`. The
`scripts/darkmesh_trust_add.py` helper enforces the same guardrail
before appending.

## Modes (`auth_mode`)

Both nodes and the relay support the same three values via
`DARKMESH_AUTH_MODE` / `DARKMESH_RELAY_AUTH_MODE`, or the
`auth_mode` field on `DarkmeshConfig` and `DarkmeshRelayState`:

| Mode     | Inbound behaviour                                                                            | Outbound behaviour (node / listener / connector)                                           |
|----------|-----------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------|
| `hmac`   | Accepts only the legacy `X-Darkmesh-Key` / body `relay_key`.                                 | Always uses `X-Darkmesh-Key`; never signs.                                                 |
| `aauth`  | Requires a verifying AAuth signature. Missing `Signature-Input` → 401.                        | Requires AAuth signer config; failure is fatal at boot / start.                            |
| `either` | Prefers AAuth when signature headers are present; otherwise falls back to HMAC.              | Signs when AAuth env material is present; otherwise falls back to HMAC.                    |

`either` is the migration default and is what the shipped
`config/mark_local.json` and `config/node_b_local.json` use.

## Capability matrix

| Endpoint                                          | Required AAuth capability        | Notes                                                        |
|---------------------------------------------------|----------------------------------|--------------------------------------------------------------|
| `POST /darkmesh/relay/nodes/register`             | `relay.register`                 | Relay also pins `node_id` suffix to the agent `sub` scope.   |
| `GET  /darkmesh/relay/nodes`                      | `relay.list`                     | GET signs over an empty body.                                |
| `POST /darkmesh/relay/posts`                      | `relay.publish`                  | Warm-intro post publication.                                 |
| `POST /darkmesh/relay/posts/pull`                 | `relay.pull`                     | Listener pulls new posts with the node's own signer.         |
| `POST /darkmesh/ingest`                           | `node.ingest`                    | Emitted by CSV / OpenClaw / Neotoma-sync connectors.         |
| `POST /darkmesh/skills/warm-intro/consent*`       | `node.callback.consent`          | Peer calling back after consent prompt.                      |
| `POST /darkmesh/skills/warm-intro/reveal*`        | `node.callback.reveal`           | Peer calling back with PSI + reveal token.                   |
| `POST /darkmesh/skills/warm-intro/inbox`          | `node.callback.consent`          |                                                              |
| `POST /darkmesh/skills/warm-intro/psi/respond`    | `node.callback.reveal`           |                                                              |
| `POST /darkmesh/skills/warm-intro/request`        | `node.query`                     | Originating warm-intro request from a trusted agent.         |
| `GET  /darkmesh/integrations/status`, `/capabilities`, `/node/card` | `node.query` | Read-only introspection. |

`node.ingest`, `node.query`, and the `node.callback.*` caps are
distinct on purpose: a connector never needs callback permission and a
peer responder never needs ingest permission.

## Pairing recipe

The shared-secret handoff that used to read "I'll text you the relay
key" becomes, for two operators Alice and Bob:

```bash
# Both sides generate keypairs (one-time per operator/machine)
python -m darkmesh.aauth_signer keygen \
  --private-out secrets/<node>_darkmesh_private.jwk \
  --public-out  secrets/<node>_darkmesh_public.jwk

# Publish the PUBLIC JWK somewhere the other side can read it
# (gist, fork, repo, static site — it's public).

# Each side imports the other's public JWK into its trust registry
python scripts/darkmesh_trust_add.py \
  --public-jwk path/to/bob_darkmesh_public.jwk \
  --sub darkmesh-node@bob \
  --iss https://darkmesh.local \
  --capabilities relay.register,relay.publish,relay.pull,node.callback.consent,node.callback.reveal \
  --file config/trusted_agents.json

# Sanity-check: the helper is idempotent — re-running updates the
# existing entry by thumbprint instead of duplicating.
python scripts/darkmesh_trust_add.py --dry-run ...
```

Connectors get their own entries so operators can revoke a connector
without rotating a whole node:

```bash
python scripts/darkmesh_trust_add.py \
  --public-jwk path/to/alice_connector_csv_contacts_public.jwk \
  --sub connector-csv-contacts@alice \
  --capabilities node.ingest \
  --file config/trusted_agents.json
```

Then run connectors with AAuth env material — `source
scripts/aauth_env.sh <connector-sub>` (or set
`DARKMESH_AAUTH_PRIVATE_JWK_PATH` + `DARKMESH_AAUTH_SUB` directly).

## Outbound selection logic

`publish_to_relay`, the `register_node` startup hook, warm-intro
peer callbacks, and `scripts/darkmesh_listener.py` all route outbound
traffic through a small helper (`_peer_post` / `_build_post`) that:

1. Prefers AAuth when `auth_mode != "hmac"` **and** a signer config is
   loaded;
2. Otherwise falls back to an HMAC `X-Darkmesh-Key` request;
3. Never embeds `relay_key` in the body when AAuth is in use (the
   signed request authenticates itself).

That keeps a half-migrated fleet usable: a node in `either` mode
signs where it can but speaks HMAC to an upstream vanilla Darkmesh
relay until the operator has installed a trust registry on the relay.

## Inbound verifier (`darkmesh/aauth_verify.py`)

The Python verifier mirrors Neotoma's
`src/middleware/aauth_verify.ts` against the same RFC 9421 + AAuth
profile that `darkmesh/aauth_signer.py` produces:

- **Covered components** (every signed request must carry all six, or
  the verifier raises `signature_covered_components_incomplete`):
  `@method`, `@authority`, `@path`, `content-type`, `content-digest`,
  `signature-key`. `@path` is used instead of `@target-uri` so
  `http://` local-dev round-trips successfully (Neotoma's upstream
  verifier hardcodes `https://`).
- **Signature label**: `aasig`. Other labels are accepted as long as
  the covered-component set is complete; `aasig` is preferred for
  diagnostic consistency.
- **JWT requirements**: `typ=aa-agent+jwt`, non-empty `sub` and `iss`,
  optional `iat`/`exp` enforced with a 60s clock-skew window
  (`DEFAULT_JWT_CLOCK_SKEW_SEC`), `cnf.jwk` (RFC 7800) carrying the
  signing public JWK, and an optional `jkt` thumbprint that — if
  present — must match the JWK thumbprint.
- **Replay protection**: RFC 9421 `created` freshness window defaults
  to 300 seconds (`DEFAULT_MAX_AGE_SEC`), well above the signer's
  default token TTL.
- **Trust boundary**: verification succeeds only when the JWK
  thumbprint matches a `TrustRegistry` entry. There is no
  fall-through to anonymous; capability enforcement happens at the
  call site via `VerifiedAgent.has_capability(...)` /
  `TrustRegistry.permits(...)`.

`AAuthVerifyError.reason` is a stable, machine-readable code suitable
for logs and HTTP error envelopes:

| Reason | Meaning |
|--------|---------|
| `signature_key_missing` / `signature_key_malformed` | `Signature-Key` header absent or not RFC 8941 dictionary form. |
| `jwt_malformed` / `jwt_decode_failed` | Three-segment JWT could not be parsed. |
| `jwt_typ_invalid` | JWT `typ` is not `aa-agent+jwt`. |
| `jwt_sub_missing` / `jwt_iss_missing` | Required claim absent. |
| `jwt_iat_future` / `jwt_expired` | Clock-skew check failed. |
| `cnf_jwk_missing` / `cnf_jwk_malformed` / `cnf_jwk_private` / `cnf_jwk_unsupported` | Embedded public key missing, malformed, contains private material, or uses an unsupported curve. |
| `jwt_jkt_mismatch` | Declared `jkt` ≠ computed thumbprint. |
| `unknown_thumbprint` | Thumbprint not in the trust registry. |
| `sub_mismatch` / `iss_mismatch` | Registry pinned a different sub/iss for that thumbprint. |
| `content_digest_missing` / `_unsupported` / `_malformed` / `_mismatch` | `content-digest` header absent, not `sha-256=:…:`, or did not match the body's hash. |
| `signature_invalid` / `signature_missing` | RFC 9421 verification failed or no verifiable result was produced. |
| `signature_covered_components_incomplete` | A required component was stripped from `Signature-Input`. |

Successful verification returns a `VerifiedAgent` carrying `sub`,
`iss`, `thumbprint`, the public JWK, the resolved algorithm
(`ecdsa-p256-sha256` or `ed25519`), and the registry-supplied
capability tuple. FastAPI middleware on the node and relay attaches
this to request-local state so handlers and provenance stamps can
read it without re-parsing headers.

## Connector AAuth (`connectors/_auth.py`)

The four ingest connectors (`contacts_csv`, `interactions_csv`,
`openclaw_sync`, `neotoma_sync`) share a single `ConnectorAuth`
helper that resolves the auth mode at startup and exposes a uniform
`post(url, payload, *, timeout)`:

- **`hmac`** — sends the legacy `X-Darkmesh-Key` (taken from
  `--node-key` / `DARKMESH_NODE_KEY`).
- **`aauth`** — signs the request with the connector's own keypair.
  Failure to load signer env material is fatal (a connector running
  in `aauth` mode without a key would otherwise silently ingest
  nothing).
- **`either`** *(default)* — signs when `DARKMESH_AAUTH_PRIVATE_JWK(_PATH)`
  is present, otherwise falls back to HMAC. This is the safe default
  during migration.

`add_auth_arguments(parser, default_sub=...)` registers the shared
flags on every connector:

```text
--node-key            (or DARKMESH_NODE_KEY)
--auth-mode           hmac|aauth|either   (or DARKMESH_AUTH_MODE)
--aauth-private-jwk   path                (or DARKMESH_AAUTH_PRIVATE_JWK_PATH)
--aauth-sub           connector-<...>@<operator>
--aauth-iss           https://darkmesh.local
```

Each connector publishes a canonical default sub so its trust-registry
entry can scope `node.ingest` independently of the node's own keypair:

| Connector                       | Default `sub`                                  |
|---------------------------------|------------------------------------------------|
| `connectors/contacts_csv.py`    | `connector-csv-contacts@<operator>`            |
| `connectors/interactions_csv.py`| `connector-csv-interactions@<operator>`        |
| `connectors/openclaw_sync.py`   | `connector-openclaw@<operator>`                |
| `connectors/neotoma_sync.py`    | `connector-neotoma-sync@<operator>`            |

The `<operator>` token is read from `DARKMESH_NODE_ID` /
`DARKMESH_OPERATOR` and falls back to `local`. Add a
`--public-jwk` entry for each connector sub via
`scripts/darkmesh_trust_add.py` with capability `node.ingest` (only).
That is how an operator revokes a leaked CSV-importer key without
rotating the node's own ES256 keypair.

## Listener AAuth (`scripts/darkmesh_listener.py`)

The listener is the long-running process that polls the relay for
warm-intro posts and routes them through the local node and back to
peers. Phase 3 wraps every relay/local/peer call in `_build_post`,
which honours the same `auth_mode` semantics as connectors:

- `hmac` keeps the legacy `X-Darkmesh-Key` + body `relay_key`
  behaviour.
- `aauth` requires `DARKMESH_AAUTH_PRIVATE_JWK(_PATH)` +
  `DARKMESH_AAUTH_SUB` and refuses to start otherwise.
- `either` (default) signs when configured, otherwise falls back to
  HMAC; HMAC credentials stay populated so a half-migrated peer that
  hasn't loaded our public JWK yet still admits the hop.

The listener uses the node's *own* sub (typically
`darkmesh-node@<node_id>`), so its registry entry needs the relay
caps (`relay.register`, `relay.pull`) plus the peer-callback caps
(`node.callback.consent`, `node.callback.reveal`).

## Relay startup (`scripts/run_darkmesh_relay.py`)

The relay binary now accepts the same auth knobs the runtime reads
from env:

```bash
python scripts/run_darkmesh_relay.py \
  --host 0.0.0.0 --port 9000 \
  --auth-mode either \
  --trusted-agents-file config/trusted_agents.json \
  --relay-key <legacy_shared_key>   # required for hmac/either; ignored for aauth
```

Validation rules at startup:

- `--auth-mode aauth` requires `--trusted-agents-file`; the file must
  exist on disk before boot.
- `--auth-mode hmac` / `either` require `--relay-key` (or
  `DARKMESH_RELAY_KEY`).
- The corresponding env vars (`DARKMESH_RELAY_AUTH_MODE`,
  `DARKMESH_RELAY_TRUSTED_AGENTS_FILE`, falling back to
  `DARKMESH_TRUSTED_AGENTS_FILE`) cover the same surface for
  systemd-style deployment.

## Env vars (`scripts/aauth_env.sh`)

`source scripts/aauth_env.sh <node_id>` exports every variable the
node + listener + connectors need:

| Variable                              | Phase | Purpose                                                            |
|---------------------------------------|-------|--------------------------------------------------------------------|
| `DARKMESH_AAUTH_PRIVATE_JWK_PATH`     | 2     | Path to this node's signing JWK.                                   |
| `DARKMESH_AAUTH_SUB`                  | 2     | Agent sub (`darkmesh-node@<node_id>`).                             |
| `DARKMESH_AAUTH_ISS`                  | 2     | Agent iss (`https://darkmesh.local`).                              |
| `DARKMESH_TRUSTED_AGENTS_FILE`        | 3     | Default trust registry path (defaults to `config/trusted_agents.json`). |
| `DARKMESH_RELAY_TRUSTED_AGENTS_FILE`  | 3     | Relay-specific override; falls back to the generic var.            |
| `DARKMESH_AUTH_MODE`                  | 3     | Default `auth_mode` for nodes/listeners/connectors (`either`).     |
| `DARKMESH_RELAY_AUTH_MODE`            | 3     | Default `auth_mode` for the relay (`either`).                      |

The script also prints a one-line hint reminding the operator to run
`scripts/neotoma_grants_provision.py --auto` once `NEOTOMA_TOKEN` is
set, so first-time setup never silently lands without an
`agent_grant`.

## Test coverage

| Test file                                           | What it pins                                                                                                      |
|-----------------------------------------------------|-------------------------------------------------------------------------------------------------------------------|
| `tests/unit/test_aauth_verify.py`                   | RFC 9421 verifier: covered-component enforcement, JWT clock-skew, content-digest, sub/iss/jkt mismatches, all `AAuthVerifyError.reason` codes. |
| `tests/unit/test_trust_registry.py`                 | Hot-reload semantics, RFC 7638 thumbprint binding, refusal of private-key material in `public_jwk`, capability matching. |
| `tests/unit/test_neotoma_client_auth.py`            | Read auth-mode resolver (`bearer` / `aauth` / `auto`) and `SignerConfigError` propagation.                       |
| `tests/unit/test_neotoma_grants_provision.py`       | Idempotent create/update logic of the grants script against a faked Neotoma REST surface.                         |
| `tests/integration/test_relay_aauth_roundtrip.py`   | Relay register / publish / pull / list under `auth_mode=aauth` and `auth_mode=either`, with HMAC fallback paths.  |
| `tests/integration/test_node_aauth_ingest.py`       | Node `/darkmesh/ingest` capability gating: connector-sub admission, missing-capability rejection, signed-vs-HMAC parity. |

The integration harness (`tests/integration/conftest.py`) routes
real signed requests through FastAPI `TestClient`s without binding
sockets, preserving `Host` / `@authority` so `tests/integration/`
exercises the same wire form a deployed node would emit.

Run everything with:

```bash
python -m pytest tests/
```

## Migration plan

1. Ship this phase with `auth_mode="either"` on relay + nodes +
   connectors (already the default in `config/*_local.json`).
2. Have each operator publish their public JWK.
3. Exchange trust entries bilaterally via
   `scripts/darkmesh_trust_add.py`. The shared relay key can stay in
   place during this step.
4. Flip relay + nodes to `auth_mode="aauth"` once every active
   operator is on the trust registry.
5. Retire `relay_key` / `node_key` from configs at the next release.

## Observability

- Relay logs `Darkmesh relay auth_mode=<mode> trust_registry_entries=<n>`
  at boot.
- Each node logs `Darkmesh node AAuth signer enabled sub=<sub>
  auth_mode=<mode>` when an outbound signer is loaded.
- Verification failures are logged with `reason` from
  `AAuthVerifyError` (`signature_invalid`, `jwt_expired`,
  `unknown_thumbprint`, `sub_mismatch`, …) so operators can triage
  without re-plumbing debug logging.

## Out of scope (Phase 3)

- A `/.well-known/darkmesh-jwks` auto-discovery endpoint on the relay.
- Upstream PR to `anandiyer/darkmesh`.
- Automated key rotation; treat thumbprint-level edits in
  `config/trusted_agents.json` as the rotation mechanism for now.
