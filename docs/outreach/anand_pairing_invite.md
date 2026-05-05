# Outreach: Anand pairing invite (AAuth-based)

Revised version of the earlier relay-key pairing draft. Once Phase 3
(network-layer AAuth) landed in this fork, the ask shifts from "I'll
send you the relay key privately" to "publish your public JWK and
I'll add it to my trust list." Nothing sensitive crosses the wire.

---

## Subject

Testing a Neotoma-backed Darkmesh fork — would love your take

## Body

Hey Anand,

I've been running a fork of Darkmesh that plugs
[Neotoma](https://github.com/markmhendrickson/neotoma) in as the local
data substrate — live entity graph instead of the vault, AAuth-signed
`warm_intro_reveal` writebacks, capability-scoped agent-to-agent
coordination. Write-up is in
[README.md](https://github.com/markmhendrickson/darkmesh) and
[docs/neotoma_integration.md](https://github.com/markmhendrickson/darkmesh/blob/main/docs/neotoma_integration.md).

Since the last time we talked about this, I also finished Phase 3:
every inter-node hop (node ↔ relay, peer callbacks, connectors)
signs with AAuth (RFC 9421 + `aa-agent+jwt`), so the old
`DARKMESH_RELAY_KEY` handoff is no longer needed. Full threat model
and capability matrix in
[docs/aauth_relay.md](https://github.com/markmhendrickson/darkmesh/blob/main/docs/aauth_relay.md).
Backwards-compatible — `auth_mode="either"` is the default, so nodes
still speak HMAC to plain upstream Darkmesh until both sides are on
the trust registry.

**The ask — primary:** would you be up for a fully-async pairing test
against my public node at `darkmesh.markmhendrickson.com`? All you'd
need to do is:

1. Generate a keypair (one command):

   ```bash
   python -m darkmesh.aauth_signer keygen \
     --private-out secrets/anand_darkmesh_private.jwk \
     --public-out  secrets/anand_darkmesh_public.jwk
   ```

2. Publish the **public** JWK wherever you like — gist, fork, tweet,
   attachment, all fine. It's public key material.

3. Send me the link (or paste). I'll add it to my trust registry with
   `scripts/darkmesh_trust_add.py` and the relay + node will pick it
   up on mtime reload — no restart, no secret exchange.

4. Add my public JWK ([link]) to yours the same way.

From there we can exercise the five joint tests end-to-end — warm
intro, asymmetric data richness, capability scoping, reveal
provenance, ghostwriting pipeline state — no coordinated deploy
window required.

**The ask — secondary:** if you'd rather see it live first, happy to
schedule a call and walk through the fork (and the AAuth rollout)
with Neotoma running in the background. Either way works.

Either path is zero-pressure; happy to queue up the trust entries on
my side the moment your public JWK is reachable so you can verify
it's a drop-in without needing to wait on me.

Cheers,
Mark

---

## Why this version

- **No secret in flight.** The previous draft asked for the shared
  relay key out-of-band; this one only asks for a public JWK that's
  fine to put on a gist.
- **Async-first, call-optional.** Matches the earlier framing
  (primary ask is testing with a hosted node, secondary is the live
  walkthrough) but drops the scheduling blocker entirely.
- **Capability-scoped by default.** The trust registry entry I add
  for Anand's node grants exactly the capabilities needed for the
  joint tests; nothing more. Easy to revoke later by thumbprint.
