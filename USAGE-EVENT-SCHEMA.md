# Usage Event Schema

Date: 2026-05-15
Status: design note

## Purpose

`tibet-ai-sbom` can already describe:

- what is present
- which providers are configured
- which actors exist

The next step is operational truth:

- which actor used which provider
- which model was invoked
- over which route
- under which trust basis

To do that safely, multiple observation layers need a **joinable** event
shape.

This note defines the minimum shape needed to connect:

- `tibet-gateway`
- `tibet-overlay`
- `tibet-continuityd`
- later `trail` / `keychain`

into one governance story:

`ACTOR -> PROVIDER -> MODEL -> ROUTE -> TRUST`

## Observation Layers

### 1. Gateway Layer

This is the API / inference observation layer.

It sees:

- actor-submitted calls
- provider hostname or provider class
- model in request payload
- request/response timing
- local vs remote inference surface

This is the best place to answer:

- `provider`
- `model`
- part of `actor`

In practice there are two sub-modes:

- `tibet-gateway`
  Live gateway telemetry with real proxied calls, target URLs, and
  TIBET envelope/seal evidence.
- `gateway-config`
  Prepared gateway/provider evidence where routing support is configured
  but no runtime gateway log has been observed yet. This is weaker than
  live telemetry, but stronger than a vague marketing claim because it
  still identifies provider/model/surface from real code/config.

### 2. Overlay Layer

This is the network / routing observation layer.

It sees:

- egress path
- interface / NIC / hop context
- direct vs proxy vs vpn vs mux
- transport path

This is the best place to answer:

- `route`

### 3. Continuity Layer

This is the causal / continuation observation layer.

It sees:

- intake event
- parentage
- disposition
- continuation legitimacy
- trust-bearing continuity decisions

This is the best place to answer:

- `causal legitimacy`
- part of `trust`

### 4. JIS Layer

This is the attestation / authority layer.

It sees:

- signature
- bearer identity
- key binding
- attester identity
- hardware / device binding where applicable

This is the best place to answer:

- `why do we believe this event`

## Minimum Shared Join Keys

If these layers do not share at least one durable key, the system falls
back to heuristics.

The ideal shared fields are:

- `operation_id`
- `thread_id`
- `request_id`
- `token_id`
- `object_id`
- `parent_id`

At least one of these should survive across layers.

Recommended priority:

1. `operation_id`
2. `thread_id`
3. `token_id`
4. `object_id`

## Canonical Event Shape

Every observation record should be mappable into this shape:

```json
{
  "event_id": "evt_...",
  "observation_layer": "gateway",
  "timestamp": "2026-05-15T12:34:56Z",
  "operation_id": "op_...",
  "thread_id": "thr_...",
  "request_id": "req_...",
  "token_id": "tok_...",
  "object_id": "obj_...",
  "parent_id": "obj_parent_...",

  "actor": {
    "identity": "codex.aint",
    "agent_id": "codex",
    "entity_type": "ai",
    "ains_domain": "codex.aint"
  },

  "inference": {
    "provider": "openai",
    "model": "gpt-4o-mini",
    "execution_mode": "remote",
    "surface": "https-api"
  },

  "route": {
    "route_class": "direct",
    "transport": "https",
    "overlay_hops": [],
    "egress_host": "api.openai.com",
    "lane_class": "agent-high",
    "lane_collision_policy": "graceful_yield",
    "coffee_lane_policy": "fork_on_hop_off",
    "coffee_reason": "time_diff_seconds=300<3600",
    "time_diff_seconds": 300.0,
    "diff_threshold_seconds": 3600,
    "preemptible": true,
    "lane_priority": 7
  },

  "trust": {
    "basis": "jis",
    "attested": true,
    "attester": "jis:ed25519:...",
    "signature_ref": "sig_...",
    "bearer": "codex.aint"
  },

  "continuity": {
    "disposition": "trusted-candidate",
    "verify_valid": true,
    "causal_status": "legitimate"
  },

  "evidence": {
    "source": "/var/log/tibet/gateway.jsonl",
    "raw_ref": "line:12345",
    "emitter": "cap-bus-runtime"
  }
}
```

For `gateway-config` records:

- `observation_layer` becomes `gateway-config`
- `trust.basis` is usually `configured-only`
- `continuity.causal_status` is usually `config`
- the record should not overclaim runtime invocation

## Layer-Specific Minimum Fields

### Gateway Event

Minimum useful fields:

- `timestamp`
- `operation_id` or `request_id`
- `actor.identity`
- `inference.provider`
- `inference.model`
- `inference.execution_mode`
- `inference.surface`

Nice to have:

- `latency_ms`
- `status_code`
- `token_counts`
- `payload_hash`
- `route.lane_class`
- `route.lane_collision_policy`
- `route.coffee_lane_policy`
- `route.coffee_reason`
- `route.time_diff_seconds`
- `route.diff_threshold_seconds`
- `evidence.emitter`

### Overlay Event

Minimum useful fields:

- `timestamp`
- `operation_id` or `request_id`
- `route.route_class`
- `route.transport`
- `route.egress_host`

Nice to have:

- `nic_name`
- `source_ip`
- `dest_ip`
- `mux_name`
- `vpn_profile`

### Continuity Event

Minimum useful fields:

- `timestamp`
- `operation_id` or `object_id`
- `parent_id`
- `continuity.disposition`
- `continuity.verify_valid`
- `continuity.causal_status`

Nice to have:

- `actor.identity`
- `token_id`
- `object_name`

### JIS / Trust Event

Minimum useful fields:

- `timestamp`
- `operation_id` or `signature_ref`
- `trust.attested`
- `trust.attester`
- `trust.signature_ref`
- `trust.basis`

Nice to have:

- `hardware_binding`
- `pubkey_ref`
- `bearer_key_id`
- `attestation_scope`

## Route Taxonomy

Use stable route classes:

- `direct`
- `vpn`
- `proxy`
- `mux`
- `relay`
- `local`
- `unknown`

This should come from `tibet-overlay` or a routing classifier, not from
free text.

## Execution Mode Taxonomy

Use stable inference modes:

- `local`
- `remote`
- `hybrid`
- `unknown`

Examples:

- local Ollama -> `local`
- OpenAI API -> `remote`
- local home-agent that relays to a subscription backend -> `hybrid`

## Trust Basis Taxonomy

Use stable trust basis values:

- `jis`
- `observed-only`
- `inherited`
- `unsigned`
- `unknown`

Recommended interpretation:

- `jis` -> explicit attestation exists
- `observed-only` -> seen by instrumentation but not signed
- `inherited` -> trust carried from parent event
- `unsigned` -> no attestation present

## Join Strategy

When joining records across layers, prefer:

1. exact `operation_id`
2. exact `thread_id`
3. exact `token_id`
4. exact `object_id`
5. bounded time-window fallback only as last resort

Time-window fallback should never be the primary truth.

## AI-SBOM Export Targets

Once these events exist, `tibet-ai-sbom` can safely export:

- `governance.actor_model_provider_links`
- `governance.route_observations`
- `governance.trust_observations`
- `governance.usage_events`

Where:

- `actor_model_provider_links` is a stable derived summary
- `usage_events` is the per-event raw or normalized feed

## Recommended First Implementation

The fastest path is:

1. define a `tibet-gateway` event record
2. ensure it emits `operation_id`, `actor`, `provider`, `model`
3. ensure `tibet-overlay` emits `operation_id`, `route_class`, `egress_host`
4. ensure `continuityd` emits `operation_id` or `object_id`
5. ensure `JIS` signatures can be referenced via `signature_ref`

That is enough to connect:

- who invoked
- what provider/model was used
- through what route
- under what trust basis

without guessing too much.

## One-Line Summary

If `AI-SBOM` says what exists and `AINS` says who exists, then a shared
usage-event schema is what lets the system say:

- who used what, how, where, and under what trust.
