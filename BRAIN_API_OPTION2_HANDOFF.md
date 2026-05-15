# Brain API Option 2 Handoff

Date: 2026-05-15
Owner: Root AI / Claude
Scope: `brain_api` and other core app repos such as `service_api` or `telecom_api`

## Purpose

The package side is now ready:

- `tibet-gateway` can emit structured JSONL usage events
- `tibet-ai-sbom` can ingest:
  - Tier A governance events
  - Tier B live `tibet-gateway` events
  - Tier B `gateway-config` fallback events

What is still missing is **Option 2**:

- core application code should emit the same event shape when calls happen
  through app-native BYOK / external-provider flows
- this belongs in Root AI scope because it touches core runtime code

## Canonical Event Lane

Prefer exactly the same JSONL shape already produced by `tibet-gateway`.

Reference producer:

- `packages/tibet-gateway/src/tibet_gateway/tibet_seal.py`
- function: `record_gateway_event(...)`

Reference consumer:

- `packages/tibet-ai-sbom/src/tibet_ai_sbom/cli.py`
- function: `_load_gateway_usage_events(...)`

## Priority Hooks

### 1. BYOK routing

Primary file:

- `brain_api/byok_providers.py`

Why:

- it already resolves `provider`
- it already resolves `model`
- it already distinguishes normal cloud BYOK from `home_agent`

Best hook:

- inside `call_byok(...)`
- emit one event after provider/model resolution
- emit one success/error event per actual call if feasible

Minimum fields to populate:

- `agent_id`
- `intent`
- `target_url` or provider pseudo-target
- `provider`
- `model`
- `surface`
- `route_class`
- `status`

Suggested surfaces:

- `byok-https`
- `ipoll-home-agent`
- `ollama-config`

Suggested route classes:

- `direct` for normal HTTPS provider calls
- `relay` for `home_agent`

### 2. App endpoints that call BYOK

Primary files:

- `brain_api/kit_endpoints.py`
- `brain_api/voice_identity_api.py`

Why:

- these carry caller context
- they know which app/session/user/actor initiated the request

Best hook:

- right around the `call_byok(...)` invocation
- enrich emitted events with the initiating actor if available

Important:

- do not store raw API keys
- only store metadata such as:
  - `provider`
  - `model`
  - actor identity
  - route/surface

### 3. External wrapper telemetry

Primary file:

- `brain_api/external_api_wrapper.py`

Why:

- already carries `provider`
- already carries `model`
- already has success/error/tokens/cost/latency semantics

Best hook:

- inside `create_external_api_token(...)`
- optionally emit a JSONL event next to the existing TIBET token

This is especially useful for:

- non-BYOK external calls
- generic provider wrappers
- later KPI enrichment

### 4. Tool gateway / app gateway

Primary file:

- `brain_api/tool_gateway.py`

Why:

- this is a governance chokepoint
- it already sees tool execution, actor, and route semantics

Best hook:

- emit gateway-style events for provider/model/tool calls that cross this path

## Agnostic Rule

This must stay **repo-agnostic**.

The event lane must work for:

- `brain_api`
- `service_api`
- `telecom_api`
- future service repos

So:

- no hardcoded `brain_api` assumptions in the event shape
- actor identity should come from runtime context
- repo name may be used only as a fallback actor prefix

Good fallback actor form:

- `<repo_name>.gateway`

Examples:

- `brain_api.gateway`
- `service_api.gateway`
- `telecom_api.gateway`

## Output Contract

Emit JSONL records that match the current `tibet-gateway` lane as closely as possible.

Minimum example:

```json
{
  "event_id": "evt_123",
  "observation_layer": "tibet-gateway",
  "timestamp": "2026-05-15T12:34:56Z",
  "operation_id": "op_123",
  "request_id": "op_123",
  "agent_id": "jasper.aint",
  "intent": "kit_chat",
  "target_url": "https://api.anthropic.com/v1/messages",
  "provider": "anthropic",
  "model": "claude-sonnet-4-6",
  "route_class": "direct",
  "transport": "https-api",
  "surface": "byok-https",
  "status": "success",
  "verified": false
}
```

## Best Log Path

Use the same env/config convention when possible:

- `TIBET_GATEWAY_EVENT_LOG`

Recommended default:

- `/var/log/tibet/gateway.jsonl`

That keeps `tibet-ai-sbom` ingestion simple across repos.

## Why This Matters

Once this emitter exists in core app paths, the governance chain becomes:

- `AI-SBOM` says what is present
- `CBOM` says how it got there
- `AINS` says who is acting
- `JIS` says why we believe it
- `gateway events` say who used which provider/model over which surface

That is the missing operational bridge from configuration truth to runtime truth.
