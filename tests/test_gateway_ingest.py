"""Tests for tibet-ai-sbom gateway event ingestion."""

from __future__ import annotations

import json
from pathlib import Path

from tibet_ai_sbom.cli import (
    _augment_actor_links_from_usage_events,
    _infer_actor_model_provider_links,
    _load_gateway_usage_events,
)


def test_load_gateway_usage_events_from_jsonl(monkeypatch, tmp_path):
    """Structured tibet-gateway JSONL should map into usage events."""
    event_log = tmp_path / "gateway.jsonl"
    event_log.write_text(
        json.dumps({
            "event_id": "tok_test_1",
            "observation_layer": "tibet-gateway",
            "timestamp": "2026-05-15T09:39:45.531297+00:00",
            "operation_id": "env_test_1",
            "thread_id": "env_test_1",
            "request_id": "env_test_1",
            "token_id": "tok_test_1",
            "envelope_id": "env_test_1",
            "parent_id": "env_test_1",
            "agent_id": "codex.aint",
            "intent": "chat",
            "method": "POST",
            "target_url": "http://10.100.0.2:11434/api/chat",
            "provider": "ollama",
            "model": "qwen2.5:7b",
            "payload": {"model": "qwen2.5:7b"},
            "route_class": "direct",
            "transport": "http-proxy",
            "surface": "p520-ollama",
            "gateway_actor": "jis:tibet-gateway",
            "status": "success",
            "verified": True,
            "latency_ms": 123.4,
            "content_hash": "abc",
        }) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("TIBET_GATEWAY_EVENT_LOG", str(event_log))

    events = _load_gateway_usage_events(Path("/srv/jtel-stack/brain_api"), limit=10)
    assert len(events) == 1
    event = events[0]
    assert event["observation_layer"] == "tibet-gateway"
    assert event["inference"]["provider"] == "ollama"
    assert event["inference"]["model"] == "qwen2.5:7b"
    assert event["inference"]["surface"] == "p520-ollama"
    assert event["trust"]["basis"] == "jis+tibet-gateway"


def test_gateway_usage_event_upgrades_actor_link_surface():
    """Live gateway telemetry should beat generic heuristic surfaces."""
    actor_catalog = [
        {
            "identity": "codex.aint",
            "entity_type": "ai",
            "aint_domain": "codex.aint",
            "endpoint": "https://api.openai.com",
        }
    ]
    models = {
        "declared_models": [],
    }
    inferred = _infer_actor_model_provider_links(actor_catalog, models)
    events = [
        {
            "actor": {"identity": "codex.aint", "entity_type": "ai", "ains_domain": "codex.aint"},
            "inference": {
                "provider": "ollama",
                "model": "qwen2.5:7b",
                "surface": "p520-ollama",
            },
            "trust": {"basis": "jis+tibet-gateway"},
        }
    ]

    merged = _augment_actor_links_from_usage_events(inferred, events)
    link = next(item for item in merged if item["actor_identity"] == "codex.aint")
    assert link["action_surface"] == "p520-ollama"
    assert "ollama" in link["linked_providers"]
    assert "qwen2.5:7b" in link["linked_models"]
    assert link["trust_basis"] == "jis+tibet-gateway"
