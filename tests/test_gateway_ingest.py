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
            "lane_class": "agent-high",
            "lane_collision_policy": "graceful_yield",
            "coffee_lane_policy": "fork_on_hop_off",
            "coffee_reason": "time_diff_seconds=300<3600",
            "time_diff_seconds": 300.0,
            "diff_threshold_seconds": 3600,
            "preemptible": True,
            "lane_priority": 7,
            "gateway_actor": "jis:tibet-gateway",
            "status": "success",
            "verified": True,
            "latency_ms": 123.4,
            "content_hash": "abc",
            "_emitter": "cap-bus-runtime",
        }) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("TIBET_GATEWAY_EVENT_LOG", str(event_log))

    events = _load_gateway_usage_events(Path("/srv/jtel-stack/brain_api"), limit=10)
    assert events
    event = next(item for item in events if item["event_id"] == "tok_test_1")
    assert event["observation_layer"] == "tibet-gateway"
    assert event["inference"]["provider"] == "ollama"
    assert event["inference"]["model"] == "qwen2.5:7b"
    assert event["inference"]["surface"] == "p520-ollama"
    assert event["trust"]["basis"] == "jis+tibet-gateway"
    assert event["route"]["lane_class"] == "agent-high"
    assert event["route"]["lane_collision_policy"] == "graceful_yield"
    assert event["route"]["coffee_lane_policy"] == "fork_on_hop_off"
    assert event["route"]["coffee_reason"] == "time_diff_seconds=300<3600"
    assert event["route"]["time_diff_seconds"] == 300.0
    assert event["route"]["diff_threshold_seconds"] == 3600
    assert event["route"]["preemptible"] is True
    assert event["route"]["lane_priority"] == 7
    assert event["evidence"]["emitter"] == "cap-bus-runtime"


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
            "route": {
                "lane_class": "agent-high",
                "lane_collision_policy": "graceful_yield",
                "coffee_lane_policy": "fork_on_hop_off",
                "coffee_reason": "time_diff_seconds=300<3600",
                "time_diff_seconds": 300.0,
                "diff_threshold_seconds": 3600,
                "preemptible": True,
                "lane_priority": 7,
            },
            "trust": {"basis": "jis+tibet-gateway"},
            "evidence": {"emitter": "cap-bus-runtime"},
        }
    ]

    merged = _augment_actor_links_from_usage_events(inferred, events)
    link = next(item for item in merged if item["actor_identity"] == "codex.aint")
    assert link["action_surface"] == "p520-ollama"
    assert "ollama" in link["linked_providers"]
    assert "qwen2.5:7b" in link["linked_models"]
    assert link["trust_basis"] == "jis+tibet-gateway"
    assert link["lane_class"] == "agent-high"
    assert link["lane_collision_policy"] == "graceful_yield"
    assert link["coffee_lane_policy"] == "fork_on_hop_off"
    assert link["coffee_reason"] == "time_diff_seconds=300<3600"
    assert link["time_diff_seconds"] == 300.0
    assert link["diff_threshold_seconds"] == 3600
    assert link["preemptible"] is True
    assert link["lane_priority"] == 7
    assert link["emitter"] == "cap-bus-runtime"


def test_gateway_usage_event_keeps_strongest_coffee_policy_across_multiple_events():
    actor_catalog = []
    models = {"declared_models": []}
    inferred = _infer_actor_model_provider_links(actor_catalog, models)
    events = [
        {
            "actor": {"identity": "resume.aint", "entity_type": "ai", "ains_domain": "resume.aint"},
            "inference": {"provider": "agent-runtime", "model": "resume", "surface": "lane:agent.tool.high:agent-tool"},
            "route": {
                "lane_class": "agent-high",
                "lane_collision_policy": "graceful_yield",
                "coffee_lane_policy": "fork_on_hop_off",
                "coffee_reason": "time_diff_seconds=300<3600",
                "time_diff_seconds": 300.0,
                "diff_threshold_seconds": 3600,
                "preemptible": True,
                "lane_priority": 7,
            },
            "trust": {"basis": "jis+tibet-gateway"},
            "evidence": {"emitter": "cap-bus-runtime"},
        },
        {
            "actor": {"identity": "resume.aint", "entity_type": "ai", "ains_domain": "resume.aint"},
            "inference": {"provider": "agent-runtime", "model": None, "surface": "lane:agent.tool.high.resume.live:agent-tool"},
            "route": {
                "lane_class": "agent-high",
                "lane_collision_policy": "graceful_yield",
                "coffee_lane_policy": "sip_anyway",
                "coffee_reason": "healthy_lane",
                "time_diff_seconds": None,
                "diff_threshold_seconds": 3600,
                "preemptible": True,
                "lane_priority": 7,
            },
            "trust": {"basis": "jis+tibet-gateway"},
            "evidence": {"emitter": "cap-bus-runtime"},
        },
    ]

    merged = _augment_actor_links_from_usage_events(inferred, events)
    link = next(item for item in merged if item["actor_identity"] == "resume.aint")
    assert link["coffee_lane_policy"] == "fork_on_hop_off"
    assert link["coffee_reason"] == "time_diff_seconds=300<3600"
    assert link["time_diff_seconds"] == 300.0
