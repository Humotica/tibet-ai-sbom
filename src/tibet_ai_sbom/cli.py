"""
tibet-ai-sbom CLI — alpha entry point.

This 0.1.0 release exposes:

- ``tibet-ai-sbom version``         — package version banner.
- ``tibet-ai-sbom clusters``        — list BSI cluster codes.
- ``tibet-ai-sbom code AISBOM-...`` — describe a single cluster element.
- ``tibet-ai-sbom scan [PATH]``     — AI-SBOM overlay on tibet-sbom scans.

The scan implementation starts with software inventory + provenance from
``tibet-sbom`` and maps that evidence onto the BSI/G7 AI-SBOM clusters.
Later roadmap phases add richer workspace topology, then system / models
/ datasets / infrastructure / security / KPIs.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .clusters import (
    BSICluster,
    CLUSTER_CODES,
    cluster_for_code,
    list_cluster_codes,
)


def _load_tibet_sbom():
    """Import tibet-sbom lazily so the rest of the CLI stays usable."""
    try:
        from tibet_sbom import SBOMGenerator
    except ImportError as exc:
        return None, exc
    return SBOMGenerator, None


def _schema_file_path() -> Path:
    """Return the package-local AI-SBOM JSON schema path."""
    return Path(__file__).resolve().parents[2] / "ai-sbom.schema.json"


def _load_ai_sbom_schema() -> tuple[dict[str, Any] | None, str | None]:
    """Load the package-local schema document used by validate."""
    schema_path = _schema_file_path()
    try:
        payload = json.loads(schema_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return None, f"could not load schema {schema_path}: {exc}"
    if not isinstance(payload, dict):
        return None, f"schema file is not a JSON object: {schema_path}"
    return payload, None


MODEL_EXTENSIONS = {
    ".gguf": ("definite_model_artifact", []),
    ".safetensors": ("definite_model_artifact", []),
    ".onnx": ("definite_model_artifact", []),
    ".tflite": ("definite_model_artifact", []),
    ".pb": ("probable_model_artifact", []),
    ".mlmodel": ("probable_model_artifact", []),
    ".h5": ("probable_model_artifact", []),
    ".ckpt": ("probable_model_artifact", []),
    ".pth": ("probable_model_artifact", ["high-risk-serialization"]),
    ".pt": ("probable_model_artifact", ["high-risk-serialization"]),
    ".bin": ("probable_model_artifact", []),
    ".joblib": ("probable_model_artifact", ["high-risk-serialization"]),
    ".pkl": ("probable_model_artifact", ["high-risk-serialization"]),
}

MODEL_SIDECARS = {
    "tokenizer.json",
    "config.json",
    "generation_config.json",
    "modelfile",
    "model_index.json",
}

MODEL_NAME_PATTERNS = (
    "llama",
    "mistral",
    "qwen",
    "deepseek",
    "claude",
    "gemini",
    "gpt",
    "phi",
    "mixtral",
    "yi-",
)

PROVIDER_ENV_VARS = {
    "OPENAI_API_KEY": "openai",
    "ANTHROPIC_API_KEY": "anthropic",
    "GEMINI_API_KEY": "google-gemini",
    "GOOGLE_API_KEY": "google-gemini",
    "MISTRAL_API_KEY": "mistral",
    "TOGETHER_API_KEY": "together",
    "COHERE_API_KEY": "cohere",
    "REPLICATE_API_TOKEN": "replicate",
    "HUGGINGFACEHUB_API_TOKEN": "huggingface",
    "HF_TOKEN": "huggingface",
    "OPENROUTER_API_KEY": "openrouter",
    "OLLAMA_HOST": "ollama",
}

PROVIDER_CODE_PATTERNS = {
    "openai": (
        r"\bfrom\s+openai\s+import\b",
        r"\bimport\s+openai\b",
        r"\bapi\.openai\.com\b",
        r"\bmodel\s*[:=]\s*[\"'][^\"']*gpt",
    ),
    "anthropic": (
        r"\bfrom\s+anthropic\s+import\b",
        r"\bimport\s+anthropic\b",
        r"\bapi\.anthropic\.com\b",
        r"\bmodel\s*[:=]\s*[\"'][^\"']*claude",
    ),
    "google-gemini": (
        r"\bgoogle\.generativeai\b",
        r"\bgenerative(language|ai)\b",
        r"\bmodel\s*[:=]\s*[\"'][^\"']*gemini",
    ),
    "mistral": (
        r"\bfrom\s+mistralai\s+import\b",
        r"\bimport\s+mistral(ai)?\b",
        r"\bapi\.mistral\.ai\b",
        r"\bmodel\s*[:=]\s*[\"'][^\"']*mistral",
    ),
    "together": (
        r"\bfrom\s+together\s+import\b",
        r"\bimport\s+together\b",
        r"\bapi\.together\.xyz\b",
    ),
    "cohere": (
        r"\bfrom\s+cohere\s+import\b",
        r"\bimport\s+cohere\b",
        r"\bapi\.cohere\.ai\b",
    ),
    "replicate": (
        r"\bfrom\s+replicate\s+import\b",
        r"\bimport\s+replicate\b",
        r"\bapi\.replicate\.com\b",
    ),
    "huggingface": (
        r"\bfrom\s+transformers\s+import\b",
        r"\bfrom\s+huggingface_hub\s+import\b",
        r"\bhuggingface[_-]?hub\b",
        r"\bhf\.co\b",
    ),
    "ollama": (
        r"\bollama\b",
        r"\bOLLAMA_HOST\b",
        r"\bmodelfile\b",
    ),
}

SESSION_STORE_FILENAMES = (
    "ainternet_sessions.json",
    "phantom_sessions.json",
    "ai_teams_sessions.json",
    "kevin_sessions.json",
    "jis_handoff_history.json",
)


def _default_code_status() -> dict[str, str]:
    """Return mutable code coverage status based on the package baseline."""
    return {code: info.coverage for code, info in CLUSTER_CODES.items()}


def _cluster_sources(
    cluster: BSICluster,
    overlay: dict[str, Any] | None = None,
    workspace_mode: bool = False,
) -> str:
    """Human-readable evidence/source mapping per cluster."""
    overlay = overlay or {}
    models = _normalize_overlay_list(overlay.get("models"))
    datasets = _normalize_overlay_list(overlay.get("datasets"))
    kpis = _normalize_overlay_list(overlay.get("kpi"))
    system = overlay.get("system") if isinstance(overlay.get("system"), dict) else {}
    infrastructure = overlay.get("infrastructure") if isinstance(overlay.get("infrastructure"), dict) else {}
    model_evidence = overlay.get("_model_evidence") if isinstance(overlay.get("_model_evidence"), dict) else {}
    model_signal_count = sum(
        len(model_evidence.get(key, []))
        for key in ("declared_models", "local_model_artifacts", "runtime_model_signals", "external_model_providers")
        if isinstance(model_evidence.get(key), list)
    )

    source_map = {
        BSICluster.METADATA: "document metadata, timestamp, tool version",
        BSICluster.SYSTEM_LEVEL_PROPERTIES: (
            "project identity today; workspace topology later"
            if not system else "project identity plus declared system object"
        ),
        BSICluster.MODELS: (
            "declared model overlay"
            if models else ("artifact/provider/actor model evidence" if model_signal_count else "not yet modeled")
        ),
        BSICluster.DATASET_PROPERTIES: (
            "declared dataset overlay"
            if datasets else "not yet modeled"
        ),
        BSICluster.INFRASTRUCTURE: (
            "scan node, manifest families, workspace topology"
            if not infrastructure else
            "scan node, manifest families, workspace topology, declared infrastructure"
        ),
        BSICluster.SECURITY_PROPERTIES: "vulnerability view, provenance tokens, evidence links later",
        BSICluster.KEY_PERFORMANCE_INDICATORS: (
            "declared KPI overlay"
            if kpis else "not yet modeled"
        ),
    }
    return source_map[cluster]


def _cluster_status_objects(
    code_status: dict[str, str],
    overlay: dict[str, Any] | None = None,
    workspace_mode: bool = False,
) -> list[dict]:
    """Structured cluster coverage view for JSON output."""
    rows: list[dict] = []
    for cluster in BSICluster:
        counts = {"covered": 0, "partial": 0, "missing": 0}
        for item in list_cluster_codes(cluster):
            cov = code_status.get(item.code, item.coverage)
            counts[cov] = counts.get(cov, 0) + 1
        rows.append(
            {
                "cluster": cluster.name,
                "prefix": cluster.value,
                "covered": counts["covered"],
                "partial": counts["partial"],
                "missing": counts["missing"],
                "current_sources": _cluster_sources(cluster, overlay=overlay, workspace_mode=workspace_mode),
            }
        )
    return rows


def _missing_reason_map(code_status: dict[str, str]) -> dict[str, str]:
    """Explain only the clusters that still have real missing elements."""
    reasons: dict[str, str] = {}
    if any(code_status.get(code) == "missing" for code in (
        "AISBOM-MOD-001", "AISBOM-MOD-002", "AISBOM-MOD-003", "AISBOM-MOD-004"
    )):
        reasons["models"] = (
            "Model support is still incomplete. "
            "At least one of identifier/version, hashes, training lineage, "
            "or inference properties is still not declared."
        )
    if any(code_status.get(code) == "missing" for code in (
        "AISBOM-DSE-001", "AISBOM-DSE-002", "AISBOM-DSE-003"
    )):
        reasons["datasets"] = (
            "Dataset support is still incomplete. "
            "At least one of identity/hash, provenance, or sensitivity "
            "classification is still not declared."
        )
    if any(code_status.get(code) == "missing" for code in (
        "AISBOM-KPI-001", "AISBOM-KPI-002", "AISBOM-KPI-003"
    )):
        reasons["kpi"] = (
            "KPI support is still incomplete. "
            "Measured security, operational, or drift metrics are still missing."
        )
    return reasons


def _artifact_evidence_placeholders() -> dict:
    """Reserve the next-layer AI-SBOM surfaces in scan output."""
    return {
        "artifacts": {
            "sealed_tbz_objects": 0,
            "signed_non_tbz_references": 0,
            "unsigned_external_objects": 0,
            "encryption_boundary": {
                "v1_unencrypted_supported": False,
                "v2_encrypted_supported": False,
                "status": "planned",
            },
        },
        "evidence": {
            "tibet_chain_of_command": "planned",
            "tibet_usage_custody": "planned",
            "continuity_links": "planned",
            "signed_list_boundary": "planned",
        },
    }


def _json_type_matches(value: Any, expected: str) -> bool:
    """Minimal JSON Schema type matcher for local validation."""
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return (isinstance(value, int) or isinstance(value, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    return True


def _validate_against_schema(
    value: Any,
    schema: dict[str, Any],
    path: str = "$",
) -> list[str]:
    """Small built-in validator for the package schema subset we use."""
    errors: list[str] = []
    expected_type = schema.get("type")
    if expected_type is not None:
        allowed = expected_type if isinstance(expected_type, list) else [expected_type]
        if not any(_json_type_matches(value, item) for item in allowed):
            joined = "|".join(str(item) for item in allowed)
            return [f"{path}: expected type {joined}, got {type(value).__name__}"]

    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: expected const {schema['const']!r}, got {value!r}")

    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: expected one of {schema['enum']!r}, got {value!r}")

    if isinstance(value, dict):
        required = schema.get("required", [])
        for key in required:
            if key not in value:
                errors.append(f"{path}: missing required property {key!r}")
        properties = schema.get("properties", {})
        for key, child in properties.items():
            if key in value and isinstance(child, dict):
                errors.extend(_validate_against_schema(value[key], child, f"{path}.{key}"))
        additional = schema.get("additionalProperties", True)
        if isinstance(additional, dict):
            known = set(properties.keys())
            for key, child_value in value.items():
                if key not in known:
                    errors.extend(_validate_against_schema(child_value, additional, f"{path}.{key}"))
        elif additional is False:
            known = set(properties.keys())
            for key in value:
                if key not in known:
                    errors.append(f"{path}: unexpected property {key!r}")

    if isinstance(value, list):
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for idx, item in enumerate(value):
                errors.extend(_validate_against_schema(item, item_schema, f"{path}[{idx}]"))

    return errors


def _convention_warnings(document: dict[str, Any]) -> list[str]:
    """Emit pragmatic warnings beyond strict schema validity."""
    warnings: list[str] = []
    artifacts = document.get("artifacts", {}) if isinstance(document.get("artifacts"), dict) else {}
    evidence = document.get("evidence", {}) if isinstance(document.get("evidence"), dict) else {}
    evidence_details = evidence.get("details", {}) if isinstance(evidence.get("details"), dict) else {}
    overlay = document.get("overlay", {}) if isinstance(document.get("overlay"), dict) else {}
    code_status = document.get("code_status", {}) if isinstance(document.get("code_status"), dict) else {}
    models = document.get("models", {}) if isinstance(document.get("models"), dict) else {}
    discovered_model_count = sum(
        len(models.get(key, []))
        for key in ("declared_models", "local_model_artifacts", "runtime_model_signals", "external_model_providers")
        if isinstance(models.get(key), list)
    )

    trail_sources = int(evidence_details.get("trail_source_count", 0) or 0)
    token_trail_sources = int(evidence_details.get("token_trail_source_count", 0) or 0)
    if trail_sources > 0 and token_trail_sources == 0:
        warnings.append(
            "Trail sources were found, but none matched the open token-trail record shape "
            "(token_id/action/actor/timestamp)."
        )

    unsigned_external = int(artifacts.get("unsigned_external_objects", 0) or 0)
    signed_non_tbz = int(artifacts.get("signed_non_tbz_references", 0) or 0)
    if unsigned_external > 0 and signed_non_tbz == 0:
        warnings.append(
            "Unsigned external objects are present while no signed non-TBZ references were declared."
        )

    encryption = artifacts.get("encryption_boundary", {}) if isinstance(artifacts.get("encryption_boundary"), dict) else {}
    if encryption.get("v2_encrypted_supported") is not True:
        warnings.append("V2 encrypted artifact support is not declared yet.")

    if overlay.get("loaded") is False and discovered_model_count == 0:
        for prefix, label in (("AISBOM-MOD-", "models"), ("AISBOM-DSE-", "datasets"), ("AISBOM-KPI-", "kpi")):
            if any(code_status.get(code) == "missing" for code in code_status if code.startswith(prefix)):
                warnings.append(
                    f"No overlay was loaded, so {label} remain dependent on future auto-discovery or manual declaration."
                )
                break

    return warnings


def _load_document_input(input_path: Path) -> tuple[dict[str, Any] | None, str | None]:
    """Load an existing ai-sbom-json document from disk."""
    try:
        payload = json.loads(input_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return None, f"invalid JSON document {input_path}: {exc}"
    if not isinstance(payload, dict):
        return None, f"document {input_path} is not a JSON object"
    return payload, None


def _parse_iso_datetime(value: Any) -> datetime | None:
    """Parse permissive ISO timestamps used by local JSON stores."""
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _file_mtime_iso(path: Path) -> str | None:
    """Return file mtime as ISO8601 UTC string."""
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat()
    except Exception:
        return None


def _session_store_candidates(scan_path: Path) -> list[Path]:
    """Return known JIS/AInternet session stores in preference order."""
    candidates: list[Path] = []
    data_dirs = [
        scan_path / "data",
        Path("/srv/jtel-stack/brain_api/data"),
    ]
    seen: set[str] = set()
    for data_dir in data_dirs:
        for name in SESSION_STORE_FILENAMES:
            path = data_dir / name
            key = str(path)
            if key in seen:
                continue
            seen.add(key)
            candidates.append(path)
    return candidates


def _classify_session_route(ip: Any) -> str:
    """Provide an interim route classification from session IP evidence."""
    if not isinstance(ip, str) or not ip.strip():
        return "unknown"
    value = ip.strip().lower()
    if value in {"127.0.0.1", "::1", "localhost"}:
        return "local"
    if value.startswith("10.") or value.startswith("192.168.") or value.startswith("172.16.") or value.startswith("172.17.") or value.startswith("172.18.") or value.startswith("172.19.") or value.startswith("172.2") or value.startswith("172.30.") or value.startswith("172.31."):
        return "direct"
    return "interim-session"


def _infer_provider_from_target_url(url: Any) -> str | None:
    """Infer provider from well-known API hostnames."""
    if not isinstance(url, str) or not url.strip():
        return None
    value = url.strip().lower()
    if "api.openai.com" in value:
        return "openai"
    if "api.anthropic.com" in value:
        return "anthropic"
    if "generativelanguage.googleapis.com" in value or "vertex" in value or "googleapis.com" in value:
        return "google-gemini"
    if "huggingface.co" in value or "hf.co" in value:
        return "huggingface"
    if ":11434" in value or "ollama" in value:
        return "ollama"
    if "api.together.xyz" in value:
        return "together"
    if "api.cohere.ai" in value:
        return "cohere"
    if "replicate.com" in value:
        return "replicate"
    return None


def _extract_model_name_from_payload(payload: Any) -> str | None:
    """Extract a model identifier from common gateway/API payload shapes."""
    if isinstance(payload, dict):
        for key in ("model", "model_name", "resolved_model", "used_model"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        body = payload.get("payload")
        if isinstance(body, dict):
            nested = _extract_model_name_from_payload(body)
            if nested:
                return nested
    return None


def _gateway_log_candidates(scan_path: Path) -> list[Path]:
    """Return known Tier B gateway log candidates."""
    candidates: list[Path] = []
    for env_name in ("TIBET_GATEWAY_EVENT_LOG", "TIBET_GATEWAY_LOG"):
        env_log = os.getenv(env_name, "").strip()
        if env_log:
            candidates.append(Path(env_log))
    candidates.extend([
        scan_path / "data" / "tibet_gateway.jsonl",
        scan_path / "data" / "gateway_events.jsonl",
        scan_path / ".tibet" / "gateway.jsonl",
        Path("/var/log/tibet/gateway.jsonl"),
        Path("/var/log/tibet/tibet_gateway.jsonl"),
        Path("/var/lib/tibet/gateway.jsonl"),
    ])
    seen: set[str] = set()
    result: list[Path] = []
    for path in candidates:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        result.append(path)
    return result


def _gateway_config_file_candidates(scan_path: Path, limit: int = 250) -> list[Path]:
    """Discover repo-local files that likely describe gateway/provider lanes."""
    preferred_names = {
        "byok_providers.py",
        "external_api_wrapper.py",
        "tibet_tracking.py",
        "tool_gateway.py",
        "gateway.py",
    }
    discovered: list[Path] = []
    seen: set[str] = set()

    for name in preferred_names:
        direct = scan_path / name
        if direct.exists() and direct.is_file():
            key = str(direct)
            if key not in seen:
                seen.add(key)
                discovered.append(direct)

    for path in _walk_candidate_files(scan_path, limit=limit):
        if path.name not in preferred_names:
            continue
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        discovered.append(path)

    return discovered[:50]


def _load_jis_session_records(scan_path: Path, limit: int = 400) -> list[dict[str, Any]]:
    """Load JIS/AInternet session records from known local stores."""
    records: list[dict[str, Any]] = []
    for store in _session_store_candidates(scan_path):
        payload = _read_json_if_exists(store)
        if not isinstance(payload, dict):
            continue
        for session_id, data in payload.items():
            if len(records) >= limit:
                return records
            if not isinstance(data, dict):
                continue
            domain = str(data.get("domain") or "").strip()
            if not domain:
                continue
            records.append({
                "store": str(store),
                "store_name": store.name,
                "session_id": session_id,
                "domain": domain,
                "pubkey_fingerprint": data.get("pubkey_fingerprint"),
                "created_at": data.get("created_at"),
                "expires_at": data.get("expires_at"),
                "last_seen": data.get("last_seen"),
                "ip": data.get("ip"),
            })
    records.sort(
        key=lambda item: str(item.get("last_seen") or item.get("created_at") or ""),
        reverse=True,
    )
    return records[:limit]


def _build_summary_from_args(args) -> tuple[dict[str, Any] | None, int]:
    """Create scan summary from CLI args for export/validate reuse."""
    path = Path(args.path or ".").resolve()
    if not path.exists():
        print(f"path not found: {path}", file=sys.stderr)
        return None, 2

    if bool(getattr(args, "focused", False)):
        return _focused_scan_summary(path, getattr(args, "overlay", None), getattr(args, "trail_file", None), bool(getattr(args, "workspace", False)))

    if bool(args.workspace):
        return _workspace_scan_summary(path, getattr(args, "overlay", None), getattr(args, "trail_file", None))
    return _single_root_scan_summary(path, getattr(args, "overlay", None), getattr(args, "trail_file", None))


def _load_overlay(scan_path: Path, overlay_path: str | None) -> tuple[dict[str, Any], str | None]:
    """Load optional AI-SBOM overlay JSON for models/datasets/KPI/etc."""
    candidates: list[Path] = []
    if overlay_path:
        candidates.append(Path(overlay_path).expanduser().resolve())
    else:
        base = scan_path if scan_path.is_dir() else scan_path.parent
        candidates.extend([
            base / "ai-sbom.json",
            base / ".ai-sbom.json",
        ])

    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            try:
                data = json.loads(candidate.read_text(encoding="utf-8"))
            except Exception as exc:
                print(f"invalid overlay JSON: {candidate}: {exc}", file=sys.stderr)
                return {}, str(candidate)
            return data if isinstance(data, dict) else {}, str(candidate)
    return {}, None


def _normalize_overlay_list(value: Any) -> list[dict]:
    """Normalize overlay list sections to a list of dicts."""
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _walk_candidate_files(base: Path, limit: int = 4000) -> list[Path]:
    """Collect a bounded set of files under a scan root."""
    skip_dirs = {
        ".git", ".hg", ".svn", ".venv", "venv", "node_modules",
        "__pycache__", "dist", "build", "target", ".mypy_cache",
        ".pytest_cache", ".conversation_history", "static", "server-config",
        "sql", "cia_rag", ".next", "coverage",
    }
    results: list[Path] = []
    if base.is_file():
        return [base]
    for root, dirs, files in os.walk(base):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        root_path = Path(root)
        for name in files:
            results.append(root_path / name)
            if len(results) >= limit:
                return results
    return results


def _guess_model_name(path: Path) -> str | None:
    """Best-effort extraction of a model-ish name from a path."""
    lowered = path.stem.lower()
    for token in MODEL_NAME_PATTERNS:
        if token in lowered:
            return path.stem
    parent = path.parent.name.lower()
    for token in MODEL_NAME_PATTERNS:
        if token in parent:
            return path.parent.name
    return None


def _file_has_model_header(path: Path) -> bool:
    """Lightweight header sniff for a few exact model container formats."""
    try:
        with path.open("rb") as fh:
            head = fh.read(32)
    except Exception:
        return False
    return (
        head.startswith(b"GGUF")
        or head.startswith(b"ONNX")
        or b"safetensors" in head.lower()
    )


def _is_large_unknown_blob(path: Path) -> bool:
    """Heuristic for undeclared large binary payloads."""
    try:
        size = path.stat().st_size
    except Exception:
        return False
    if size < 100 * 1024 * 1024:
        return False
    suffix = path.suffix.lower()
    if suffix in MODEL_EXTENSIONS:
        return False
    if suffix in {".zip", ".tar", ".gz", ".xz", ".bz2", ".7z"}:
        return True
    return suffix in {"", ".dat", ".blob", ".weights"} or size > 1024 * 1024 * 1024


def _discover_actor_signals(scan_path: Path) -> dict[str, Any]:
    """Find .aint and actor-like references that imply agent identities."""
    target_files = [
        scan_path / "ains_registry.json",
        scan_path / "aindex.json",
        scan_path / "jis_grants.json",
        scan_path / "main.py",
        scan_path / "buddy_endpoints.py",
        scan_path / "aindex_api.py",
        scan_path / "ainternet_api.py",
        scan_path / "ipoll_matrix_bridge.py",
    ]
    files = [p for p in target_files if p.exists() and p.is_file()]
    if not files:
        files = _walk_candidate_files(scan_path, limit=300)
    actor_refs: set[str] = set()
    aint_refs: set[str] = set()
    agentish_files: list[str] = []
    patt = re.compile(r"\b([a-z0-9_.-]+\.aint)\b", re.IGNORECASE)
    for path in files:
        if path.suffix.lower() not in {".md", ".txt", ".json", ".jsonl", ".yaml", ".yml", ".py", ".toml", ".env"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        found = patt.findall(text)
        if found:
            agentish_files.append(str(path))
            for item in found:
                aint_refs.add(item.lower())
                actor_refs.add(item.lower())
        for marker in ("actor_id", "agent_id", "root_ai", "continuityd", "ipoll", "jis:"):
            if marker in text.lower():
                agentish_files.append(str(path))
                break
    return {
        "aint_ref_count": len(aint_refs),
        "actor_ref_count": len(actor_refs),
        "aint_refs": sorted(aint_refs)[:50],
        "actor_refs": sorted(actor_refs)[:50],
        "agentish_files": sorted(set(agentish_files))[:50],
    }


def _read_json_if_exists(path: Path) -> dict[str, Any] | list[Any] | None:
    """Read a JSON file if present and valid."""
    if not path.exists() or not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _discover_declared_model_configs(scan_path: Path) -> list[dict[str, Any]]:
    """Discover project-declared models from known config/code shapes."""
    declared: list[dict[str, Any]] = []

    ai_models_config = scan_path / "ai_models_config.py"
    if ai_models_config.exists():
        try:
            text = ai_models_config.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            text = ""
        entry_re = re.compile(r'"([^"]+)"\s*:\s*\{([^{}]*?)\}', re.DOTALL)
        for match in entry_re.finditer(text):
            name = match.group(1)
            body = match.group(2)
            if "provider" not in body and "_id" not in body:
                continue
            provider_match = re.search(r'"provider"\s*:\s*"([^"]+)"', body)
            anthropic_id = re.search(r'"anthropic_id"\s*:\s*"([^"]+)"', body)
            vertex_id = re.search(r'"vertex_id"\s*:\s*"([^"]+)"', body)
            provider = provider_match.group(1) if provider_match else ("vertex" if vertex_id else "anthropic" if anthropic_id else "declared")
            identifier = anthropic_id.group(1) if anthropic_id else vertex_id.group(1) if vertex_id else name
            declared.append({
                "name": name,
                "identifier": identifier,
                "version_or_tag": name,
                "source_kind": "declared-model",
                "evidence_grade": "declared",
                "locality": "remote" if provider in {"anthropic", "vertex", "openai", "google"} else "local",
                "provider": provider,
                "artifact_path": None,
                "config_path": str(ai_models_config),
                "hash": None,
                "risk_flags": [],
            })

    modelfile = scan_path / "snaft_modelfile.txt"
    if modelfile.exists():
        try:
            text = modelfile.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            text = ""
        from_match = re.search(r"^FROM\s+([^\s]+)", text, re.MULTILINE)
        if from_match:
            model = from_match.group(1).strip()
            declared.append({
                "name": model,
                "identifier": f"ollama:{model}",
                "version_or_tag": model,
                "source_kind": "declared-model",
                "evidence_grade": "declared",
                "locality": "local",
                "provider": "ollama",
                "artifact_path": str(modelfile),
                "config_path": str(modelfile),
                "hash": None,
                "risk_flags": [],
            })

    env_candidates = [
        scan_path / ".env",
        scan_path / ".env.bak-rotate-20260501-064851",
    ]
    env_model_re = re.compile(r"^([A-Z0-9_]*MODEL[A-Z0-9_]*)=(.+)$", re.MULTILINE)
    for env_file in env_candidates:
        if not env_file.exists():
            continue
        try:
            text = env_file.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for key, raw_value in env_model_re.findall(text):
            value = raw_value.strip().strip('"').strip("'")
            if not value or value.startswith("#"):
                continue
            provider = "ollama" if ":" in value and "http" not in value else "declared"
            declared.append({
                "name": value,
                "identifier": f"{provider}:{value}",
                "version_or_tag": value,
                "source_kind": "declared-model",
                "evidence_grade": "declared",
                "locality": "local" if provider == "ollama" else "unknown",
                "provider": provider,
                "artifact_path": None,
                "config_path": str(env_file),
                "hash": None,
                "risk_flags": [],
                "declared_via": key,
            })

    unique: dict[tuple[str | None, str | None, str | None], dict[str, Any]] = {}
    for item in declared:
        key = (item.get("name"), item.get("identifier"), item.get("config_path"))
        unique[key] = item
    return list(unique.values())[:100]


def _discover_actor_identities(scan_path: Path, base_signals: dict[str, Any]) -> dict[str, Any]:
    """Enrich actor signals with AINS, AIndex and JIS identity sources."""
    enriched = dict(base_signals)
    aint_refs = set(base_signals.get("aint_refs", []))
    actor_refs = set(base_signals.get("actor_refs", []))
    agent_ids: set[str] = set()
    jis_ids: set[str] = set()
    session_fingerprints: set[str] = set()
    actor_records: list[dict[str, Any]] = []
    actor_catalog: dict[str, dict[str, Any]] = {}

    def _upsert_actor(identity: str, **fields: Any) -> None:
        if not identity:
            return
        current = actor_catalog.get(identity, {"identity": identity})
        entity_type = fields.get("entity_type")
        if entity_type in {None, "", "null"}:
            entity_type = current.get("entity_type")
        normalized = {
            **current,
            **fields,
            "entity_type": entity_type or current.get("entity_type") or "unknown",
        }
        actor_catalog[identity] = normalized

    json_candidates = [
        scan_path / "ains_registry.json",
        scan_path / "aindex.json",
        scan_path / "jis_grants.json",
    ]
    for path in json_candidates:
        payload = _read_json_if_exists(path)
        if payload is None:
            continue
        if path.name == "ains_registry.json" and isinstance(payload, dict):
            for domain, data in payload.get("domains", {}).items():
                aint_refs.add(domain.lower())
                agent = str(data.get("agent", "")).strip()
                if agent:
                    agent_ids.add(agent)
                    actor_refs.add(agent.lower())
                    _upsert_actor(
                        agent,
                        entity_type=data.get("entity_type", "ai"),
                        aint_domain=domain,
                        owner=data.get("owner"),
                        endpoint=data.get("endpoint"),
                        source=str(path),
                    )
                _upsert_actor(
                    domain.lower(),
                    entity_type=data.get("entity_type", "ai"),
                    aint_domain=domain,
                    owner=data.get("owner"),
                    endpoint=data.get("endpoint"),
                    source=str(path),
                )
                actor_records.append({
                    "source": str(path),
                    "kind": "ains-domain",
                    "aint_domain": domain,
                    "agent_id": agent or None,
                    "owner": data.get("owner"),
                    "entity_type": data.get("entity_type", "ai"),
                })
        elif path.name == "aindex.json" and isinstance(payload, dict):
            for agent in payload.get("agents", []):
                if not isinstance(agent, dict):
                    continue
                agent_id = str(agent.get("agent_id", "")).strip()
                if agent_id:
                    agent_ids.add(agent_id)
                    actor_refs.add(agent_id.lower())
                    _upsert_actor(
                        agent_id,
                        entity_type=agent.get("entity_type", "ai"),
                        aint_domain=agent.get("ains_domain"),
                        owner=agent.get("owner"),
                        team=agent.get("team"),
                        source=str(path),
                    )
                domain = agent.get("ains_domain")
                if isinstance(domain, str) and domain:
                    aint_refs.add(domain.lower())
                    _upsert_actor(
                        domain.lower(),
                        entity_type=agent.get("entity_type", "ai"),
                        aint_domain=domain,
                        owner=agent.get("owner"),
                        team=agent.get("team"),
                        source=str(path),
                    )
                actor_records.append({
                    "source": str(path),
                    "kind": "aindex-agent",
                    "agent_id": agent_id or None,
                    "aint_domain": domain,
                    "entity_type": agent.get("entity_type", "ai"),
                    "team": agent.get("team"),
                })
        elif path.name == "jis_grants.json" and isinstance(payload, dict):
            for grant in payload.get("grants", []):
                if not isinstance(grant, dict):
                    continue
                for key in ("principal_jis", "actor_jis"):
                    value = grant.get(key)
                    if isinstance(value, str) and value.startswith("jis:"):
                        jis_ids.add(value)
                        actor_refs.add(value.lower())
                        _upsert_actor(
                            value,
                            entity_type="jis-identity",
                            source=str(path),
                        )
                        actor_records.append({
                            "source": str(path),
                            "kind": "jis-grant",
                            "jis_id": value,
                            "field": key,
                        })

    for session in _load_jis_session_records(scan_path, limit=400):
        domain = str(session.get("domain") or "").strip()
        if not domain:
            continue
        identity = domain if domain.endswith(".aint") else f"{domain}.aint"
        aint_refs.add(identity.lower())
        actor_refs.add(domain.lower())
        actor_refs.add(identity.lower())
        fingerprint = str(session.get("pubkey_fingerprint") or "").strip()
        if fingerprint and fingerprint.lower() != "none":
            session_fingerprints.add(fingerprint)
        _upsert_actor(
            identity.lower(),
            entity_type="agent",
            aint_domain=identity,
            endpoint=session.get("ip"),
            pubkey_fingerprint=fingerprint or None,
            last_seen=session.get("last_seen"),
            source=session.get("store"),
        )
        _upsert_actor(
            domain,
            entity_type="agent",
            aint_domain=identity,
            endpoint=session.get("ip"),
            pubkey_fingerprint=fingerprint or None,
            last_seen=session.get("last_seen"),
            source=session.get("store"),
        )
        actor_records.append({
            "source": session.get("store"),
            "kind": "jis-session",
            "session_id": session.get("session_id"),
            "aint_domain": identity,
            "pubkey_fingerprint": fingerprint or None,
            "last_seen": session.get("last_seen"),
            "ip": session.get("ip"),
        })

    enriched["aint_refs"] = sorted(aint_refs)[:100]
    enriched["actor_refs"] = sorted(actor_refs)[:100]
    enriched["agent_ids"] = sorted(agent_ids)[:100]
    enriched["jis_ids"] = sorted(jis_ids)[:100]
    enriched["session_fingerprints"] = sorted(session_fingerprints)[:100]
    enriched["aint_ref_count"] = len(aint_refs)
    enriched["actor_ref_count"] = len(actor_refs)
    enriched["agent_id_count"] = len(agent_ids)
    enriched["jis_id_count"] = len(jis_ids)
    enriched["session_fingerprint_count"] = len(session_fingerprints)
    enriched["session_count"] = len([r for r in actor_records if r.get("kind") == "jis-session"])
    enriched["actor_records"] = actor_records[:100]
    enriched["actor_catalog"] = sorted(actor_catalog.values(), key=lambda item: str(item.get("identity", "")))[:200]
    return enriched


def _discover_external_model_providers(scan_path: Path) -> list[dict[str, Any]]:
    """Detect remote model provider configuration without exposing secrets."""
    providers: dict[str, dict[str, Any]] = {}
    for env_name, provider in PROVIDER_ENV_VARS.items():
        present = env_name in os.environ and bool(os.environ.get(env_name))
        if present:
            record = providers.setdefault(provider, {
                "name": provider,
                "identifier": provider,
                "version_or_tag": None,
                "source_kind": "remote-inference-provider",
                "evidence_grade": "externally-configured",
                "locality": "remote" if provider != "ollama" else "hybrid",
                "provider": provider,
                "credential_present": False,
                "credential_source": None,
                "execution_mode": "remote" if provider != "ollama" else "hybrid",
                "data_boundary": "outbound-inference" if provider != "ollama" else "hybrid",
                "models_referenced": [],
                "risk_flags": ["external-provider-configured"] if provider != "ollama" else [],
                "evidence_sources": [],
            })
            record["credential_present"] = True
            record["credential_source"] = "env"
            record["evidence_sources"].append(f"env:{env_name}")

    target_files = [
        scan_path / "ai_models_config.py",
        scan_path / "external_providers.py",
        scan_path / "main.py",
        scan_path / "kit_live_endpoint.py",
        scan_path / "humotica_os_api.py",
        scan_path / "byok_providers.py",
        scan_path / ".env",
        scan_path / ".env.bak-rotate-20260501-064851",
    ]
    files = [p for p in target_files if p.exists() and p.is_file()]
    if not files:
        files = _walk_candidate_files(scan_path, limit=400)
    for path in files:
        if path.suffix.lower() not in {".py", ".json", ".jsonl", ".yaml", ".yml", ".toml", ".env", ".js", ".ts"}:
            continue
        if path.name in {"cli.py"} and "tibet_ai_sbom" in str(path):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore").lower()
        except Exception:
            continue
        for provider, patterns in PROVIDER_CODE_PATTERNS.items():
            if any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns):
                record = providers.setdefault(provider, {
                    "name": provider,
                    "identifier": provider,
                    "version_or_tag": None,
                    "source_kind": "remote-inference-provider",
                    "evidence_grade": "externally-configured" if provider != "ollama" else "runtime-confirmed",
                    "locality": "remote" if provider != "ollama" else "hybrid",
                    "provider": provider,
                    "credential_present": False,
                    "credential_source": None,
                    "execution_mode": "remote" if provider != "ollama" else "hybrid",
                    "data_boundary": "outbound-inference" if provider != "ollama" else "hybrid",
                    "models_referenced": [],
                    "risk_flags": ["external-provider-configured"] if provider != "ollama" else [],
                    "evidence_sources": [],
                })
                record["evidence_sources"].append(str(path))

    env_candidates = [
        scan_path / ".env",
        scan_path / ".env.bak-rotate-20260501-064851",
    ]
    for env_file in env_candidates:
        if not env_file.exists():
            continue
        try:
            text = env_file.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for env_name, provider in PROVIDER_ENV_VARS.items():
            if re.search(rf"^{re.escape(env_name)}=", text, re.MULTILINE):
                record = providers.setdefault(provider, {
                    "name": provider,
                    "identifier": provider,
                    "version_or_tag": None,
                    "source_kind": "remote-inference-provider",
                    "evidence_grade": "externally-configured",
                    "locality": "remote" if provider != "ollama" else "hybrid",
                    "provider": provider,
                    "credential_present": env_name.endswith("_API_KEY") or env_name.endswith("_TOKEN"),
                    "credential_source": "env-file",
                    "execution_mode": "remote" if provider != "ollama" else "hybrid",
                    "data_boundary": "outbound-inference" if provider != "ollama" else "hybrid",
                    "models_referenced": [],
                    "risk_flags": ["external-provider-configured"] if provider != "ollama" else [],
                    "evidence_sources": [],
                })
                record["evidence_sources"].append(str(env_file))

    if (scan_path / "ai_models_config.py").exists():
        declared = _discover_declared_model_configs(scan_path)
        for item in declared:
            provider = str(item.get("provider", "")).lower()
            if provider in {"anthropic", "vertex", "openai", "google", "google-gemini"}:
                record = providers.setdefault(provider, {
                    "name": provider,
                    "identifier": provider,
                    "version_or_tag": None,
                    "source_kind": "remote-inference-provider",
                    "evidence_grade": "externally-configured",
                    "locality": "remote",
                    "provider": provider,
                    "credential_present": False,
                    "credential_source": None,
                    "execution_mode": "remote",
                    "data_boundary": "outbound-inference",
                    "models_referenced": [],
                    "risk_flags": ["external-provider-configured"],
                    "evidence_sources": [],
                })
                if item.get("name"):
                    record["models_referenced"].append(item["name"])
                if item.get("config_path"):
                    record["evidence_sources"].append(str(item["config_path"]))
    return sorted(
        [{
            **item,
            "models_referenced": sorted(set(item["models_referenced"]))[:20],
            "evidence_sources": sorted(set(item["evidence_sources"]))[:20],
        } for item in providers.values()],
        key=lambda item: item["provider"],
    )


def _discover_model_evidence(scan_path: Path) -> dict[str, Any]:
    """Collect broad model evidence lanes from the scan path."""
    files = _walk_candidate_files(scan_path, limit=2500)
    local_model_artifacts: list[dict[str, Any]] = []
    suspicious_candidates: list[dict[str, Any]] = []
    runtime_model_signals: list[dict[str, Any]] = []
    sidecar_dirs: dict[str, set[str]] = {}

    for path in files:
        name_l = path.name.lower()
        if name_l in MODEL_SIDECARS:
            sidecar_dirs.setdefault(str(path.parent), set()).add(path.name)

    for path in files:
        suffix = path.suffix.lower()
        artifact_kind = MODEL_EXTENSIONS.get(suffix)
        model_name = _guess_model_name(path)
        try:
            size = path.stat().st_size
        except Exception:
            size = None

        if artifact_kind:
            source_kind, risk_flags = artifact_kind
            sidecars = sorted(sidecar_dirs.get(str(path.parent), set()))
            evidence_grade = "artifact-confirmed" if _file_has_model_header(path) or sidecars else "behaviorally-suspected"
            local_model_artifacts.append({
                "name": model_name,
                "identifier": f"file:{path}",
                "version_or_tag": None,
                "source_kind": source_kind,
                "evidence_grade": evidence_grade,
                "locality": "local",
                "provider": "filesystem",
                "artifact_path": str(path),
                "hash": None,
                "size_bytes": size,
                "supporting_files": sidecars,
                "risk_flags": list(risk_flags),
            })
            if suffix in {".pt", ".pth", ".pkl", ".joblib"}:
                suspicious_candidates.append({
                    "name": model_name,
                    "identifier": f"file:{path}",
                    "source_kind": "high_risk_loader",
                    "evidence_grade": "behaviorally-suspected",
                    "locality": "local",
                    "artifact_path": str(path),
                    "size_bytes": size,
                    "risk_flags": ["high-risk-serialization"],
                })
            continue

        if re.search(r"model-\d{5}-of-\d{5}", path.name.lower()):
            suspicious_candidates.append({
                "name": model_name,
                "identifier": f"file:{path}",
                "source_kind": "sharded_weight_candidate",
                "evidence_grade": "behaviorally-suspected",
                "locality": "local",
                "artifact_path": str(path),
                "size_bytes": size,
                "risk_flags": ["sharded-weight-pattern"],
            })
            continue

        if _is_large_unknown_blob(path):
            flags = ["unknown-large-binary", "undeclared-large-blob"]
            if path.suffix.lower() in {".zip", ".tar", ".gz", ".xz", ".bz2", ".7z"}:
                flags.append("compressed-weight-candidate")
            suspicious_candidates.append({
                "name": model_name,
                "identifier": f"blob:{path}",
                "source_kind": "undeclared_large_blob",
                "evidence_grade": "behaviorally-suspected",
                "locality": "local",
                "artifact_path": str(path),
                "size_bytes": size,
                "risk_flags": flags,
            })

    ollama_dir = Path.home() / ".ollama" / "models"
    if ollama_dir.exists():
        runtime_model_signals.append({
            "name": "ollama-local-cache",
            "identifier": f"dir:{ollama_dir}",
            "version_or_tag": None,
            "source_kind": "runtime-confirmed-model",
            "evidence_grade": "runtime-confirmed",
            "locality": "hybrid",
            "provider": "ollama",
            "artifact_path": str(ollama_dir),
            "risk_flags": [],
        })

    declared_models = _discover_declared_model_configs(scan_path)
    actor_signals = _discover_actor_identities(scan_path, _discover_actor_signals(scan_path))
    external_model_providers = _discover_external_model_providers(scan_path)
    return {
        "declared_models": declared_models,
        "local_model_artifacts": local_model_artifacts[:100],
        "runtime_model_signals": runtime_model_signals[:50],
        "external_model_providers": external_model_providers[:50],
        "suspicious_model_candidates": suspicious_candidates[:100],
        "actor_signals": actor_signals,
    }


def _upgrade_status(code_status: dict[str, str], code: str, new_status: str) -> None:
    order = {"missing": 0, "partial": 1, "covered": 2}
    current = code_status.get(code, "missing")
    if order.get(new_status, 0) > order.get(current, 0):
        code_status[code] = new_status


def _derive_dynamic_code_status(
    overlay: dict[str, Any],
    summary: dict[str, Any],
    workspace_mode: bool,
) -> dict[str, str]:
    """Adjust baseline cluster coverage using real scan and overlay data."""
    code_status = _default_code_status()

    if workspace_mode or summary.get("component_count", 0) > 0:
        _upgrade_status(code_status, "AISBOM-SLP-001", "partial")
        _upgrade_status(code_status, "AISBOM-INF-001", "partial")

    system = overlay.get("system")
    if isinstance(system, dict) and system:
        if any(system.get(k) for k in ("system_name", "system_version", "system_producer", "system_timestamp")):
            _upgrade_status(code_status, "AISBOM-SLP-001", "covered")
        if system.get("system_data_flow") or system.get("system_data_usage"):
            _upgrade_status(code_status, "AISBOM-SLP-002", "partial")
            if system.get("system_data_flow") and system.get("system_data_usage"):
                _upgrade_status(code_status, "AISBOM-SLP-002", "covered")
        if system.get("system_input_output_properties"):
            _upgrade_status(code_status, "AISBOM-SLP-003", "covered")
        if system.get("intended_application_area"):
            _upgrade_status(code_status, "AISBOM-SLP-004", "covered")

    models = _normalize_overlay_list(overlay.get("models"))
    discovered_models = summary.get("model_evidence", {}) if isinstance(summary.get("model_evidence"), dict) else {}
    local_model_artifacts = discovered_models.get("local_model_artifacts", []) if isinstance(discovered_models.get("local_model_artifacts"), list) else []
    runtime_model_signals = discovered_models.get("runtime_model_signals", []) if isinstance(discovered_models.get("runtime_model_signals"), list) else []
    external_model_providers = discovered_models.get("external_model_providers", []) if isinstance(discovered_models.get("external_model_providers"), list) else []
    suspicious_model_candidates = discovered_models.get("suspicious_model_candidates", []) if isinstance(discovered_models.get("suspicious_model_candidates"), list) else []
    if models:
        _upgrade_status(code_status, "AISBOM-MOD-001", "partial")
        if all(any(m.get(k) for k in ("model_name", "name")) and m.get("model_identifier") and m.get("model_version") for m in models):
            _upgrade_status(code_status, "AISBOM-MOD-001", "covered")
        if any(m.get("model_hash_value") or m.get("hash") for m in models):
            _upgrade_status(code_status, "AISBOM-MOD-002", "partial")
        if all((m.get("model_hash_value") or m.get("hash")) and (m.get("model_hash_algorithm") or m.get("hash_algorithm")) for m in models):
            _upgrade_status(code_status, "AISBOM-MOD-002", "covered")
        if any(m.get("model_training_properties") or m.get("training_properties") for m in models):
            _upgrade_status(code_status, "AISBOM-MOD-003", "covered")
        if any(m.get("model_input_output_properties") or m.get("input_output_properties") for m in models):
            _upgrade_status(code_status, "AISBOM-MOD-004", "covered")
    elif local_model_artifacts or runtime_model_signals or external_model_providers or suspicious_model_candidates:
        _upgrade_status(code_status, "AISBOM-MOD-001", "partial")
        if local_model_artifacts:
            _upgrade_status(code_status, "AISBOM-MOD-002", "partial")
        if external_model_providers:
            _upgrade_status(code_status, "AISBOM-MOD-004", "partial")

    datasets = _normalize_overlay_list(overlay.get("datasets"))
    if datasets:
        _upgrade_status(code_status, "AISBOM-DSE-001", "partial")
        if all((d.get("dataset_name") or d.get("name")) and d.get("dataset_identifier") and (d.get("dataset_hash") or d.get("hash")) for d in datasets):
            _upgrade_status(code_status, "AISBOM-DSE-001", "covered")
        if any(d.get("dataset_provenance") or d.get("provenance") for d in datasets):
            _upgrade_status(code_status, "AISBOM-DSE-002", "covered")
        if any(d.get("dataset_sensitivity") or d.get("sensitivity") for d in datasets):
            _upgrade_status(code_status, "AISBOM-DSE-003", "covered")

    infrastructure = overlay.get("infrastructure")
    if isinstance(infrastructure, dict) and infrastructure:
        if any(infrastructure.get(k) for k in ("infrastructure_software", "software", "runtime_environment")):
            _upgrade_status(code_status, "AISBOM-INF-001", "covered")
        if any(infrastructure.get(k) for k in ("infrastructure_hardware", "hardware", "accelerators")):
            _upgrade_status(code_status, "AISBOM-INF-002", "covered")
        if infrastructure.get("hbom_reference"):
            _upgrade_status(code_status, "AISBOM-INF-003", "covered")

    artifacts = overlay.get("artifacts")
    if isinstance(artifacts, dict) and artifacts:
        _upgrade_status(code_status, "AISBOM-SEC-001", "partial")
    evidence = overlay.get("evidence")
    if isinstance(evidence, dict) and evidence:
        _upgrade_status(code_status, "AISBOM-SEC-002", "partial")

    kpis = _normalize_overlay_list(overlay.get("kpi"))
    if kpis:
        for item in kpis:
            category = str(item.get("category", "")).lower()
            metric_name = str(item.get("name", "")).lower()
            if category == "security" or "security" in metric_name:
                _upgrade_status(code_status, "AISBOM-KPI-001", "covered")
            elif category in {"operational", "performance"} or "latency" in metric_name or "availability" in metric_name:
                _upgrade_status(code_status, "AISBOM-KPI-002", "covered")
            elif category == "drift" or "drift" in metric_name:
                _upgrade_status(code_status, "AISBOM-KPI-003", "covered")

    return code_status


def _artifact_evidence_from_overlay(overlay: dict[str, Any]) -> dict:
    """Merge artifact/evidence placeholders with declared overlay data."""
    base = _artifact_evidence_placeholders()
    artifacts = overlay.get("artifacts")
    if isinstance(artifacts, dict):
        sealed = _normalize_overlay_list(artifacts.get("sealed_tbz_objects"))
        signed = _normalize_overlay_list(artifacts.get("signed_non_tbz_references"))
        unsigned = _normalize_overlay_list(artifacts.get("unsigned_external_objects"))
        base["artifacts"] = {
            "sealed_tbz_objects": len(sealed),
            "signed_non_tbz_references": len(signed),
            "unsigned_external_objects": len(unsigned),
            "encryption_boundary": artifacts.get("encryption_boundary", base["artifacts"]["encryption_boundary"]),
            "details": artifacts,
        }
    evidence = overlay.get("evidence")
    if isinstance(evidence, dict):
        base["evidence"] = {
            "tibet_chain_of_command": "present" if evidence.get("tibet_chain_of_command") else "planned",
            "tibet_usage_custody": "present" if evidence.get("tibet_usage_custody") else "planned",
            "continuity_links": "present" if evidence.get("continuity_links") else "planned",
            "signed_list_boundary": "present" if evidence.get("signed_list_boundary") else "planned",
            "details": evidence,
        }
    return base


def _discover_project_trail_candidates(scan_path: Path) -> list[Path]:
    """Look for project-local TIBET trail files near the scan path."""
    base = scan_path if scan_path.is_dir() else scan_path.parent
    candidates = [
        base / ".tibet" / "provenance" / "audit.jsonl",
        base / ".tibet" / "provenance" / "trail.jsonl",
        base / ".tibet" / "provenance" / "tokens.jsonl",
        base / ".tibet" / "trail" / "audit.jsonl",
        base / ".tibet" / "trail" / "tokens.jsonl",
        base / "audit.jsonl",
        base / "trail.jsonl",
        base / "tibet-trail.jsonl",
        base / ".tibet" / "audit.jsonl",
        base / ".tibet" / "trail.jsonl",
    ]
    return [p for p in candidates if p.exists() and p.is_file()]


def _auto_detect_runtime_evidence(
    scan_path: Path,
    trail_file: str | None = None,
) -> dict:
    """
    Lightweight local autodiscovery for continuityd-style runtime state.

    This intentionally uses local conventions only. It is meant as a
    first automatic signal, not as a complete runtime integration.
    """
    inbox = Path("/var/lib/tibet/inbox")
    quarantine = Path("/var/lib/tibet/quarantine")
    audit_jsonl = Path("/var/log/tibet/continuityd-audit.jsonl")

    sealed_count = 0
    unsigned_count = 0
    if inbox.exists() and inbox.is_dir():
        for item in inbox.iterdir():
            if not item.is_file():
                continue
            if item.suffix.lower() in {".tza", ".tbz"}:
                sealed_count += 1
            else:
                unsigned_count += 1

    quarantine_count = 0
    if quarantine.exists() and quarantine.is_dir():
        quarantine_count = sum(1 for item in quarantine.iterdir() if item.is_file())

    audit_present = audit_jsonl.exists() and audit_jsonl.is_file()
    audit_lines = 0
    stage_counts: dict[str, int] = {}
    verify_valid_count = 0
    trusted_candidate_count = 0
    trusted_fork_count = 0
    if audit_present:
        try:
            with audit_jsonl.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    audit_lines += 1
                    try:
                        record = json.loads(line)
                    except Exception:
                        continue
                    if not isinstance(record, dict):
                        continue
                    stage = str(record.get("stage", "unknown"))
                    stage_counts[stage] = stage_counts.get(stage, 0) + 1
                    if record.get("verify_valid") is True:
                        verify_valid_count += 1
                    if record.get("disposition_hint") == "trusted-candidate":
                        trusted_candidate_count += 1
                    if record.get("disposition") == "trusted-fork":
                        trusted_fork_count += 1
        except Exception:
            audit_lines = 0

    keychain_example = Path("/srv/jtel-stack/packages/tibet-sam/examples/keychain-record-example.json")
    keychain_record_present = keychain_example.exists() and keychain_example.is_file()
    keychain_exposure_state = None
    keychain_owner_id = None
    keychain_custodian_id = None
    if keychain_record_present:
        try:
            payload = json.loads(keychain_example.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                keychain_exposure_state = payload.get("exposure_state")
                keychain_owner_id = payload.get("owner_id")
                keychain_custodian_id = payload.get("custodian_id")
        except Exception:
            pass

    trail_candidates = []
    if trail_file:
        trail_candidates.append(Path(trail_file).expanduser().resolve())
    trail_candidates.extend(_discover_project_trail_candidates(scan_path))
    trail_candidates.extend([
        Path("/var/log/tibet/continuityd-audit.jsonl"),
        Path("/srv/jtel-stack/sandbox/ai/codex/continuityd-test-packages/expected-audit-example.jsonl"),
    ])
    trail_candidates.extend(
        sorted(
            Path("/srv/jtel-stack/redspecter-eval-runs").glob("**/audit*.jsonl")
        )
        if Path("/srv/jtel-stack/redspecter-eval-runs").exists()
        else []
    )
    seen: set[str] = set()
    trail_sources = []
    for p in trail_candidates:
        if p.exists() and p.is_file():
            ps = str(p)
            if ps not in seen:
                seen.add(ps)
                trail_sources.append(ps)
    token_trail_sources: list[str] = []
    token_trail_total = 0
    token_trail_actor_count = 0
    token_trail_action_count = 0
    token_actors: set[str] = set()
    token_actions: set[str] = set()

    for path_str in trail_sources:
        p = Path(path_str)
        valid_tokens_in_file = 0
        try:
            with p.open("r", encoding="utf-8") as fh:
                for idx, line in enumerate(fh):
                    if idx >= 200:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except Exception:
                        continue
                    if not isinstance(record, dict):
                        continue
                    if {"token_id", "action", "actor", "timestamp"}.issubset(record.keys()):
                        valid_tokens_in_file += 1
                        token_trail_total += 1
                        if record.get("actor"):
                            token_actors.add(str(record["actor"]))
                        if record.get("action"):
                            token_actions.add(str(record["action"]))
            if valid_tokens_in_file > 0:
                token_trail_sources.append(str(p))
        except Exception:
            continue

    token_trail_actor_count = len(token_actors)
    token_trail_action_count = len(token_actions)

    twin_profiles_file = Path("/srv/jtel-stack/packages/tibet-twin/src/tibet_twin/profiles/__init__.py")
    twin_profile_count = 0
    twin_min_drift_ms = None
    twin_max_drift_ms = None
    if twin_profiles_file.exists():
        try:
            text = twin_profiles_file.read_text(encoding="utf-8")
            drifts = []
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("max_drift_ms="):
                    raw = line.split("=", 1)[1].rstrip(",").strip()
                    drifts.append(float(raw))
            if drifts:
                twin_profile_count = len(drifts)
                twin_min_drift_ms = min(drifts)
                twin_max_drift_ms = max(drifts)
        except Exception:
            pass

    return {
        "artifacts": {
            "sealed_tbz_objects": sealed_count,
            "signed_non_tbz_references": 0,
            "unsigned_external_objects": unsigned_count + quarantine_count,
            "encryption_boundary": {
                "v1_unencrypted_supported": sealed_count > 0,
                "v2_encrypted_supported": False,
                "status": "auto-detected-v1" if sealed_count > 0 else "planned",
            },
            "details": {
                "auto_detected_inbox": str(inbox),
                "auto_detected_quarantine": str(quarantine),
                "quarantine_file_count": quarantine_count,
            },
        },
        "evidence": {
            "tibet_chain_of_command": "present" if audit_present else "planned",
            "tibet_usage_custody": "present" if keychain_record_present else "planned",
            "continuity_links": "present" if audit_present or trail_sources else "planned",
            "signed_list_boundary": "planned",
            "details": {
                "continuityd_audit_jsonl": str(audit_jsonl),
                "continuityd_audit_present": audit_present,
                "continuityd_audit_lines": audit_lines,
                "continuityd_stage_counts": stage_counts,
                "continuityd_verify_valid_count": verify_valid_count,
                "continuityd_trusted_candidate_count": trusted_candidate_count,
                "continuityd_trusted_fork_count": trusted_fork_count,
                "keychain_record_example": str(keychain_example),
                "keychain_record_present": keychain_record_present,
                "keychain_exposure_state": keychain_exposure_state,
                "keychain_owner_id": keychain_owner_id,
                "keychain_custodian_id": keychain_custodian_id,
                "trail_sources": trail_sources,
                "trail_source_count": len(trail_sources),
                "token_trail_sources": token_trail_sources,
                "token_trail_source_count": len(token_trail_sources),
                "token_trail_total": token_trail_total,
                "token_trail_actor_count": token_trail_actor_count,
                "token_trail_action_count": token_trail_action_count,
                "twin_profiles_file": str(twin_profiles_file),
                "twin_profile_count": twin_profile_count,
                "twin_min_drift_ms": twin_min_drift_ms,
                "twin_max_drift_ms": twin_max_drift_ms,
            },
        },
    }


def _merge_artifact_evidence(auto_detected: dict, overlay_derived: dict) -> dict:
    """Merge autodetected runtime signals with optional overlay data."""
    merged = {
        "artifacts": dict(auto_detected.get("artifacts", {})),
        "evidence": dict(auto_detected.get("evidence", {})),
    }

    overlay_artifacts = overlay_derived.get("artifacts", {})
    overlay_evidence = overlay_derived.get("evidence", {})

    if overlay_artifacts:
        merged["artifacts"].update({
            "sealed_tbz_objects": overlay_artifacts.get(
                "sealed_tbz_objects",
                merged["artifacts"].get("sealed_tbz_objects", 0),
            ),
            "signed_non_tbz_references": overlay_artifacts.get(
                "signed_non_tbz_references",
                merged["artifacts"].get("signed_non_tbz_references", 0),
            ),
            "unsigned_external_objects": overlay_artifacts.get(
                "unsigned_external_objects",
                merged["artifacts"].get("unsigned_external_objects", 0),
            ),
            "encryption_boundary": overlay_artifacts.get(
                "encryption_boundary",
                merged["artifacts"].get("encryption_boundary", {}),
            ),
            "details": overlay_artifacts.get(
                "details",
                merged["artifacts"].get("details", {}),
            ),
        })

    if overlay_evidence:
        status_rank = {"planned": 0, "present": 1}
        for key in (
            "tibet_chain_of_command",
            "tibet_usage_custody",
            "continuity_links",
            "signed_list_boundary",
        ):
            current = str(merged["evidence"].get(key, "planned"))
            incoming = str(overlay_evidence.get(key, current))
            merged["evidence"][key] = (
                incoming
                if status_rank.get(incoming, 0) >= status_rank.get(current, 0)
                else current
            )
        merged["evidence"]["details"] = overlay_evidence.get(
            "details",
            merged["evidence"].get("details", {}),
        )

    return merged


def _overlay_section_counts(overlay: dict[str, Any]) -> dict[str, int]:
    """Compact count summary for declared AI-specific overlay sections."""
    return {
        "models": len(_normalize_overlay_list(overlay.get("models"))),
        "datasets": len(_normalize_overlay_list(overlay.get("datasets"))),
        "kpi": len(_normalize_overlay_list(overlay.get("kpi"))),
    }


def _declared_models_from_overlay(overlay: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalize overlay models into declared-model lane."""
    declared: list[dict[str, Any]] = []
    for item in _normalize_overlay_list(overlay.get("models")):
        declared.append({
            "name": item.get("model_name") or item.get("name"),
            "identifier": item.get("model_identifier") or item.get("identifier"),
            "version_or_tag": item.get("model_version") or item.get("version"),
            "source_kind": "declared-model",
            "evidence_grade": "declared",
            "locality": item.get("locality", "unknown"),
            "provider": item.get("provider", "declared"),
            "artifact_path": item.get("artifact_path"),
            "config_path": None,
            "hash": item.get("model_hash_value") or item.get("hash"),
            "risk_flags": item.get("risk_flags", []),
            "training_properties": item.get("model_training_properties") or item.get("training_properties"),
            "input_output_properties": item.get("model_input_output_properties") or item.get("input_output_properties"),
        })
    return declared


def _merge_declared_models(
    discovered: list[dict[str, Any]],
    overlay_declared: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Merge discovered and overlay-declared model records."""
    merged: dict[tuple[str | None, str | None, str | None], dict[str, Any]] = {}
    for item in discovered + overlay_declared:
        key = (
            item.get("name"),
            item.get("identifier"),
            item.get("config_path") or item.get("artifact_path"),
        )
        if key not in merged:
            merged[key] = item
            continue
        existing = merged[key]
        merged[key] = {
            **existing,
            **item,
            "risk_flags": sorted(set(existing.get("risk_flags", []) + item.get("risk_flags", []))),
        }
    return list(merged.values())[:100]


def _infer_action_surface(actor: dict[str, Any]) -> str:
    """Infer the main action surface for an actor from its endpoint."""
    endpoint = str(actor.get("endpoint") or "").lower()
    if endpoint.startswith("mcp://"):
        return "mcp"
    if endpoint.startswith("sip://"):
        return "sip"
    if endpoint.startswith("human://"):
        return "human"
    if endpoint.startswith("local://"):
        return "local-runtime"
    if "/api/ipoll" in endpoint:
        return "ipoll"
    if endpoint.startswith("https://") or endpoint.startswith("http://"):
        return "https-api"
    return "unknown"


def _infer_actor_model_provider_links(
    actor_catalog: list[dict[str, Any]],
    models: dict[str, Any],
) -> list[dict[str, Any]]:
    """Build first-pass actor -> provider/model -> surface links."""
    external_providers = models.get("external_model_providers", []) if isinstance(models, dict) else []
    declared_models = models.get("declared_models", []) if isinstance(models, dict) else []
    provider_by_name = {str(item.get("provider") or item.get("name")).lower(): item for item in external_providers if isinstance(item, dict)}

    provider_clues = {
        "openai": ("openai", "api.openai.com"),
        "anthropic": ("anthropic", "claude"),
        "google-gemini": ("gemini", "generativelanguage", "googleapis"),
        "vertex": ("vertex", "googleapis"),
        "ollama": ("ollama", "oomllama"),
    }

    links: list[dict[str, Any]] = []
    for actor in actor_catalog:
        if not isinstance(actor, dict):
            continue
        identity = str(actor.get("identity") or "")
        identity_l = identity.lower()
        aint_domain = str(actor.get("aint_domain") or "").lower()
        endpoint = str(actor.get("endpoint") or "").lower()
        owner = str(actor.get("owner") or "").lower()
        text = " ".join([identity_l, aint_domain, endpoint, owner])
        linked_providers: list[str] = []
        linked_models: list[str] = []

        for provider, clues in provider_clues.items():
            if any(clue in text for clue in clues):
                linked_providers.append(provider)

        for item in declared_models:
            if not isinstance(item, dict):
                continue
            provider = str(item.get("provider") or "").lower()
            model_name = str(item.get("name") or item.get("identifier") or "")
            if provider and provider in linked_providers and model_name:
                linked_models.append(model_name)
            elif model_name and any(token in text for token in (model_name.lower(),)):
                linked_models.append(model_name)

        if not linked_providers and not linked_models:
            continue

        links.append({
            "actor_identity": identity,
            "entity_type": actor.get("entity_type", "unknown"),
            "action_surface": _infer_action_surface(actor),
            "linked_providers": sorted(set(linked_providers)),
            "linked_models": sorted(set(linked_models)),
            "trust_basis": (
                "ains+jis-session"
                if actor.get("pubkey_fingerprint")
                else ("ains+jis" if actor.get("aint_domain") else "heuristic")
            ),
        })
    return links[:200]


def _load_sqlite_polls_usage_events(limit: int = 200) -> list[dict[str, Any]]:
    """Load recent I-Poll activity from the local RABEL sqlite store."""
    db = Path("/root/.rabel/memories.sqlite")
    if not db.exists():
        return []
    query = """
        select id, from_agent, to_agent, poll_type, created_at, metadata
        from polls
        order by created_at desc
        limit ?
    """
    events: list[dict[str, Any]] = []
    try:
        conn = sqlite3.connect(str(db))
        conn.row_factory = sqlite3.Row
        rows = conn.execute(query, (limit,)).fetchall()
        conn.close()
    except Exception:
        return []

    for row in rows:
        metadata = {}
        raw_meta = row["metadata"]
        if isinstance(raw_meta, str) and raw_meta.strip():
            try:
                payload = json.loads(raw_meta)
                if isinstance(payload, dict):
                    metadata = payload
            except Exception:
                metadata = {}
        events.append({
            "event_id": row["id"],
            "observation_layer": "ipoll",
            "timestamp": row["created_at"],
            "operation_id": row["id"],
            "thread_id": row["id"],
            "request_id": None,
            "token_id": metadata.get("tibet_token"),
            "object_id": metadata.get("tbz_envelope_ref"),
            "parent_id": None,
            "actor": {
                "identity": row["from_agent"],
                "agent_id": row["from_agent"],
                "entity_type": "actor",
                "ains_domain": f"{row['from_agent']}.aint" if "." not in str(row["from_agent"]) else row["from_agent"],
            },
            "inference": {
                "provider": None,
                "model": None,
                "execution_mode": None,
                "surface": "ipoll",
            },
            "route": {
                "route_class": "relay" if metadata.get("intended_remote") else "local",
                "transport": "ipoll",
                "overlay_hops": [],
                "egress_host": metadata.get("intended_remote"),
            },
            "trust": {
                "basis": "observed-only",
                "attested": bool(metadata.get("trust_score") is not None),
                "attester": None,
                "signature_ref": None,
                "bearer": row["from_agent"],
            },
            "continuity": {
                "disposition": None,
                "verify_valid": metadata.get("tbz_verified"),
                "causal_status": "observed",
            },
            "evidence": {
                "source": str(db),
                "raw_ref": f"poll:{row['id']}",
                "poll_type": row["poll_type"],
                "to_agent": row["to_agent"],
            },
        })
    return events


def _load_ains_usage_events(scan_path: Path, limit: int = 200) -> list[dict[str, Any]]:
    """Load baseline actor-presence events from AINS registry."""
    payload = _read_json_if_exists(scan_path / "ains_registry.json")
    if not isinstance(payload, dict):
        return []
    events: list[dict[str, Any]] = []
    for idx, (domain, data) in enumerate(payload.get("domains", {}).items()):
        if idx >= limit:
            break
        if not isinstance(data, dict):
            continue
        agent = data.get("agent") or domain.replace(".aint", "")
        events.append({
            "event_id": f"ains:{domain}",
            "observation_layer": "ains",
            "timestamp": data.get("registered_at"),
            "operation_id": f"ains:{domain}",
            "thread_id": None,
            "request_id": None,
            "token_id": None,
            "object_id": domain,
            "parent_id": None,
            "actor": {
                "identity": domain,
                "agent_id": agent,
                "entity_type": data.get("entity_type", "ai"),
                "ains_domain": domain,
            },
            "inference": {
                "provider": None,
                "model": None,
                "execution_mode": None,
                "surface": _infer_action_surface({"endpoint": data.get("endpoint")}),
            },
            "route": {
                "route_class": "unknown",
                "transport": None,
                "overlay_hops": [],
                "egress_host": data.get("endpoint"),
            },
            "trust": {
                "basis": "jis",
                "attested": True,
                "attester": data.get("owner"),
                "signature_ref": None,
                "bearer": domain,
            },
            "continuity": {
                "disposition": data.get("status"),
                "verify_valid": True if data.get("status") == "active" else None,
                "causal_status": "registered",
            },
            "evidence": {
                "source": str(scan_path / "ains_registry.json"),
                "raw_ref": f"domain:{domain}",
            },
        })
    return events


def _load_continuity_usage_events(limit: int = 200) -> list[dict[str, Any]]:
    """Load coarse continuity/liveness events from local tibet state files."""
    events: list[dict[str, Any]] = []
    liveness = _read_json_if_exists(Path("/var/lib/tibet/liveness.json"))
    if isinstance(liveness, dict):
        for peer, data in list((liveness.get("peers") or {}).items())[:limit]:
            if not isinstance(data, dict):
                continue
            events.append({
                "event_id": f"liveness:{peer}",
                "observation_layer": "continuityd",
                "timestamp": data.get("last_seen_iso"),
                "operation_id": None,
                "thread_id": None,
                "request_id": None,
                "token_id": data.get("last_surface_hash"),
                "object_id": peer,
                "parent_id": None,
                "actor": {
                    "identity": peer,
                    "agent_id": peer,
                    "entity_type": "service",
                    "ains_domain": None,
                },
                "inference": {
                    "provider": None,
                    "model": None,
                    "execution_mode": None,
                    "surface": "continuityd",
                },
                "route": {
                    "route_class": "local",
                    "transport": "file-state",
                    "overlay_hops": [],
                    "egress_host": None,
                },
                "trust": {
                    "basis": "observed-only",
                    "attested": False,
                    "attester": None,
                    "signature_ref": None,
                    "bearer": peer,
                },
                "continuity": {
                    "disposition": data.get("last_kind_detail"),
                    "verify_valid": None,
                    "causal_status": "heartbeat",
                },
                "evidence": {
                    "source": "/var/lib/tibet/liveness.json",
                    "raw_ref": f"peer:{peer}",
                },
            })
    mux = _read_json_if_exists(Path("/var/lib/tibet/mux-consumer-seen.json"))
    if isinstance(mux, dict):
        for idx, item in enumerate((mux.get("seen") or [])[:limit]):
            if not isinstance(item, list) or not item:
                continue
            token = item[0]
            events.append({
                "event_id": f"mux:{token}",
                "observation_layer": "continuityd",
                "timestamp": None,
                "operation_id": token,
                "thread_id": None,
                "request_id": None,
                "token_id": token,
                "object_id": None,
                "parent_id": None,
                "actor": {
                    "identity": mux.get("agent", "continuityd"),
                    "agent_id": mux.get("agent", "continuityd"),
                    "entity_type": "service",
                    "ains_domain": None,
                },
                "inference": {
                    "provider": None,
                    "model": None,
                    "execution_mode": None,
                    "surface": "continuityd",
                },
                "route": {
                    "route_class": "local",
                    "transport": "mux",
                    "overlay_hops": [],
                    "egress_host": None,
                },
                "trust": {
                    "basis": "observed-only",
                    "attested": False,
                    "attester": None,
                    "signature_ref": None,
                    "bearer": mux.get("agent", "continuityd"),
                },
                "continuity": {
                    "disposition": mux.get("intent"),
                    "verify_valid": None,
                    "causal_status": "seen",
                },
                "evidence": {
                    "source": "/var/lib/tibet/mux-consumer-seen.json",
                    "raw_ref": f"seen:{idx}",
                },
            })
    return events[:limit]


def _load_jis_session_usage_events(scan_path: Path, limit: int = 200) -> list[dict[str, Any]]:
    """Load Tier A JIS/AInternet session events as trust-bearing activity."""
    events: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc)
    for session in _load_jis_session_records(scan_path, limit=limit):
        session_id = session.get("session_id")
        domain = str(session.get("domain") or "").strip()
        if not session_id or not domain:
            continue
        aint_domain = domain if domain.endswith(".aint") else f"{domain}.aint"
        fingerprint = str(session.get("pubkey_fingerprint") or "").strip()
        expires_at = session.get("expires_at")
        expires_dt = _parse_iso_datetime(expires_at)
        is_active = expires_dt is None or expires_dt >= now
        ip = session.get("ip")
        events.append({
            "event_id": f"session:{session.get('store_name')}:{session_id}",
            "observation_layer": "jis-session",
            "timestamp": session.get("last_seen") or session.get("created_at"),
            "operation_id": session_id,
            "thread_id": session_id,
            "request_id": session_id,
            "token_id": None,
            "object_id": aint_domain,
            "parent_id": None,
            "actor": {
                "identity": domain,
                "agent_id": domain,
                "entity_type": "agent",
                "ains_domain": aint_domain,
            },
            "inference": {
                "provider": None,
                "model": None,
                "execution_mode": "session-authenticated",
                "surface": "https-session",
            },
            "route": {
                "route_class": _classify_session_route(ip),
                "transport": "https-session",
                "overlay_hops": [],
                "egress_host": ip,
            },
            "trust": {
                "basis": "jis-session",
                "attested": bool(fingerprint and fingerprint.lower() != "none"),
                "attester": fingerprint or None,
                "signature_ref": f"pubkey:{fingerprint}" if fingerprint and fingerprint.lower() != "none" else None,
                "bearer": aint_domain,
                "session_id": session_id,
                "session_expires_at": expires_at,
                "last_seen": session.get("last_seen"),
                "pubkey_fingerprint": fingerprint or None,
            },
            "continuity": {
                "disposition": "active-session" if is_active else "expired-session",
                "verify_valid": is_active,
                "causal_status": "session",
            },
            "evidence": {
                "source": session.get("store"),
                "raw_ref": f"session:{session_id}",
                "store_name": session.get("store_name"),
                "created_at": session.get("created_at"),
                "ip": ip,
            },
        })
    return events[:limit]


def _load_gateway_usage_events(scan_path: Path, limit: int = 200) -> list[dict[str, Any]]:
    """Load Tier B gateway events from JSON/JSONL logs when present."""
    events: list[dict[str, Any]] = []
    for path in _gateway_log_candidates(scan_path):
        if not path.exists():
            continue
        records: list[dict[str, Any]] = []
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        stripped = text.strip()
        if not stripped:
            continue
        if path.suffix.lower() == ".jsonl":
            for line in stripped.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except Exception:
                    continue
                if isinstance(payload, dict):
                    records.append(payload)
        else:
            try:
                payload = json.loads(stripped)
            except Exception:
                payload = None
            if isinstance(payload, list):
                records.extend([item for item in payload if isinstance(item, dict)])
            elif isinstance(payload, dict):
                records.append(payload)

        for idx, record in enumerate(records):
            if len(events) >= limit:
                return events
            if record.get("observation_layer") not in {None, "tibet-gateway"}:
                continue
            target_url = record.get("target_url") or record.get("url") or record.get("target")
            provider = record.get("provider") or _infer_provider_from_target_url(target_url)
            payload = record.get("payload")
            if not isinstance(payload, dict):
                payload = record.get("request_payload") if isinstance(record.get("request_payload"), dict) else {}
            model = record.get("model") or _extract_model_name_from_payload(record) or _extract_model_name_from_payload(payload)
            if not target_url and not provider and not model:
                continue
            actor_id = record.get("agent_id") or record.get("actor") or record.get("identity") or record.get("ains_domain") or "gateway-observed"
            surface = record.get("surface") or "tibet-gateway"
            if surface == "tibet-gateway" and provider == "ollama":
                surface = "ollama-gateway"
            events.append({
                "event_id": str(record.get("event_id") or record.get("token_id") or f"gateway:{path.name}:{idx}"),
                "observation_layer": "tibet-gateway",
                "timestamp": record.get("timestamp") or record.get("created_at") or record.get("when") or _file_mtime_iso(path),
                "operation_id": record.get("operation_id") or record.get("request_id") or record.get("token_id"),
                "thread_id": record.get("thread_id"),
                "request_id": record.get("request_id"),
                "token_id": record.get("token_id") or record.get("envelope_id"),
                "object_id": record.get("object_id") or target_url,
                "parent_id": record.get("parent_id"),
                "actor": {
                    "identity": actor_id,
                    "agent_id": actor_id,
                    "entity_type": "agent",
                    "ains_domain": actor_id if isinstance(actor_id, str) and actor_id.endswith(".aint") else None,
                },
                "inference": {
                    "provider": provider,
                    "model": model,
                    "execution_mode": "gateway-proxied",
                    "surface": surface,
                },
                "route": {
                    "route_class": record.get("route_class") or "gateway",
                    "transport": record.get("transport") or "https-proxy",
                    "overlay_hops": record.get("overlay_hops") or [],
                    "egress_host": target_url,
                    "lane_class": record.get("lane_class"),
                    "lane_collision_policy": record.get("lane_collision_policy"),
                    "coffee_lane_policy": record.get("coffee_lane_policy"),
                    "coffee_reason": record.get("coffee_reason"),
                    "time_diff_seconds": record.get("time_diff_seconds"),
                    "diff_threshold_seconds": record.get("diff_threshold_seconds"),
                    "preemptible": record.get("preemptible"),
                    "lane_priority": record.get("lane_priority"),
                },
                "trust": {
                    "basis": "jis+tibet-gateway" if record.get("token_id") or record.get("envelope_id") else "gateway-observed",
                    "attested": bool(record.get("verified") or record.get("token_id") or record.get("envelope_id")),
                    "attester": record.get("gateway_actor") or "jis:tibet-gateway",
                    "signature_ref": record.get("content_hash") or record.get("signature_ref"),
                    "bearer": actor_id,
                },
                "continuity": {
                    "disposition": record.get("status"),
                    "verify_valid": record.get("verified"),
                    "causal_status": "gateway",
                },
                "evidence": {
                    "source": str(path),
                    "raw_ref": f"{path.name}:{idx}",
                    "target_url": target_url,
                    "intent": record.get("intent"),
                    "method": record.get("method"),
                    "emitter": record.get("_emitter"),
                },
            })
    return events[:limit]


def _load_gateway_config_events(scan_path: Path, limit: int = 50) -> list[dict[str, Any]]:
    """Load Tier B prepared gateway/provider support from BYOK config."""
    events: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str, str]] = set()
    actor_identity = f"{scan_path.name}.gateway"

    for config_path in _gateway_config_file_candidates(scan_path):
        try:
            text = config_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        timestamp = _file_mtime_iso(config_path)
        pairs: list[tuple[str, str, str]] = []

        block_match = re.search(r"BYOK_DEFAULT_MODELS\s*:\s*dict\[str,\s*str\]\s*=\s*\{(.*?)\}", text, re.DOTALL)
        if block_match:
            for provider, model in re.findall(r'"([^"]+)"\s*:\s*"([^"]+)"', block_match.group(1)):
                pairs.append((provider, model, "configured-byok"))

        for provider, model in re.findall(
            r"track_external_api_call\s*\(\s*provider\s*=\s*[\"']([^\"']+)[\"']\s*,\s*model\s*=\s*[\"']([^\"']+)[\"']",
            text,
            re.IGNORECASE,
        ):
            pairs.append((provider, model, "configured-external-wrapper"))

        for provider, model, execution_mode in pairs:
            key = (str(config_path), provider, model)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            if len(events) >= limit:
                return events

            surface = "byok-https"
            route_class = "direct"
            transport = "https-api"
            if provider == "home_agent":
                surface = "ipoll-home-agent"
                route_class = "relay"
                transport = "ipoll"
            elif provider == "ollama":
                surface = "ollama-config"
                transport = "local-http"

            events.append({
                "event_id": f"gateway-config:{config_path.stem}:{provider}:{model}",
                "observation_layer": "gateway-config",
                "timestamp": timestamp,
                "operation_id": None,
                "thread_id": None,
                "request_id": None,
                "token_id": None,
                "object_id": provider,
                "parent_id": None,
                "actor": {
                    "identity": actor_identity,
                    "agent_id": actor_identity,
                    "entity_type": "service",
                    "ains_domain": None,
                },
                "inference": {
                    "provider": provider,
                    "model": model,
                    "execution_mode": execution_mode,
                    "surface": surface,
                },
                "route": {
                    "route_class": route_class,
                    "transport": transport,
                    "overlay_hops": [],
                    "egress_host": provider,
                },
                "trust": {
                    "basis": "configured-only",
                    "attested": False,
                    "attester": None,
                    "signature_ref": None,
                    "bearer": actor_identity,
                },
                "continuity": {
                    "disposition": "configured",
                    "verify_valid": None,
                    "causal_status": "config",
                },
                "evidence": {
                    "source": str(config_path),
                    "raw_ref": f"provider:{provider}",
                },
            })
    return events


def _collect_usage_events(scan_path: Path, limit: int = 400) -> list[dict[str, Any]]:
    """Collect Tier A usage/governance events from local sources."""
    events = []
    events.extend(_load_gateway_usage_events(scan_path, limit=limit))
    events.extend(_load_gateway_config_events(scan_path, limit=limit))
    events.extend(_load_ains_usage_events(scan_path, limit=limit))
    events.extend(_load_jis_session_usage_events(scan_path, limit=limit))
    events.extend(_load_sqlite_polls_usage_events(limit=limit))
    events.extend(_load_continuity_usage_events(limit=limit))
    events.sort(key=lambda item: str(item.get("timestamp") or ""), reverse=True)
    return events[:limit]


def _augment_actor_links_from_usage_events(
    actor_links: list[dict[str, Any]],
    usage_events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Merge observed provider/model usage back into actor links."""
    merged: dict[str, dict[str, Any]] = {}
    generic_surfaces = {"observed", "https-api", "ipoll", "continuityd", "unknown", None}
    for item in actor_links:
        if not isinstance(item, dict):
            continue
        identity = str(item.get("actor_identity") or "").strip()
        if not identity:
            continue
        merged[identity] = {
            **item,
            "linked_providers": list(item.get("linked_providers", [])),
            "linked_models": list(item.get("linked_models", [])),
            "lane_class": item.get("lane_class"),
            "lane_collision_policy": item.get("lane_collision_policy"),
            "coffee_lane_policy": item.get("coffee_lane_policy"),
            "coffee_reason": item.get("coffee_reason"),
            "time_diff_seconds": item.get("time_diff_seconds"),
            "diff_threshold_seconds": item.get("diff_threshold_seconds"),
            "preemptible": item.get("preemptible"),
            "lane_priority": item.get("lane_priority"),
            "emitter": item.get("emitter"),
        }

    for event in usage_events:
        if not isinstance(event, dict):
            continue
        actor = event.get("actor")
        inference = event.get("inference")
        route = event.get("route")
        trust = event.get("trust")
        evidence = event.get("evidence")
        if not isinstance(actor, dict) or not isinstance(inference, dict):
            continue
        identity = str(actor.get("identity") or actor.get("ains_domain") or "").strip()
        if not identity:
            continue
        link = merged.setdefault(identity, {
            "actor_identity": identity,
            "entity_type": actor.get("entity_type", "unknown"),
            "action_surface": inference.get("surface") or "observed",
            "linked_providers": [],
            "linked_models": [],
            "trust_basis": trust.get("basis") if isinstance(trust, dict) else "observed",
            "lane_class": route.get("lane_class") if isinstance(route, dict) else None,
            "lane_collision_policy": route.get("lane_collision_policy") if isinstance(route, dict) else None,
            "coffee_lane_policy": route.get("coffee_lane_policy") if isinstance(route, dict) else None,
            "coffee_reason": route.get("coffee_reason") if isinstance(route, dict) else None,
            "time_diff_seconds": route.get("time_diff_seconds") if isinstance(route, dict) else None,
            "diff_threshold_seconds": route.get("diff_threshold_seconds") if isinstance(route, dict) else None,
            "preemptible": route.get("preemptible") if isinstance(route, dict) else None,
            "lane_priority": route.get("lane_priority") if isinstance(route, dict) else None,
            "emitter": evidence.get("emitter") if isinstance(evidence, dict) else None,
        })
        provider = inference.get("provider")
        model = inference.get("model")
        if isinstance(provider, str) and provider and provider not in link["linked_providers"]:
            link["linked_providers"].append(provider)
        if isinstance(model, str) and model and model not in link["linked_models"]:
            link["linked_models"].append(model)
        event_surface = inference.get("surface")
        if event_surface and link.get("action_surface") in generic_surfaces:
            link["action_surface"] = event_surface
        if isinstance(trust, dict) and trust.get("basis"):
            link["trust_basis"] = trust["basis"]
        if isinstance(route, dict):
            current_rank = _coffee_policy_rank(link.get("coffee_lane_policy"))
            route_rank = _coffee_policy_rank(route.get("coffee_lane_policy"))
            should_upgrade_policy = route_rank >= current_rank
            if route.get("lane_class") and (should_upgrade_policy or not link.get("lane_class")):
                link["lane_class"] = route["lane_class"]
            if route.get("lane_collision_policy") and (should_upgrade_policy or not link.get("lane_collision_policy")):
                link["lane_collision_policy"] = route["lane_collision_policy"]
            if route.get("coffee_lane_policy") and (should_upgrade_policy or not link.get("coffee_lane_policy")):
                link["coffee_lane_policy"] = route["coffee_lane_policy"]
            if route.get("coffee_reason") and (should_upgrade_policy or not link.get("coffee_reason")):
                link["coffee_reason"] = route["coffee_reason"]
            if route.get("time_diff_seconds") is not None and (should_upgrade_policy or link.get("time_diff_seconds") is None):
                link["time_diff_seconds"] = route["time_diff_seconds"]
            if route.get("diff_threshold_seconds") is not None and (should_upgrade_policy or link.get("diff_threshold_seconds") is None):
                link["diff_threshold_seconds"] = route["diff_threshold_seconds"]
            if route.get("preemptible") is not None:
                link["preemptible"] = route["preemptible"]
            if route.get("lane_priority") is not None:
                link["lane_priority"] = route["lane_priority"]
        if isinstance(evidence, dict) and evidence.get("emitter"):
            link["emitter"] = evidence["emitter"]

    for item in merged.values():
        item["linked_providers"] = sorted(set(item.get("linked_providers", [])))
        item["linked_models"] = sorted(set(item.get("linked_models", [])))
    return sorted(merged.values(), key=lambda item: str(item.get("actor_identity", "")))[:250]


def _coffee_policy_rank(value: Any) -> int:
    """Rank coffee policies so actor-link summaries keep the strongest semantics."""
    ranking = {
        "hard_avoid": 7,
        "offline_fallback": 6,
        "rebuild": 5,
        "fork_on_hop_off": 4,
        "freeze_resume": 3,
        "polite_avoid": 2,
        "sip_anyway": 1,
    }
    if not isinstance(value, str):
        return 0
    return ranking.get(value, 0)


def _manifest_types_for_path(path: Path) -> list[str]:
    """Lightweight manifest family detection for focused scans."""
    manifest_map = [
        ("pyproject.toml", "pyproject"),
        ("requirements.txt", "requirements"),
        ("package.json", "npm"),
        ("Cargo.toml", "cargo"),
        ("go.mod", "gomod"),
    ]
    manifests = []
    base = path if path.is_dir() else path.parent
    for filename, label in manifest_map:
        if (base / filename).exists():
            manifests.append(label)
    return manifests


def _focused_scan_summary(
    path: Path,
    overlay_path: str | None = None,
    trail_file: str | None = None,
    workspace_mode: bool = False,
) -> tuple[dict, int]:
    """Config-first AI-SBOM summary without full tibet-sbom substrate walk."""
    overlay, loaded_overlay_path = _load_overlay(path, overlay_path)
    model_evidence = _discover_model_evidence(path)
    model_evidence["declared_models"] = _merge_declared_models(
        model_evidence.get("declared_models", []),
        _declared_models_from_overlay(overlay),
    )
    component_count = 0
    code_status = _derive_dynamic_code_status(
        overlay,
        {"component_count": component_count, "model_evidence": model_evidence},
        workspace_mode,
    )
    artifact_evidence = _merge_artifact_evidence(
        _auto_detect_runtime_evidence(path, trail_file=trail_file),
        _artifact_evidence_from_overlay(overlay),
    )
    usage_events = _collect_usage_events(path)
    metadata = {
        "scanner_version": "focused",
        "scan_node": os.uname().nodename,
        "timestamp": None,
    }
    summary = {
        "mode": "workspace" if workspace_mode else "single-root",
        "path": str(path),
        "workspace_root": str(path) if workspace_mode else None,
        "project_name": path.name,
        "version": "0.0.0",
        "timestamp": None,
        "component_count": 0,
        "vulnerability_count": 0,
        "tibet_chain_length": 0,
        "metadata": metadata,
        "manifest_types": _manifest_types_for_path(path),
        "workspace_roots_detected": 0,
        "software_components": [],
        "packages": [],
        "package_count": 0,
        "cluster_status": _cluster_status_objects(code_status, overlay={**overlay, "_model_evidence": model_evidence}, workspace_mode=workspace_mode),
        "code_status": code_status,
        "missing_reasons": _missing_reason_map(code_status),
        "overlay": {
            "path": loaded_overlay_path,
            "loaded": bool(loaded_overlay_path),
            "section_counts": _overlay_section_counts(overlay),
        },
        "system": overlay.get("system", {}),
        "models": model_evidence,
        "datasets": _normalize_overlay_list(overlay.get("datasets")),
        "infrastructure": overlay.get("infrastructure", {}),
        "kpi": _normalize_overlay_list(overlay.get("kpi")),
        "model_evidence": model_evidence,
        "usage_events": usage_events,
        **artifact_evidence,
    }
    return summary, 0


def _single_root_scan_summary(
    path: Path,
    overlay_path: str | None = None,
    trail_file: str | None = None,
) -> tuple[dict, int] | tuple[None, int]:
    """Run tibet-sbom single-root scan and return summarized data."""
    SBOMGenerator, import_err = _load_tibet_sbom()
    if SBOMGenerator is None:
        print(
            "tibet-ai-sbom scan needs tibet-sbom available in the environment.",
            file=sys.stderr,
        )
        print(f"Import error: {import_err}", file=sys.stderr)
        return None, 2

    gen = SBOMGenerator(actor="tibet-ai-sbom")
    sbom = gen.scan(str(path))
    vulns = gen.check_vulnerabilities()
    model_evidence = _discover_model_evidence(path)
    manifests = []
    manifest_map = [
        ("pyproject.toml", "pyproject"),
        ("requirements.txt", "requirements"),
        ("package.json", "npm"),
        ("Cargo.toml", "cargo"),
        ("go.mod", "gomod"),
    ]
    for filename, label in manifest_map:
        if (path / filename).exists():
            manifests.append(label)
    overlay, loaded_overlay_path = _load_overlay(path, overlay_path)
    declared_models = _merge_declared_models(
        model_evidence.get("declared_models", []),
        _declared_models_from_overlay(overlay),
    )
    model_evidence["declared_models"] = declared_models
    code_status = _derive_dynamic_code_status(
        overlay,
        {"component_count": len(sbom.components), "model_evidence": model_evidence},
        False,
    )
    artifact_evidence = _merge_artifact_evidence(
        _auto_detect_runtime_evidence(path, trail_file=trail_file),
        _artifact_evidence_from_overlay(overlay),
    )
    usage_events = _collect_usage_events(path)
    return {
        "mode": "single-root",
        "path": str(path),
        "project_name": sbom.project_name,
        "version": sbom.version,
        "timestamp": sbom.timestamp,
        "component_count": len(sbom.components),
        "vulnerability_count": len(vulns),
        "tibet_chain_length": sbom.tibet_chain_length,
        "metadata": sbom.metadata,
        "manifest_types": manifests,
        "workspace_roots_detected": len(SBOMGenerator.discover_workspace_roots(str(path))),
        "software_components": [c.to_dict() for c in sbom.components],
        "cluster_status": _cluster_status_objects(code_status, overlay={**overlay, "_model_evidence": model_evidence}, workspace_mode=False),
        "code_status": code_status,
        "missing_reasons": _missing_reason_map(code_status),
        "overlay": {
            "path": loaded_overlay_path,
            "loaded": bool(loaded_overlay_path),
            "section_counts": _overlay_section_counts(overlay),
        },
        "system": overlay.get("system", {}),
        "models": model_evidence,
        "datasets": _normalize_overlay_list(overlay.get("datasets")),
        "infrastructure": overlay.get("infrastructure", {}),
        "kpi": _normalize_overlay_list(overlay.get("kpi")),
        "model_evidence": model_evidence,
        "usage_events": usage_events,
        **artifact_evidence,
    }, 0


def _workspace_scan_summary(
    path: Path,
    overlay_path: str | None = None,
    trail_file: str | None = None,
) -> tuple[dict, int] | tuple[None, int]:
    """Run tibet-sbom workspace scan and return summarized data."""
    SBOMGenerator, import_err = _load_tibet_sbom()
    if SBOMGenerator is None:
        print(
            "tibet-ai-sbom scan needs tibet-sbom available in the environment.",
            file=sys.stderr,
        )
        print(f"Import error: {import_err}", file=sys.stderr)
        return None, 2

    gen = SBOMGenerator(actor="tibet-ai-sbom")
    workspace = gen.scan_workspace(str(path))
    data = workspace.to_dict()
    model_evidence = _discover_model_evidence(path)
    overlay, loaded_overlay_path = _load_overlay(path, overlay_path)
    declared_models = _merge_declared_models(
        model_evidence.get("declared_models", []),
        _declared_models_from_overlay(overlay),
    )
    model_evidence["declared_models"] = declared_models
    code_status = _derive_dynamic_code_status(
        overlay,
        {"component_count": data.get("component_count", 0), "model_evidence": model_evidence},
        True,
    )
    data["cluster_status"] = _cluster_status_objects(code_status, overlay={**overlay, "_model_evidence": model_evidence}, workspace_mode=True)
    data["code_status"] = code_status
    data["missing_reasons"] = _missing_reason_map(code_status)
    data["overlay"] = {
        "path": loaded_overlay_path,
        "loaded": bool(loaded_overlay_path),
        "section_counts": _overlay_section_counts(overlay),
    }
    data["system"] = overlay.get("system", {})
    data["models"] = model_evidence
    data["datasets"] = _normalize_overlay_list(overlay.get("datasets"))
    data["infrastructure"] = overlay.get("infrastructure", {})
    data["kpi"] = _normalize_overlay_list(overlay.get("kpi"))
    data["model_evidence"] = model_evidence
    data["usage_events"] = _collect_usage_events(path)
    data.update(
        _merge_artifact_evidence(
            _auto_detect_runtime_evidence(path, trail_file=trail_file),
            _artifact_evidence_from_overlay(overlay),
        )
    )
    return data, 0


def _build_ai_sbom_document(summary: dict[str, Any]) -> dict[str, Any]:
    """Build a normalized AI-SBOM JSON document from scan summary."""
    scan_mode = summary.get("mode", "workspace" if "workspace_root" in summary else "single-root")
    root_path = summary.get("workspace_root") or summary.get("path")
    metadata = summary.get("metadata", {})

    if scan_mode == "workspace":
        workspace = {
            "workspace_root": summary.get("workspace_root"),
            "workspace_packages": [
                {
                    "component_ref": f"pkg:{pkg.get('project_name','unknown')}@{pkg.get('version','0.0.0')}",
                    "package_root": pkg.get("package_path"),
                    "manifest_types": pkg.get("manifest_types", []),
                    "component_count": pkg.get("component_count", 0),
                    "tibet_chain_length": pkg.get("tibet_chain_length", 0),
                    "vulnerability_count": pkg.get("vulnerability_count", 0),
                }
                for pkg in summary.get("packages", [])
            ],
        }
        components = [
            {
                "component_ref": f"pkg:{pkg.get('project_name','unknown')}@{pkg.get('version','0.0.0')}",
                "name": pkg.get("project_name"),
                "version": pkg.get("version"),
                "package_root": pkg.get("package_path"),
                "manifest_types": pkg.get("manifest_types", []),
                "component_count": pkg.get("component_count", 0),
                "tibet_chain_length": pkg.get("tibet_chain_length", 0),
                "vulnerability_count": pkg.get("vulnerability_count", 0),
            }
            for pkg in summary.get("packages", [])
        ]
    else:
        workspace = {
            "workspace_root": None,
            "workspace_packages": [],
        }
        components = summary.get("software_components", [])

    model_evidence = summary.get("model_evidence", {}) if isinstance(summary.get("model_evidence"), dict) else {}
    actor_signals = model_evidence.get("actor_signals", {}) if isinstance(model_evidence.get("actor_signals"), dict) else {}
    actor_catalog = actor_signals.get("actor_catalog", []) if isinstance(actor_signals.get("actor_catalog"), list) else []
    usage_events = summary.get("usage_events", []) if isinstance(summary.get("usage_events"), list) else []
    actor_links = _augment_actor_links_from_usage_events(
        _infer_actor_model_provider_links(actor_catalog, summary.get("models", {})),
        usage_events,
    )
    jis_present = (
        bool(actor_signals.get("jis_id_count", 0))
        or bool(actor_signals.get("session_count", 0))
        or bool(summary.get("evidence", {}).get("tibet_chain_of_command") == "present")
    )
    document = {
        "schema_name": "ai-sbom-json",
        "schema_version": "0.1.0-draft",
        "document": {
            "sbom_author": "HumoticaOS",
            "sbom_version": "0.1.0",
            "sbom_format_name": "ai-sbom-json",
            "sbom_format_version": "0.1.0-draft",
            "sbom_author_signature": None,
            "sbom_timestamp": summary.get("timestamp") or metadata.get("timestamp"),
            "sbom_generation_context": {
                "scan_mode": scan_mode,
                "root_path": root_path,
                "tool_name": "tibet-ai-sbom",
                "tool_version": __version__,
                "substrate_tool": "tibet-sbom",
                "substrate_version": metadata.get("scanner_version"),
                "scan_node": metadata.get("scan_node"),
                "manifest_types": summary.get("manifest_types", []),
            },
            "dependency_relationship_policy": "direct+transitive",
        },
        "workspace": workspace,
        "system": summary.get("system", {}),
        "components": components,
        "artifacts": summary.get("artifacts", {}),
        "models": summary.get("models", {}),
        "datasets": summary.get("datasets", []),
        "infrastructure": summary.get("infrastructure", {}),
        "security_properties": {
            "cluster_status": [
                row for row in summary.get("cluster_status", [])
                if row.get("prefix") == "SEC"
            ],
            "vulnerability_count": summary.get("vulnerability_count", 0),
            "evidence_status": summary.get("evidence", {}),
            "runtime_signals": {
                "sealed_tbz_objects": summary.get("artifacts", {}).get("sealed_tbz_objects", 0),
                "signed_non_tbz_references": summary.get("artifacts", {}).get("signed_non_tbz_references", 0),
                "unsigned_external_objects": summary.get("artifacts", {}).get("unsigned_external_objects", 0),
                "continuity_links": summary.get("evidence", {}).get("continuity_links"),
                "tibet_chain_of_command": summary.get("evidence", {}).get("tibet_chain_of_command"),
                "tibet_usage_custody": summary.get("evidence", {}).get("tibet_usage_custody"),
                "trail_source_count": summary.get("evidence", {}).get("details", {}).get("trail_source_count", 0),
                "token_trail_source_count": summary.get("evidence", {}).get("details", {}).get("token_trail_source_count", 0),
                "token_trail_total": summary.get("evidence", {}).get("details", {}).get("token_trail_total", 0),
                "twin_profile_count": summary.get("evidence", {}).get("details", {}).get("twin_profile_count", 0),
                "twin_min_drift_ms": summary.get("evidence", {}).get("details", {}).get("twin_min_drift_ms"),
                "aint_ref_count": actor_signals.get("aint_ref_count", 0),
                "actor_ref_count": actor_signals.get("actor_ref_count", 0),
                "jis_session_count": actor_signals.get("session_count", 0),
                "jis_session_fingerprint_count": actor_signals.get("session_fingerprint_count", 0),
            },
        },
        "kpi": summary.get("kpi", []),
        "governance": {
            "questions": {
                "what": "ai-sbom",
                "how": "cbom",
                "who": "ains",
                "why": "jis",
            },
            "trust_foundation": {
                "authority_layer": "jis",
                "jis_present": jis_present,
                "session_count": actor_signals.get("session_count", 0),
                "session_fingerprint_count": actor_signals.get("session_fingerprint_count", 0),
                "sources": sorted({
                    item.get("source")
                    for item in actor_signals.get("actor_records", [])
                    if isinstance(item, dict) and item.get("kind") in {"jis-grant", "jis-session"} and item.get("source")
                })[:20],
                "explanation": (
                    "AI-SBOM, CBOM, and AINS claims become governance claims "
                    "only when their inventory, provenance, and active identity "
                    "surfaces are cryptographically anchored."
                ),
            },
            "claims": {
                "inventory_truth": True,
                "provenance_truth": True,
                "active_identity_truth": bool(actor_catalog),
                "trust_foundation_truth": jis_present,
                "usage_event_truth": bool(usage_events),
            },
            "governance_links": {
                "what_path": "models/components/datasets/infrastructure",
                "how_path": "evidence/security_properties",
                "who_path": "models.actor_signals.actor_catalog",
                "why_path": "governance.trust_foundation",
                "usage_events_path": "governance.usage_events",
            },
            "actor_catalog": actor_catalog,
            "actor_model_provider_links": actor_links,
            "usage_events": usage_events,
        },
        "evidence": {
            **summary.get("evidence", {}),
            "details": {
                **(summary.get("evidence", {}).get("details", {}) if isinstance(summary.get("evidence", {}).get("details", {}), dict) else {}),
                "actor_signals": actor_signals,
            },
        },
        "cluster_status": summary.get("cluster_status", []),
        "code_status": summary.get("code_status", {}),
        "missing_reasons": summary.get("missing_reasons", {}),
        "overlay": summary.get("overlay", {}),
    }
    return document


def _cmd_version(_args) -> int:
    print(f"tibet-ai-sbom {__version__}")
    print("BSI/G7 SBOM-for-AI implementation — governance-oriented AI inventory.")
    return 0


def _cmd_clusters(args) -> int:
    cluster: BSICluster | None = None
    if args.cluster:
        try:
            cluster = BSICluster(args.cluster.upper())
        except ValueError:
            print(
                f"unknown cluster '{args.cluster}'. "
                f"Known: {', '.join(c.value for c in BSICluster)}",
                file=sys.stderr,
            )
            return 2

    items = list_cluster_codes(cluster)
    if not items:
        print("(no items)")
        return 0
    width = max(len(it.code) for it in items)
    for it in items:
        print(f"{it.code:<{width}}  [{it.coverage:8s}]  {it.title}")
    return 0


def _cmd_code(args) -> int:
    info = cluster_for_code(args.code)
    if not info:
        print(f"unknown code '{args.code}'", file=sys.stderr)
        return 2
    print(f"Code:        {info.code}")
    print(f"Cluster:     {info.cluster.name} ({info.cluster.value})")
    print(f"Title:       {info.title}")
    print(f"Description: {info.description}")
    print(f"Coverage:    {info.coverage}")
    return 0


def _cmd_scan(args) -> int:
    path = Path(args.path or ".").resolve()
    workspace_mode = bool(args.workspace)
    summary, status = _build_summary_from_args(args)
    if status != 0 or summary is None:
        return status

    if args.json:
        print(json.dumps(summary, indent=2))
        return 0

    print(f"tibet-ai-sbom scan {path}")
    print()

    if workspace_mode:
        print("AI-SBOM workspace summary")
        print(f"  Workspace root:   {summary['workspace_root']}")
        print(f"  Package roots:    {summary['package_count']}")
        print(f"  Components total: {summary['component_count']}")
        print(f"  TIBET tokens:     {summary['tibet_chain_length']}")
        print(f"  Vulnerabilities:  {summary['vulnerability_count']}")
        print()
        if summary["packages"]:
            print("  Discovered package roots:")
            for pkg in summary["packages"][:12]:
                manifests = ",".join(pkg.get("manifest_types", [])) or "-"
                print(
                    f"    - {pkg['project_name']} v{pkg['version']} "
                    f"[{manifests}] components={pkg['component_count']}"
                )
            if len(summary["packages"]) > 12:
                print(f"    ... and {len(summary['packages']) - 12} more")
            print()
    else:
        print("AI-SBOM single-root summary")
        print(f"  Project:          {summary['project_name']} v{summary['version']}")
        print(f"  Components:       {summary['component_count']}")
        print(f"  TIBET tokens:     {summary['tibet_chain_length']}")
        print(f"  Vulnerabilities:  {summary['vulnerability_count']}")
        manifests = ",".join(summary["manifest_types"]) or "-"
        print(f"  Manifest types:   {manifests}")
        print()
        if summary["component_count"] == 0 and summary["workspace_roots_detected"] > 0:
            print("  Note:")
            print("    This path looks more like a workspace than a single package root.")
            print("    Try: tibet-ai-sbom scan /path --workspace")
            print()
    if bool(getattr(args, "focused", False)):
        print("  Focus mode:      config-first governance scan (lightweight)")
        print()

    if summary.get("overlay", {}).get("loaded"):
        print("Overlay:")
        print(f"  Source:           {summary['overlay']['path']}")
        print(f"  Models:           {summary['overlay']['section_counts']['models']}")
        print(f"  Datasets:         {summary['overlay']['section_counts']['datasets']}")
        print(f"  KPI records:      {summary['overlay']['section_counts']['kpi']}")
        print()

    model_evidence = summary.get("model_evidence", {})
    actor_signals = model_evidence.get("actor_signals", {})
    print("Model signals:")
    print(f"  Declared:         {len(model_evidence.get('declared_models', []))}")
    print(f"  Local artifacts:  {len(model_evidence.get('local_model_artifacts', []))}")
    print(f"  Runtime signals:  {len(model_evidence.get('runtime_model_signals', []))}")
    print(f"  External prov.:   {len(model_evidence.get('external_model_providers', []))}")
    print(f"  Suspicious cand.: {len(model_evidence.get('suspicious_model_candidates', []))}")
    print(f"  .aint refs:       {actor_signals.get('aint_ref_count', 0)}")
    print(f"  Actor refs:       {actor_signals.get('actor_ref_count', 0)}")
    print(f"  Agent IDs:        {actor_signals.get('agent_id_count', 0)}")
    print(f"  JIS IDs:          {actor_signals.get('jis_id_count', 0)}")
    print(f"  JIS sessions:     {actor_signals.get('session_count', 0)}")
    print(f"  Session fp's:     {actor_signals.get('session_fingerprint_count', 0)}")
    print()

    artifacts = summary.get("artifacts", {})
    evidence = summary.get("evidence", {})
    evidence_details = evidence.get("details", {})
    print("Runtime signals:")
    print(f"  Sealed TBZ objs:  {artifacts.get('sealed_tbz_objects', 0)}")
    print(f"  Signed non-TBZ:   {artifacts.get('signed_non_tbz_references', 0)}")
    print(f"  Unsigned ext:     {artifacts.get('unsigned_external_objects', 0)}")
    print(f"  Continuity links: {evidence.get('continuity_links', 'planned')}")
    print(f"  Trail sources:    {evidence_details.get('trail_source_count', 0)}")
    print(f"  Token trails:     {evidence_details.get('token_trail_source_count', 0)} "
          f"(tokens {evidence_details.get('token_trail_total', 0)})")
    if evidence_details.get("twin_profile_count"):
        print(
            f"  Twin profiles:    {evidence_details.get('twin_profile_count')} "
            f"(min drift {evidence_details.get('twin_min_drift_ms')}ms)"
        )
    print()

    print("Cluster summary:")
    for row in summary["cluster_status"]:
        print(
            f"  {row['prefix']:<3} "
            f"covered={row['covered']:<2} "
            f"partial={row['partial']:<2} "
            f"missing={row['missing']:<2} "
            f"<- {row['current_sources']}"
        )
    print()

    print("What this scan already gives you:")
    print("  - software inventory via tibet-sbom")
    print("  - provenance-bearing component scan")
    print("  - vulnerability view for software components")
    print("  - a BSI/G7 cluster map over that current evidence")
    print()
    print("What is still missing:")
    missing_reasons = summary.get("missing_reasons", {})
    if "models" in missing_reasons:
        print("  - first-class model completeness")
    if "datasets" in missing_reasons:
        print("  - first-class dataset completeness")
    if "kpi" in missing_reasons:
        print("  - KPI and drift metrics")
    if summary.get("artifacts", {}).get("encryption_boundary", {}).get("status") != "present":
        print("  - signed/sealed/encrypted artifact modeling")
    if any(v != "present" for v in summary.get("evidence", {}).values()):
        print("  - explicit TIBET chain-of-command and usage evidence")
    if summary.get("missing_reasons"):
        print()
        print("Why some clusters still stay missing:")
        for label in ("models", "datasets", "kpi"):
            reason = summary["missing_reasons"].get(label)
            if reason:
                print(f"  - {label.capitalize():<8} {reason}")
    return 0


def _cmd_export(args) -> int:
    summary, status = _build_summary_from_args(args)
    if status != 0 or summary is None:
        return status

    document = _build_ai_sbom_document(summary)
    print(json.dumps(document, indent=2 if args.pretty else None))
    return 0


def _cmd_validate(args) -> int:
    schema, schema_error = _load_ai_sbom_schema()
    if schema is None:
        print(schema_error, file=sys.stderr)
        return 2

    source_label = None
    if args.input:
        input_path = Path(args.input).expanduser().resolve()
        if not input_path.exists():
            print(f"input not found: {input_path}", file=sys.stderr)
            return 2
        document, input_error = _load_document_input(input_path)
        if document is None:
            print(input_error, file=sys.stderr)
            return 2
        source_label = str(input_path)
    else:
        summary, status = _build_summary_from_args(args)
        if status != 0 or summary is None:
            return status
        document = _build_ai_sbom_document(summary)
        source_label = str(Path(args.path or ".").resolve())

    errors = _validate_against_schema(document, schema)
    warnings = _convention_warnings(document)
    report = {
        "valid": len(errors) == 0,
        "error_count": len(errors),
        "warning_count": len(warnings),
        "source": source_label,
        "schema": str(_schema_file_path()),
        "errors": errors,
        "warnings": warnings,
    }

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"tibet-ai-sbom validate {source_label}")
        print()
        print(f"Schema:      {report['schema']}")
        print(f"Result:      {'VALID' if report['valid'] else 'INVALID'}")
        print(f"Errors:      {report['error_count']}")
        print(f"Warnings:    {report['warning_count']}")
        if errors:
            print()
            print("Schema errors:")
            for item in errors:
                print(f"  - {item}")
        if warnings:
            print()
            print("Convention warnings:")
            for item in warnings:
                print(f"  - {item}")

    return 0 if not errors else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tibet-ai-sbom",
        description=(
            "BSI/G7 SBOM-for-AI implementation. "
            "See README.md and ROADMAP.md for the conformance plan."
        ),
    )
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("version", help="Show package version and banner.")

    p_clusters = sub.add_parser(
        "clusters",
        help="List BSI cluster codes (optionally filtered by cluster).",
    )
    p_clusters.add_argument(
        "--cluster",
        help="Filter by cluster prefix (MD, SLP, MOD, DSE, INF, SEC, KPI).",
    )

    p_code = sub.add_parser("code", help="Describe a single cluster code.")
    p_code.add_argument("code", help="A cluster code such as AISBOM-MD-001.")

    p_scan = sub.add_parser(
        "scan",
        help="Run an AI-SBOM scan using tibet-sbom as the substrate.",
    )
    p_scan.add_argument("path", nargs="?", default=None)
    p_scan.add_argument(
        "--workspace",
        action="store_true",
        help="Scan child package roots under a workspace path",
    )
    p_scan.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="Machine-readable JSON summary",
    )
    p_scan.add_argument(
        "--overlay",
        help="Optional JSON overlay with system/models/datasets/kpi/artifacts/evidence",
    )
    p_scan.add_argument(
        "--trail-file",
        help="Explicit TIBET audit trail JSONL file to include as evidence",
    )
    p_scan.add_argument(
        "--focused",
        action="store_true",
        help="Use config-first governance scan instead of full substrate scan",
    )

    p_export = sub.add_parser(
        "export",
        help="Export a normalized ai-sbom-json document.",
    )
    p_export.add_argument("path", nargs="?", default=None)
    p_export.add_argument(
        "--workspace",
        action="store_true",
        help="Export from workspace scan mode",
    )
    p_export.add_argument(
        "--overlay",
        help="Optional JSON overlay with system/models/datasets/kpi/artifacts/evidence",
    )
    p_export.add_argument(
        "--trail-file",
        help="Explicit TIBET audit trail JSONL file to include as evidence",
    )
    p_export.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    p_export.add_argument(
        "--focused",
        action="store_true",
        help="Export from config-first governance scan instead of full substrate scan",
    )

    p_validate = sub.add_parser(
        "validate",
        help="Validate an ai-sbom-json document or a generated scan/export view.",
    )
    p_validate.add_argument("path", nargs="?", default=None)
    p_validate.add_argument(
        "--input",
        help="Validate an existing ai-sbom-json file instead of generating one from a scan",
    )
    p_validate.add_argument(
        "--workspace",
        action="store_true",
        help="Generate validation input from workspace scan mode",
    )
    p_validate.add_argument(
        "--overlay",
        help="Optional JSON overlay with system/models/datasets/kpi/artifacts/evidence",
    )
    p_validate.add_argument(
        "--trail-file",
        help="Explicit TIBET audit trail JSONL file to include as evidence",
    )
    p_validate.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="Machine-readable validation report",
    )
    p_validate.add_argument(
        "--focused",
        action="store_true",
        help="Validate a config-first generated document instead of full substrate scan",
    )

    args = parser.parse_args(argv)
    handlers = {
        "version": _cmd_version,
        "clusters": _cmd_clusters,
        "code": _cmd_code,
        "scan": _cmd_scan,
        "export": _cmd_export,
        "validate": _cmd_validate,
    }
    if args.cmd is None:
        parser.print_help()
        return 0
    try:
        return handlers[args.cmd](args)
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
