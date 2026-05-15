"""
BSI Cluster definitions for SBOM-for-AI.

Each cluster code follows the format ``AISBOM-{CLUSTER}-{NNN}`` where
``CLUSTER`` is a three-letter cluster prefix and ``NNN`` is a
three-digit element index within that cluster.

Example: ``AISBOM-MD-001`` = first Metadata-cluster minimum element.

This is intentionally CVE-style (`CVE-YYYY-NNNN`) so engineers and
auditors can refer to a single specific element of the AI-SBOM
expectation by code rather than by sentence. That makes
auditor-vs-implementer conversations precise and grep-able.

Authoritative source for the cluster list and their semantics is the
BSI / G7 paper *Software Bill of Materials for AI — Minimum Elements*.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional


class BSICluster(str, Enum):
    """The seven BSI clusters of SBOM-for-AI minimum elements."""

    METADATA = "MD"
    SYSTEM_LEVEL_PROPERTIES = "SLP"
    MODELS = "MOD"
    DATASET_PROPERTIES = "DSE"
    INFRASTRUCTURE = "INF"
    SECURITY_PROPERTIES = "SEC"
    KEY_PERFORMANCE_INDICATORS = "KPI"


@dataclass(frozen=True)
class ClusterInfo:
    code: str
    cluster: BSICluster
    title: str
    description: str
    coverage: str  # "covered", "partial", "missing"


# A first-pass cluster-code catalogue. The descriptions paraphrase the
# BSI paper; coverage indicates what the surrounding TIBET / CBOM stack
# already provides today (as of 2026-05-15). This catalogue is meant to
# grow alongside the package — see ROADMAP.md.
CLUSTER_CODES: Dict[str, ClusterInfo] = {
    # ── Metadata cluster ─────────────────────────────────────────────
    "AISBOM-MD-001": ClusterInfo(
        code="AISBOM-MD-001",
        cluster=BSICluster.METADATA,
        title="SBOM author",
        description="Identification of the party that produced the SBOM document.",
        coverage="partial",
    ),
    "AISBOM-MD-002": ClusterInfo(
        code="AISBOM-MD-002",
        cluster=BSICluster.METADATA,
        title="SBOM version",
        description="Document version of the SBOM artifact itself.",
        coverage="partial",
    ),
    "AISBOM-MD-003": ClusterInfo(
        code="AISBOM-MD-003",
        cluster=BSICluster.METADATA,
        title="SBOM data format and version",
        description="Format identifier such as CycloneDX 1.5, SPDX 2.3, ai-sbom-json 0.1.",
        coverage="covered",
    ),
    "AISBOM-MD-004": ClusterInfo(
        code="AISBOM-MD-004",
        cluster=BSICluster.METADATA,
        title="SBOM author signature",
        description="Cryptographic signature over the SBOM by its author.",
        coverage="missing",
    ),
    "AISBOM-MD-005": ClusterInfo(
        code="AISBOM-MD-005",
        cluster=BSICluster.METADATA,
        title="SBOM tool name and version",
        description="Identification of the tool that produced the SBOM.",
        coverage="covered",
    ),
    "AISBOM-MD-006": ClusterInfo(
        code="AISBOM-MD-006",
        cluster=BSICluster.METADATA,
        title="SBOM generation context",
        description="Information about the environment in which the SBOM was produced.",
        coverage="partial",
    ),
    "AISBOM-MD-007": ClusterInfo(
        code="AISBOM-MD-007",
        cluster=BSICluster.METADATA,
        title="SBOM timestamp",
        description="Time at which the SBOM was produced.",
        coverage="covered",
    ),
    # ── System Level Properties (SLP) ────────────────────────────────
    "AISBOM-SLP-001": ClusterInfo(
        code="AISBOM-SLP-001",
        cluster=BSICluster.SYSTEM_LEVEL_PROPERTIES,
        title="System name, version, producer, timestamp",
        description="Top-level identification of the AI system as a whole.",
        coverage="partial",
    ),
    "AISBOM-SLP-002": ClusterInfo(
        code="AISBOM-SLP-002",
        cluster=BSICluster.SYSTEM_LEVEL_PROPERTIES,
        title="System data flow and data usage",
        description="How data moves through the AI system and how it is used.",
        coverage="missing",
    ),
    "AISBOM-SLP-003": ClusterInfo(
        code="AISBOM-SLP-003",
        cluster=BSICluster.SYSTEM_LEVEL_PROPERTIES,
        title="System input/output properties",
        description="What the AI system accepts as input and produces as output.",
        coverage="missing",
    ),
    "AISBOM-SLP-004": ClusterInfo(
        code="AISBOM-SLP-004",
        cluster=BSICluster.SYSTEM_LEVEL_PROPERTIES,
        title="Intended application area",
        description="The intended deployment context of the AI system.",
        coverage="missing",
    ),
    # ── Models cluster ───────────────────────────────────────────────
    "AISBOM-MOD-001": ClusterInfo(
        code="AISBOM-MOD-001",
        cluster=BSICluster.MODELS,
        title="Model name, identifier, version",
        description="First-class identification of each model in the system.",
        coverage="missing",
    ),
    "AISBOM-MOD-002": ClusterInfo(
        code="AISBOM-MOD-002",
        cluster=BSICluster.MODELS,
        title="Model hash and algorithm",
        description="Cryptographic integrity reference for model artifacts.",
        coverage="missing",
    ),
    "AISBOM-MOD-003": ClusterInfo(
        code="AISBOM-MOD-003",
        cluster=BSICluster.MODELS,
        title="Model training properties",
        description="Provenance and configuration of model training.",
        coverage="missing",
    ),
    "AISBOM-MOD-004": ClusterInfo(
        code="AISBOM-MOD-004",
        cluster=BSICluster.MODELS,
        title="Model input-output properties",
        description="Declared inference contract of the model.",
        coverage="missing",
    ),
    # ── Dataset Properties (DSE) ─────────────────────────────────────
    "AISBOM-DSE-001": ClusterInfo(
        code="AISBOM-DSE-001",
        cluster=BSICluster.DATASET_PROPERTIES,
        title="Dataset name, identifier, hash",
        description="First-class identification and integrity for datasets.",
        coverage="missing",
    ),
    "AISBOM-DSE-002": ClusterInfo(
        code="AISBOM-DSE-002",
        cluster=BSICluster.DATASET_PROPERTIES,
        title="Dataset provenance",
        description="Where the dataset originated and how it reached the system.",
        coverage="missing",
    ),
    "AISBOM-DSE-003": ClusterInfo(
        code="AISBOM-DSE-003",
        cluster=BSICluster.DATASET_PROPERTIES,
        title="Dataset sensitivity classification",
        description="Sensitivity level / regulatory class of the dataset content.",
        coverage="missing",
    ),
    # ── Infrastructure (INF) ─────────────────────────────────────────
    "AISBOM-INF-001": ClusterInfo(
        code="AISBOM-INF-001",
        cluster=BSICluster.INFRASTRUCTURE,
        title="Infrastructure software",
        description="Runtime software stack that hosts the AI system.",
        coverage="partial",
    ),
    "AISBOM-INF-002": ClusterInfo(
        code="AISBOM-INF-002",
        cluster=BSICluster.INFRASTRUCTURE,
        title="Infrastructure hardware / accelerators",
        description="GPU/TPU/edge hardware that the AI system depends on.",
        coverage="missing",
    ),
    "AISBOM-INF-003": ClusterInfo(
        code="AISBOM-INF-003",
        cluster=BSICluster.INFRASTRUCTURE,
        title="HBOM reference",
        description="Reference to a separate Hardware Bill of Materials.",
        coverage="missing",
    ),
    # ── Security Properties (SEC) ────────────────────────────────────
    "AISBOM-SEC-001": ClusterInfo(
        code="AISBOM-SEC-001",
        cluster=BSICluster.SECURITY_PROPERTIES,
        title="Security controls",
        description="Declared security controls active for the AI system.",
        coverage="partial",
    ),
    "AISBOM-SEC-002": ClusterInfo(
        code="AISBOM-SEC-002",
        cluster=BSICluster.SECURITY_PROPERTIES,
        title="Security compliance",
        description="Mapping to applicable security regulatory frameworks.",
        coverage="partial",
    ),
    "AISBOM-SEC-003": ClusterInfo(
        code="AISBOM-SEC-003",
        cluster=BSICluster.SECURITY_PROPERTIES,
        title="Vulnerability referencing",
        description="Known vulnerabilities affecting any component.",
        coverage="covered",
    ),
    # ── Key Performance Indicators (KPI) ─────────────────────────────
    "AISBOM-KPI-001": ClusterInfo(
        code="AISBOM-KPI-001",
        cluster=BSICluster.KEY_PERFORMANCE_INDICATORS,
        title="Security metrics",
        description="Quantitative security state indicators.",
        coverage="missing",
    ),
    "AISBOM-KPI-002": ClusterInfo(
        code="AISBOM-KPI-002",
        cluster=BSICluster.KEY_PERFORMANCE_INDICATORS,
        title="Operational performance KPIs",
        description="Operational availability, latency, and similar KPIs.",
        coverage="missing",
    ),
    "AISBOM-KPI-003": ClusterInfo(
        code="AISBOM-KPI-003",
        cluster=BSICluster.KEY_PERFORMANCE_INDICATORS,
        title="Drift metrics",
        description="Behavioral or model drift indicators across time.",
        coverage="missing",
    ),
}


def cluster_for_code(code: str) -> Optional[ClusterInfo]:
    """Look up a single cluster element by its CVE-style code."""
    return CLUSTER_CODES.get(code.upper().strip())


def list_cluster_codes(cluster: Optional[BSICluster] = None) -> List[ClusterInfo]:
    """Return all cluster codes, optionally filtered by cluster."""
    items = list(CLUSTER_CODES.values())
    if cluster is not None:
        items = [it for it in items if it.cluster == cluster]
    return items
