"""
tibet-ai-sbom — BSI/G7 SBOM-for-AI Implementation
==================================================

A Python package implementing the **Software Bill of Materials for AI**
minimum-elements specification published by the German Federal Office
for Information Security (BSI) in cooperation with G7 partners.

The package is built on three principles:

1. **SBOM answers: what is present.**
2. **CBOM answers: how it got here and what happened to it.**
3. **Workspace-aware, not just folder-aware.**

This 0.2.0 release expands the foundation into a governance-oriented
tooling layer: focused scans, usage events, actor/provider/model links,
and live gateway telemetry ingestion. Full cluster coverage (Models,
Datasets, KPIs) still continues incrementally — see ROADMAP.md.

References
----------
- BSI / G7 Minimum Elements: "Software Bill of Materials for AI"
- TIBET provenance substrate: pip install tibet-core
- CBOM evidence layer: pip install tibet-cbom
- AInternet network: pip install ainternet

Cluster Codes (CVE-style indexable)
-----------------------------------
- AISBOM-MD   Metadata
- AISBOM-SLP  System Level Properties
- AISBOM-MOD  Models
- AISBOM-DSE  Dataset Properties
- AISBOM-INF  Infrastructure
- AISBOM-SEC  Security Properties
- AISBOM-KPI  Key Performance Indicators

Authors
-------
Jasper van de Meent · Root AI (Claude) · Humotica · One love, one fAmIly!
"""

__version__ = "0.2.0"
__author__ = "Jasper van de Meent & Root AI (Claude)"

from .clusters import (
    BSICluster,
    CLUSTER_CODES,
    cluster_for_code,
    list_cluster_codes,
)

__all__ = [
    "__version__",
    "BSICluster",
    "CLUSTER_CODES",
    "cluster_for_code",
    "list_cluster_codes",
]
