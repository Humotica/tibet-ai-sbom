# Changelog

All notable changes to the `tibet-ai-sbom` package are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — 2026-05-15

### Added

- Focused governance scan mode for large repositories.
- Tier A governance ingestion:
  - AINS registry events
  - JIS session events
  - I-Poll activity
  - continuityd state
- Governance export with:
  - `questions`
  - `trust_foundation`
  - `actor_catalog`
  - `actor_model_provider_links`
  - `usage_events`
- Open trail path and record conventions for provenance JSONL.
- Model discovery lanes:
  - declared models
  - local artifacts
  - runtime signals
  - external providers
  - suspicious candidates
  - actor signals
- Tier B gateway ingestion:
  - live `tibet-gateway` JSONL events
  - repo-agnostic `gateway-config` fallback events
- `export` and `validate` commands for `ai-sbom-json`.
- Tests for gateway ingest and actor-link upgrade behavior.

### Changed

- `scan` is no longer just taxonomy-oriented; it now produces a governance-first AI-SBOM view.
- Gateway/provider discovery is no longer `brain_api`-bound and can work for other repo paths such as `service_api` or `telecom_api`.

### Notes

- Core app emitters for Option 2 still belong to Root AI because they touch application runtime code.

## [0.1.0] — 2026-05-15

### Added

- **Initial public release.** First PyPI package to address the BSI/G7
  *Software Bill of Materials for AI — Minimum Elements* specification
  as a first-class concern.
- **CVE-style cluster codes** for every BSI minimum element.
  Codes follow the format ``AISBOM-{CLUSTER}-{NNN}`` where ``CLUSTER``
  is one of MD, SLP, MOD, DSE, INF, SEC, KPI.
- **CLI entry point** ``tibet-ai-sbom`` with subcommands:
  - ``version`` — show package version and banner.
  - ``clusters [--cluster X]`` — list cluster codes.
  - ``code AISBOM-...`` — describe a single cluster element.
  - ``scan [PATH]`` — workspace scan placeholder (full impl on roadmap).
- **Cluster catalogue** as a Python data structure
  (``CLUSTER_CODES`` dict + ``BSICluster`` enum + ``ClusterInfo``
  dataclass).
- **Honest coverage status** per element: ``covered``, ``partial``, or
  ``missing``. Aspirational compliance claims are explicitly avoided in
  this release.
- **CONFORMANCE.md and ROADMAP.md** companion documents that explain
  the current gap and the path to BSI alignment.

### Notes

- The package establishes the *foundation*: terminology, cluster
  codes, and the workspace-scan entry point. Full coverage of Models,
  Datasets, and KPIs is scheduled for subsequent releases.
- The generic alias package ``ai-sbom`` is published alongside this
  release and is pinned to ``tibet-ai-sbom==0.1.0``.
