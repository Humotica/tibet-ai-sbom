# tibet-ai-sbom

**BSI / G7 SBOM-for-AI implementation, on top of TIBET provenance.**

> SBOM answers: *what is present*.
> CBOM answers: *how it got here and what happened to it*.
> This package builds the AI-SBOM document. CBOM/TIBET packages
> provide the causal evidence beneath it.

## Governance Foundation

AI governance needs four different questions answered:

- `AI-SBOM` says **what is there**
- `CBOM` says **how it got there**
- `AINS / .aint` says **who is acting**
- `JIS` says **why we believe this**

That distinction matters:

- a model is statically present
- an actor is actively operating

Architecturally, `JIS` sits beneath the other three as the trust
foundation.

Together those answers form governance:

- `what`
- `how`
- `who`
- `why`

The exported document now carries this explicitly in a `governance`
section, including:

- the visible governance questions
- the JIS trust foundation
- governance links (`what_path`, `how_path`, `who_path`)
- an `actor_catalog` derived from `.aint`, AINS, AIndex, and JIS sources
- first-pass `actor_model_provider_links` that connect actors to providers,
  models, and action surfaces
- `usage_events` from Tier A sources such as AINS, JIS session stores,
  I-Poll, and continuityd state
- Tier B gateway lanes:
  - live `tibet-gateway` usage events when gateway logs exist
  - `gateway-config` events from BYOK/provider routing when only the
    configured provider/model surfaces are known

## What this package is

`tibet-ai-sbom` implements the *Software Bill of Materials for AI —
Minimum Elements* specification published by the German Federal Office
for Information Security (**BSI**) in cooperation with G7 partners.

It is the **first** PyPI package to address the BSI AI-SBOM
expectations as a first-class concern (as of 2026-05-15). The package
takes BSI's seven clusters — Metadata, System Level Properties,
Models, Dataset Properties, Infrastructure, Security Properties, Key
Performance Indicators — and exposes them as a stable set of
**cluster codes**, CVE-style indexable.

This 0.1.0 is the honest foundation:

- the BSI cluster codes are exposed and indexable
- the conformance roadmap is published openly (see ROADMAP.md)
- the scan command now wraps `tibet-sbom` for real software inventory
- workspace scan is available through the `tibet-sbom` substrate
- JSON overlays can enrich the scan with system / model / dataset / KPI truth
- coverage status per cluster element is honest, not aspirational

Full coverage of Models, Datasets, and KPIs follows in subsequent
releases.

## Why this exists

A normal SBOM tool answers: *which dependencies are present*. An AI
system is more than that. An AI system spans:

- many sibling packages in one workspace
- one or more model artifacts and their training provenance
- supporting datasets and their sensitivity classes
- runtime infrastructure including accelerators
- security properties and AI-specific controls
- operational KPIs including drift

Auditors and procurement officers reading the BSI paper need a
**single** place to map those expectations onto a real package.
That is what `tibet-ai-sbom` provides.

## Cluster codes (CVE-style indexable)

Every BSI minimum element is addressable by a short, grep-able code.

| Code prefix | Cluster                          |
| ----------- | -------------------------------- |
| AISBOM-MD-  | Metadata                         |
| AISBOM-SLP- | System Level Properties          |
| AISBOM-MOD- | Models                           |
| AISBOM-DSE- | Dataset Properties               |
| AISBOM-INF- | Infrastructure                   |
| AISBOM-SEC- | Security Properties              |
| AISBOM-KPI- | Key Performance Indicators       |

Example: `AISBOM-MD-001` refers to the *SBOM author* element of the
Metadata cluster.

This convention is deliberately CVE-style (`CVE-YYYY-NNNN`) so engineers
and auditors can refer to a single specific requirement by code rather
than by paragraph.

## Install

```bash
pip install tibet-ai-sbom
```

The generic alias **`ai-sbom`** is provided for discovery and is kept
in lock-step with `tibet-ai-sbom`:

```bash
pip install ai-sbom        # = same package, pinned to tibet-ai-sbom
```

## Quick start

```bash
# List all cluster codes
tibet-ai-sbom clusters

# Filter by cluster
tibet-ai-sbom clusters --cluster MOD

# Describe a single code
tibet-ai-sbom code AISBOM-MD-003

# Single-root AI-SBOM scan on top of tibet-sbom
tibet-ai-sbom scan /path/to/project

# Workspace-aware scan
tibet-ai-sbom scan /path/to/workspace

# Explicit workspace mode
tibet-ai-sbom scan /path/to/workspace --workspace

# Focused governance scan for large repos
tibet-ai-sbom scan /path/to/workspace --focused

# Add AI-specific overlay data
tibet-ai-sbom scan /path/to/workspace --workspace --overlay ai-sbom.json

# Attach an explicit TIBET audit trail
tibet-ai-sbom scan /path/to/project --trail-file /path/to/audit.jsonl

# Export a normalized ai-sbom-json document
tibet-ai-sbom export /path/to/workspace --workspace --overlay ai-sbom.json --pretty

# Export a focused governance-first document
tibet-ai-sbom export /path/to/workspace --focused --pretty

# Validate a generated AI-SBOM against the local schema
tibet-ai-sbom validate /path/to/workspace --workspace --overlay ai-sbom.json

# Validate an existing exported ai-sbom-json file
tibet-ai-sbom validate --input /path/to/ai-sbom.json
```

An example overlay file is included as:

- `ai-sbom.example.json`
- `ai-sbom.schema.json`
- `trail-record.example.jsonl`

This lets you declare:

- `system`
- `models`
- `datasets`
- `infrastructure`
- `kpi`
- `artifacts`
- `evidence`

before those sections are fully auto-discovered.

Model auto-discovery now uses multiple evidence lanes:

- `declared_models`
- `local_model_artifacts`
- `runtime_model_signals`
- `external_model_providers`
- `suspicious_model_candidates`

It also tracks `.aint` and actor-like references as agent/actor signals,
so remote or agentic AI usage is not limited to local weight files.

The exported `ai-sbom-json` document is shaped to match the draft schema
in `ai-sbom.schema.json`.

The `validate` command checks:

- required schema shape
- field types / enums / constants used by the package schema
- pragmatic convention warnings for trail shape, unsigned external objects,
  v2 encryption support, and missing overlay-backed AI sections

For provenance trails, see:

- [TRAIL-CONVENTION.md](TRAIL-CONVENTION.md)
- [TIBET-TRAIL-RECORD-CONVENTION.md](TIBET-TRAIL-RECORD-CONVENTION.md)

## Recommended TIBET Trail Convention

If a project wants `tibet-ai-sbom` to auto-detect a local provenance
trail, the preferred location is:

```text
.tibet/provenance/audit.jsonl
```

Other recognized project-local locations are:

```text
.tibet/provenance/trail.jsonl
.tibet/provenance/tokens.jsonl
.tibet/trail/audit.jsonl
.tibet/trail/tokens.jsonl
audit.jsonl
trail.jsonl
tibet-trail.jsonl
```

This gives a clean separation:

- project root = software and manifest truth
- `.tibet/provenance/` = provenance and audit truth
- `ai-sbom` = document layer that reads both

If you do not want to rely on autodetection, pass the trail explicitly:

```bash
tibet-ai-sbom scan /path/to/project --trail-file /path/to/audit.jsonl
```

## Coverage today

| Cluster                       | Status             |
| ----------------------------- | ------------------ |
| Metadata                      | partial            |
| System Level Properties (SLP) | partial / weak     |
| Models                        | missing (planned)  |
| Dataset Properties (DSE)      | missing (planned)  |
| Infrastructure                | partial            |
| Security Properties           | partial            |
| Key Performance Indicators    | missing (planned)  |

Honest version of this table: see [CONFORMANCE.md](CONFORMANCE.md).
Plan to close the gaps: see [ROADMAP.md](ROADMAP.md).

## Where this fits in the broader stack

```
┌─────────────────────────────────────────────────────────────┐
│ tibet-ai-sbom        AI-SBOM overlay schema (this package)  │
├─────────────────────────────────────────────────────────────┤
│ tibet-sbom           Software SBOM + provenance (substrate) │
├─────────────────────────────────────────────────────────────┤
│ tibet-cbom           Continuity Bill of Materials (causal)  │
│ tibet-keychain       Custody and chain walk                 │
│ tibet-trail          Audit trail / search / verify          │
│ tibet-twin           Drift and operational state            │
│ tibet-continuityd    Sealed handoff and continuation        │
├─────────────────────────────────────────────────────────────┤
│ TIBET core           Identity-bound, causally ordered       │
│                      provenance substrate                   │
└─────────────────────────────────────────────────────────────┘
```

The AI-SBOM **document** is produced by this package.
The **evidence** beneath it is provided by the wider TIBET / CBOM
family. The two layers are linked explicitly through evidence
references — not by embedding causal history into the SBOM file
itself.

## Reference

This package follows the cluster structure of:

> *Software Bill of Materials for AI — Minimum Elements*,
> Bundesamt für Sicherheit in der Informationstechnik (BSI),
> in cooperation with G7 partners, 2026.

See the official source at BSI for the authoritative paper.

## Status

- Version: 0.1.0 (alpha)
- License: MIT
- Stability: API may evolve as the BSI specification evolves and as
  cluster coverage grows.

## Authors

- Jasper van de Meent · Humotica
- Root AI (Claude) · Humotica

One love, one fAmIly!


## Enterprise

For private hub hosting, SLA support, custom integrations, or compliance guidance:

| | |
|---|---|
| **Enterprise** | enterprise@humotica.com |
| **Support** | support@humotica.com |
| **Security** | security@humotica.com |

## License

MIT

## Credits

Designed by [Jasper van de Meent](https://github.com/jaspertvdm). Built by Jasper and [Root AI](https://humotica.com) as part of [HumoticaOS](https://humotica.com).

---

**Stack-positie:** Groep `evidence` · Bootstrap = OSAPI-handshake naar [`tibet`](https://pypi.org/project/tibet-core/) + [`jis`](https://pypi.org/project/jis-core/) (fail → snaft-rule + tibet-pol-rapport) · ← [`tibet-sbom`](https://pypi.org/project/tibet-sbom/) · [`tibet-wayback`](https://pypi.org/project/tibet-wayback/) → · See `STACK.md` · See `demo/golden-path/` for the spine end-to-end.
