# tibet-ai-sbom — Conformance Roadmap

Phased plan to evolve `tibet-ai-sbom` from its 0.1.0 honest foundation
to full BSI/G7 SBOM-for-AI minimum-element coverage.

The roadmap deliberately puts **structural** work before
**AI-specific** depth, because an AI-SBOM that cannot see system
topology will always be partial regardless of how rich the model and
dataset schemas become.

## Phase 0 — Honest positioning (✓ done in 0.1.0)

- Public cluster-code catalogue (`AISBOM-{CLUSTER}-{NNN}`).
- Honest coverage table per cluster element.
- Explicit cite of the BSI paper.
- Generic alias `ai-sbom` published alongside `tibet-ai-sbom`.

## Phase 1 — Workspace and topology scan

- Workspace scan CLI surface (`tibet-ai-sbom workspace PATH`).
- Discovery of sibling package roots under one directory tree.
- Per-package classification.
- Publish-surface metadata per package where available.

This is the **structural prerequisite** for a system-level AI-SBOM.
An AI system is rarely one project root; it is a workspace.

## Phase 2 — System layer

- First-class `system` object fed by workspace scan.
- System name / version / producer / timestamp / components.
- System data flow, data usage, input/output properties.
- Intended application area.

## Phase 3 — Models layer

- First-class `models[]` schema.
- Model name / identifier / version / producer / timestamp.
- Model hash + algorithm.
- Model training properties.
- Model input-output properties.
- Model license and external references.

## Phase 4 — Dataset layer

- First-class `datasets[]` schema.
- Dataset name / identifier / hash / provenance.
- Dataset sensitivity classification.
- Dataset dependency relationship.
- Dataset license.

## Phase 5 — Infrastructure layer

- `infrastructure` object distinguishing software vs hardware.
- Accelerator and deployment-environment fields.
- Optional HBOM reference for hardware bill of materials.

## Phase 6 — Security properties layer

- Explicit `security_properties` object.
- Security controls and compliance frameworks.
- Provenance / integrity / continuity policy declarations.

## Phase 7 — KPI layer

- `kpis` object with security metrics, drift, operational performance.
- Integration with `tibet-twin` for drift signals.
- Integration with `tibet-trail` for operational trace metrics.

## Phase 8 — CBOM and evidence integration

- Explicit evidence references at document level:
  `provenance_chain_ref`, `cbom_walk_ref`, `continuity_events_ref`,
  `custody_timeline_ref`.
- The SBOM stays the structured manifest;
  causal evidence remains a separate, linked layer.

## Phase 9 — Export strategy

- `export_ai_sbom()` — native AI-SBOM JSON schema.
- CycloneDX 1.5 export (compatibility).
- SPDX 2.3 export (compatibility).
- Optional embedding into CycloneDX/SPDX extension fields where
  useful, after the native schema stabilises.

## Phase 10 — CLI evolution

- `tibet-ai-sbom scan PATH --workspace`
- `tibet-ai-sbom export --format ai-sbom`
- `tibet-ai-sbom enrich --models ... --datasets ...`
- `tibet-ai-sbom check --profile bsi-ai`

## Source materials

The roadmap is grounded in:

- BSI / G7 *Software Bill of Materials for AI — Minimum Elements*.
- A detailed engineering gap analysis at
  `/srv/jtel-stack/packages/tibet-sbom/docs/bsi-sbom-for-ai-gap-analysis-2026-05-14.md`.
- A BSI cluster feature matrix at
  `/srv/jtel-stack/packages/tibet-sbom/docs/bsi-cluster-feature-matrix-2026-05-14.md`.
- An AI-SBOM JSON schema sketch at
  `/srv/jtel-stack/packages/tibet-sbom/docs/ai-sbom-json-schema-sketch-2026-05-14.md`.
