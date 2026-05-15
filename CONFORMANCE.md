# BSI SBOM-for-AI Conformance Status

This document captures the **honest** conformance state of
`tibet-ai-sbom` against the BSI / G7 *Software Bill of Materials for AI
— Minimum Elements* specification.

The purpose is to avoid over-claiming. The package is at version
0.1.0 — it provides the cluster codes, the workspace-scan entry point,
and the foundation. Full coverage of Models, Datasets, and KPIs
follows in subsequent releases.

## Verdict in one sentence

`tibet-ai-sbom` provides the **software and provenance foundation** for
SBOM-for-AI, plus the public cluster-code namespace
(`AISBOM-{CLUSTER}-{NNN}`), and an honest gap analysis. It does **not
yet** claim full BSI minimum-element coverage.

## Honest verdict (= phrasing approved for use in pitches)

> "Does `tibet-ai-sbom` already satisfy the BSI minimum elements
>  for SBOM for AI?"
>
> → No, not yet — at 0.1.0 the Models, Datasets, and KPI clusters
>   are explicitly marked *missing*, and System Level Properties is
>   only partial.
>
> "Does `tibet-ai-sbom` provide a strong base layer for that work?"
>
> → Yes — software composition is solid via the wider TIBET / CBOM
>   family, the cluster codes are public, and the path to alignment
>   is documented in `ROADMAP.md`.

## Cluster-by-cluster coverage today

| Cluster                       | Status   |
| ----------------------------- | -------- |
| Metadata                      | partial  |
| System Level Properties (SLP) | partial  |
| Models                        | missing  |
| Dataset Properties (DSE)      | missing  |
| Infrastructure                | partial  |
| Security Properties           | partial  |
| Key Performance Indicators    | missing  |

A more granular per-element view lives directly in the package:

```bash
tibet-ai-sbom clusters
tibet-ai-sbom clusters --cluster MOD
tibet-ai-sbom code AISBOM-MD-003
```

## Where to deepen

For the **engineering-level** gap analysis and the **10-phase roadmap**
toward full BSI alignment, see:

- [`ROADMAP.md`](ROADMAP.md) — phased plan
- The wider package family at
  `/srv/jtel-stack/packages/tibet-sbom/docs/` — full gap analysis,
  feature matrix, JSON schema sketch, issue breakdown

## Reference

> *Software Bill of Materials for AI — Minimum Elements*,
> Bundesamt für Sicherheit in der Informationstechnik (BSI),
> in cooperation with G7 partners, 2026.
