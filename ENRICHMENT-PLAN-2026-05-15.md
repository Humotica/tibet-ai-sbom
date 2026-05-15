# `tibet-ai-sbom` Enrichment Plan

Date: 2026-05-15
Status: design note

## Short Verdict

The current split is clear:

- `tibet-sbom` has **substance**
- `tibet-ai-sbom` has **framing**

Right now `tibet-ai-sbom` is useful as:

- a BSI / G7 cluster index
- a conformance surface
- an honest roadmap entry point

But it is not yet useful as:

- a rich operator tool
- a system-aware scanner
- an evidence-bearing AI-SBOM producer

That is the gap to close.

## Confirmed Current State

### `tibet-ai-sbom`

Current CLI provides:

- `version`
- `clusters`
- `code`
- `scan` as placeholder

This makes the package legible, but thin.

### `tibet-sbom`

Current `tibet-sbom` scan logic is one-root only.

It looks only at manifests in the selected path:

- `pyproject.toml`
- `requirements.txt`
- `package.json`
- `Cargo.toml`
- `go.mod`

It does **not** discover sibling package roots below a workspace.

That is not theoretical.

A direct scan of:

- `/srv/jtel-stack/packages`

currently returns:

- `Project: packages v0.0.0`
- `No components found`

So the system-wide / workspace limitation is real and currently blocks a
richer AI-SBOM experience.

## Core Design Decision

`tibet-ai-sbom` should not become a second shallow scanner.

It should become a:

- **wrapper**
- **overlay**
- **interpreter**

on top of:

- `tibet-sbom` for software inventory and provenance
- later workspace scan in `tibet-sbom`
- later TIBET / CBOM evidence sources

In other words:

- `tibet-sbom` finds and exports inventory truth
- `tibet-ai-sbom` maps that truth onto AI-SBOM clusters and fills the
  system / artifact / evidence layer around it

## What `tibet-ai-sbom` Should Feel Like

Today it feels like:

- "here are the requirement codes"

It should evolve toward:

- "here is your system"
- "here is current BSI coverage"
- "here is what evidence supports that coverage"
- "here is what is still missing"

That means the primary command should not be `code`.

It should be `scan`.

## Recommended Product Shape

## Layer 1 - Reuse `tibet-sbom` directly

`tibet-ai-sbom scan PATH` should call into `tibet-sbom` scan logic where
possible instead of duplicating software inventory logic.

Immediate benefits:

- software component discovery
- direct/transitive relationships
- provenance token generation
- export-ready substrate

This gives `tibet-ai-sbom` real scan output fast.

## Layer 2 - Add AI-SBOM mapping

After collecting the `tibet-sbom` result, `tibet-ai-sbom` should map it
into:

- metadata cluster coverage
- system-level partial coverage
- infrastructure partial coverage
- security-property partial coverage

And it should explain:

- why a cluster item is `covered`
- why it is `partial`
- what source produced that status
- what is still missing

## Layer 3 - Add workspace truth

This is the key blocker.

Without workspace discovery, `tibet-ai-sbom` cannot honestly describe:

- a package garden
- a multi-package AI system
- package-to-package topology
- publish surfaces across the system

So the next meaningful feature remains:

- workspace-aware scanning in `tibet-sbom`

That feature should then be consumed by `tibet-ai-sbom`, not copied into
it separately.

## Layer 4 - Add AI-specific surfaces

Once the substrate is real, `tibet-ai-sbom` can add:

- system object
- models
- datasets
- infrastructure object
- KPI object
- artifact intake and trust boundary semantics

## Recommended CLI Evolution

## v0.1.x

Keep:

- `version`
- `clusters`
- `code`

But make it clear these are support surfaces, not the main operator
experience.

## v0.2.0

Make `scan` real.

Minimum expected behavior:

- call underlying `tibet-sbom` scan logic
- print actual inventory summary
- print AI-SBOM coverage summary
- show source mapping per cluster
- show explicit missing areas

Example shape:

```text
AI-SBOM scan: /srv/jtel-stack/packages/tibet-sbom

Software inventory:
  components: 23
  provenance tokens: 23
  manifests: pyproject.toml

Cluster coverage:
  MD   covered/partial
  SLP  partial
  MOD  missing
  DSE  missing
  INF  partial
  SEC  partial
  KPI  missing

Evidence sources:
  metadata      <- tibet-sbom document metadata
  software      <- tibet-sbom components
  vulnerabilities <- tibet-sbom vulnerability view
  provenance    <- TIBET token references
```

## v0.3.0

Introduce workspace mode once `tibet-sbom` supports it:

- `tibet-ai-sbom scan PATH --workspace`

Expected additions:

- discovered package roots
- package roles
- publish surfaces
- system component graph

## v0.4.0+

Introduce:

- `export --format ai-sbom-json`
- model declarations
- dataset declarations
- infrastructure enrichment
- evidence links

## Why `tibet-sbom` Must Evolve First

The clean architecture is not:

- copy `tibet-sbom` scanning into `tibet-ai-sbom`

The clean architecture is:

- make `tibet-sbom` workspace-aware
- let `tibet-ai-sbom` consume that richer substrate

Why:

- one source of truth for software inventory
- one place for provenance-bearing SBOM logic
- less duplicated parser logic
- richer scan results for both packages

## Artifact and Evidence Direction

When `tibet-ai-sbom` becomes richer, it should not stop at package
inventory.

It should expose:

- sealed TBZ artifacts
- signed non-TBZ references
- encryption boundary (`v1` vs `v2`)
- verification grade
- TIBET chain-of-command
- TIBET usage / custody evidence

This should appear as an **AI overlay** on top of software SBOM
inventory, not as a replacement for it.

## Concrete Recommendation

If work is split pragmatically, the best order is:

1. improve `tibet-sbom` with workspace scan
2. let `tibet-ai-sbom scan` wrap `tibet-sbom` for single-root scans
3. add cluster coverage mapping from scan result
4. add explanation mode for `covered / partial / missing`
5. add workspace mode to `tibet-ai-sbom`
6. add AI-SBOM JSON export

## One Sentence

`tibet-ai-sbom` should become the AI-aware interpretation layer for
`tibet-sbom`, not a second thin scanner with better terminology.
