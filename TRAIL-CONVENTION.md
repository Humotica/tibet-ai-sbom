# TIBET Trail Convention for `tibet-ai-sbom`

Date: 2026-05-15
Status: local project convention

## Purpose

`tibet-ai-sbom` can ingest TIBET provenance trails as evidence.

To make that reliable across projects, a local path convention is
useful.

## Preferred Path

The preferred project-local path is:

```text
.tibet/provenance/audit.jsonl
```

Why this path:

- `.tibet/` makes the ownership explicit
- `provenance/` says what kind of data it contains
- `audit.jsonl` is simple and tool-friendly

## Also Recognized

The current CLI also recognizes:

```text
.tibet/provenance/trail.jsonl
.tibet/provenance/tokens.jsonl
.tibet/trail/audit.jsonl
.tibet/trail/tokens.jsonl
audit.jsonl
trail.jsonl
tibet-trail.jsonl
```

These are compatibility paths.

The preferred path for new projects remains:

```text
.tibet/provenance/audit.jsonl
```

## Why This Helps

This gives a stable split between layers:

- package manifests describe software
- overlays describe AI-specific system truth
- `.tibet/provenance/` holds audit and token truth

That means `tibet-ai-sbom` can auto-detect evidence without guessing too
much.

## Explicit Override

Projects can always override autodetection:

```bash
tibet-ai-sbom scan /path/to/project --trail-file /path/to/custom-audit.jsonl
tibet-ai-sbom export /path/to/project --trail-file /path/to/custom-audit.jsonl --pretty
```

## Short Form

If a project emits a local TIBET provenance trail, put it at:

```text
.tibet/provenance/audit.jsonl
```
