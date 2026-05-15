# TIBET Trail Record Convention

Date: 2026-05-15
Status: draft interoperability convention

## Purpose

`tibet-ai-sbom` should be able to read provenance trails without being
tightly coupled to one producer implementation.

That means:

- `tibet-core` can be a first-class producer
- but it must not be the only valid producer

This document defines the minimum JSONL record shape that `tibet-ai-sbom`
can recognize as a **TIBET-compatible token trail**.

## File Format

A trail file is:

- UTF-8 text
- one JSON object per line
- append-friendly
- safe to stream

Recommended file name:

```text
.tibet/provenance/audit.jsonl
```

## Minimum Record Shape

For `ai-sbom` to count a JSONL line as a TIBET-compatible token trail
record, the JSON object should contain at least:

- `token_id`
- `action`
- `actor`
- `timestamp`

These are the current minimum recognition fields.

Example minimal record:

```json
{
  "token_id": "tibet_20260515091500000000_ab12cd34",
  "action": "scan_workspace",
  "actor": "jis:humotica:ai-sbom",
  "timestamp": "2026-05-15T09:15:00Z"
}
```

## Recommended Full Record Shape

The richer interoperable shape is:

- `token_id`
- `action`
- `actor`
- `timestamp`
- `erin`
- `eraan`
- `eromheen`
- `erachter`
- `parent_id`
- `state`
- `content_hash`
- `signature`

This mirrors the current TIBET token semantics without forcing every
producer to import `tibet-core`.

## Semantic Meaning

Recommended meanings:

- `token_id`
  - stable record identifier
- `action`
  - what happened
- `actor`
  - who or what performed it
- `timestamp`
  - when it happened
- `erin`
  - what was acted on
- `eraan`
  - attachments / dependencies / references
- `eromheen`
  - surrounding context
- `erachter`
  - intent / reason
- `parent_id`
  - parent chain reference
- `state`
  - lifecycle stage
- `content_hash`
  - integrity digest
- `signature`
  - optional signature or authenticator

## Recognition Levels

`ai-sbom` should distinguish three practical levels:

### 1. Generic audit JSONL

The file is JSONL, but records do not match the minimum TIBET token
shape.

Meaning:

- usable as an audit source
- not countable as a token trail

### 2. TIBET-compatible token trail

The file contains records with at least:

- `token_id`
- `action`
- `actor`
- `timestamp`

Meaning:

- count as token trail
- actor/action statistics may be computed

### 3. Full TIBET token trail

The file contains the richer token fields and integrity data.

Meaning:

- stronger provenance semantics
- better verification potential

## Why This Matters

This keeps the ecosystem open.

`ai-sbom` is then reading:

- a convention

not:

- one Python class implementation only

That means:

- `tibet-core` can write it
- other runtimes can write it
- future Rust/Go/JS tools can write it
- `ai-sbom` can still understand it

## Producer Guidance

If you want a tool to generate AI-SBOM-readable provenance trails:

1. write JSONL
2. emit the minimum record shape
3. prefer the richer TIBET fields when possible
4. place the file at:

```text
.tibet/provenance/audit.jsonl
```

## Current `ai-sbom` Behavior

Today `ai-sbom`:

- counts a file as token trail if the minimum fields are present
- treats other JSONL audit logs as generic trail sources
- reports both counts separately

That is deliberate.

It avoids pretending that every audit log is already a full provenance
trail.
