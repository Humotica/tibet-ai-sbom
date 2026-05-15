# `tibet-ai-sbom` Model Detection Architecture

Date: 2026-05-15
Status: design note

## Short Verdict

Model detection for AI-SBOM cannot rely on file extensions alone.

If `tibet-ai-sbom` only scans for:

- `.gguf`
- `.safetensors`
- `.onnx`
- `.pt`

then it will miss:

- renamed model blobs
- sharded weights
- embedded package data
- runtime-loaded models
- remote inference dependencies
- undeclared but operational external providers

So the correct design is not:

- "find model files"

but:

- "collect model evidence across multiple lanes"
- "grade that evidence"
- "flag gaps between declared, present, and operational truth"

## Core Design Principle

There are two different problems:

1. **heuristic detection**
2. **provenance enforcement**

Heuristics help us discover likely model presence.
Provenance enforcement decides whether the model is legitimate.

`tibet-ai-sbom` should primarily do:

- discovery
- classification
- evidence export
- policy handoff

It does **not** need to be the final enforcement layer.

That enforcement can later be performed by:

- TIBET policy
- continuityd
- tibet-pol
- signed manifests
- keychain / trail / twin evidence

## Model Detection Lanes

The `/models` problem should be split into independent evidence lanes.

### Lane 1 - Declared Models

This is the strongest source of truth.

Sources:

- `ai-sbom.json`
- project-local manifests
- service configuration
- deployment configuration
- runtime-specific model manifests

Examples:

- Ollama model declarations
- vLLM service configs
- LM Studio references
- Hugging Face snapshot manifests
- custom `model.json`

Strength:

- semantically strong
- low false positive rate
- still depends on honest declaration

Recommended output class:

- `declared_model`

### Lane 2 - Local Model Artifacts

This detects probable local model presence on disk.

Sources:

- known weight files
- sidecar files
- directory patterns
- package data

Candidate file types:

- `.gguf`
- `.safetensors`
- `.onnx`
- `.pt`
- `.pth`
- `.ckpt`
- `.bin`
- `.h5`
- `.tflite`
- `.pb`
- `.mlmodel`
- `.joblib`
- `.pkl`

Supporting sidecars:

- `tokenizer.json`
- `config.json`
- `generation_config.json`
- `modelfile`
- `model_index.json`

Strength:

- strong when combined with known headers and sidecars
- weaker when only large generic binaries are found

Recommended output classes:

- `definite_model_artifact`
- `probable_model_artifact`
- `supporting_model_file`

### Lane 3 - Runtime Model Signals

This captures models that may be active even if disk truth is weak.

Signals:

- open model file handles
- mapped model files in `/proc/<pid>/maps`
- abnormal RAM usage jumps
- abnormal VRAM usage
- long-lived GPU / NPU compute activity
- local runtime inventories

Examples:

- `ollama list`
- local Ollama manifest/cache inspection
- vLLM process/config discovery
- runtime directories that indicate loaded models

Strength:

- operationally valuable
- stronger for "warm loaded" or service-managed models
- more platform-specific

Recommended output classes:

- `runtime_confirmed_model`
- `runtime_suspected_model`

### Lane 4 - External Model Providers

This covers remote inference that behaves as part of the local system.

Sources:

- environment variables
- config files
- SDK references
- provider endpoints
- proxy / gateway references

Examples:

- `OPENAI_API_KEY`
- `ANTHROPIC_API_KEY`
- `GEMINI_API_KEY`
- `MISTRAL_API_KEY`
- `TOGETHER_API_KEY`
- OpenAI / Anthropic / Gemini SDK configs

Strength:

- essential for AI-SBOM
- does not prove local model artifacts
- does prove outbound model dependency or capability

Recommended output classes:

- `external_model_provider`
- `remote_inference_dependency`

### Lane 5 - Suspicious Model Candidates

This lane exists for disguised, hidden, or policy-violating model presence.

It is heuristic by nature.

Signals:

- large unknown binary blobs
- sharded weight naming patterns
- model-like archives
- embedded package data with unusual mass
- high-risk serialization formats
- runtime activity without matching declared or artifact truth

Strength:

- necessary for Shadow AI discovery
- never sufficient as sole truth
- must be exported with explicit confidence and risk flags

Recommended output classes:

- `undeclared_large_blob`
- `sharded_weight_candidate`
- `compressed_weight_candidate`
- `high_risk_loader`
- `runtime_without_provenance`

## Evidence Grades

Every model-related item should carry an evidence grade.

Recommended grades:

- `declared`
- `artifact-confirmed`
- `runtime-confirmed`
- `externally-configured`
- `behaviorally-suspected`
- `untrusted`

Interpretation:

- `declared` means explicitly named by operator/config
- `artifact-confirmed` means file evidence strongly matches a model
- `runtime-confirmed` means operational signals show model presence
- `externally-configured` means a remote model provider is configured
- `behaviorally-suspected` means heuristics point at model behavior
- `untrusted` means present but not anchored in provenance or policy

## Risk Flags

The document should separate identity from risk.

A model-like artifact can be:

- known
- unknown
- legitimate
- suspicious

Recommended risk flags:

- `high-risk-serialization`
- `undeclared-large-blob`
- `runtime-without-provenance`
- `external-provider-configured`
- `sharded-weight-pattern`
- `compressed-weight-candidate`
- `embedded-package-payload`
- `unknown-large-binary`
- `memory-active-no-artifact`

Special cases:

- `.pkl`
- `.joblib`
- some `.pt`

should be treated as intrinsically higher risk because they may carry
executable loading behavior or unsafe deserialization paths.

## External Providers and API Keys

Remote model providers are first-class AI-SBOM entities.

They must not be hidden just because no local weight file exists.

But credentials must be treated carefully.

The AI-SBOM should never store:

- raw secrets
- raw API keys
- full tokens

It may store:

- `provider_name`
- `credential_present`
- `credential_source`
- `execution_mode`
- `data_boundary`
- `models_referenced`

Recommended values:

- `credential_source: env | vault | secret-file | managed-secret | unknown`
- `execution_mode: local | remote | hybrid`
- `data_boundary: local-only | outbound-inference | hybrid`

This captures:

- "external AI acting as part of the internal system"

without leaking credentials.

## Discovery Heuristics

### Filesystem Heuristics

Use these as evidence builders, not as sole truth:

- known model extensions
- sidecar manifests
- size thresholds
- shard naming patterns
- compression / archive structure
- package_data payloads

Suggested suspicious patterns:

- single unknown binary > 100MB
- many sequential shards such as `model-00001-of-00032.bin`
- archive with many large binary entries and low compression benefit
- `tokenizer.json` without a nearby declared model

### Format / Header Heuristics

Where possible:

- inspect magic bytes
- inspect known format headers
- classify exact known formats separately from generic binaries

This is stronger than extension matching.

### Runtime Heuristics

Later phases may inspect:

- process maps
- file handles
- VRAM usage
- RAM spikes
- known local model runtimes

This is useful for:

- warm-loaded models
- models streamed in by runtimes
- services that obscure their disk layout

### Behavior / Provenance Heuristics

This is where TIBET becomes essential.

Relevant signals:

- tool actions without declared model provenance
- continuity events linked to unknown model identities
- twin drift versus expected model behavior
- chain-of-command gaps

These are not just "model detection" signals.
They are governance signals.

## TIBET Interpretation Layer

Heuristics alone are not enough.

A stronger architecture is:

- `tibet-ai-sbom` discovers
- TIBET determines legitimacy

That means the interesting state is not only:

- "is there a model?"

but also:

- "was it declared?"
- "is it signed?"
- "is it inside the approved manifest?"
- "does its behavior match an allowed continuity lane?"

So the policy handoff states should look like:

- `allowed`
- `watch`
- `suspect`
- `deny`

Examples:

- declared local model with matching artifact hash -> `allowed`
- external provider configured but not declared in policy -> `watch`
- runtime-active model with no declared artifact or provider -> `suspect`
- large unknown blob plus model-like runtime activity plus no provenance -> `deny`

## Proposed JSON Shape

`tibet-ai-sbom` should eventually export model truth in multiple lanes.

```json
{
  "models": {
    "declared_models": [],
    "local_model_artifacts": [],
    "runtime_model_signals": [],
    "external_model_providers": [],
    "suspicious_model_candidates": []
  }
}
```

Each item should support a common core:

```json
{
  "name": "qwen2.5-coder",
  "identifier": "ollama:qwen2.5-coder:7b",
  "version_or_tag": "7b",
  "source_kind": "declared-model",
  "evidence_grade": "declared",
  "locality": "local",
  "provider": "ollama",
  "artifact_path": "/models/qwen2.5-coder.gguf",
  "config_path": "/srv/app/ai-sbom.json",
  "hash": "sha256:...",
  "risk_flags": []
}
```

Example for an external provider:

```json
{
  "name": "gpt-5",
  "identifier": "openai:gpt-5",
  "version_or_tag": "gpt-5",
  "source_kind": "remote-inference-provider",
  "evidence_grade": "externally-configured",
  "locality": "remote",
  "provider": "openai",
  "credential_present": true,
  "credential_source": "env",
  "execution_mode": "remote",
  "data_boundary": "outbound-inference",
  "risk_flags": ["external-provider-configured"]
}
```

Example for a suspicious candidate:

```json
{
  "name": null,
  "identifier": "blob:/srv/app/assets/internal.bin",
  "source_kind": "undeclared-large-blob",
  "evidence_grade": "behaviorally-suspected",
  "locality": "local",
  "artifact_path": "/srv/app/assets/internal.bin",
  "size_bytes": 7340032000,
  "risk_flags": [
    "unknown-large-binary",
    "undeclared-large-blob"
  ]
}
```

## Implementation Phases

### Phase 1 - Broad Static Discovery

Add:

- known model extension scan
- sidecar scan
- shard pattern scan
- high-risk serialization detection
- external provider env/config detection

Goal:

- move `models` from `missing` to `partial`

### Phase 2 - Confidence and Risk Layer

Add:

- evidence grades
- risk flags
- lane-based model export
- explicit `declared vs present vs suspicious` distinction

Goal:

- make findings defensible and operator-readable

### Phase 3 - Runtime Signals

Add:

- local runtime inventories
- process/file-handle integration where practical
- VRAM / memory signal hooks where available

Goal:

- capture warm-loaded or runtime-managed model presence

### Phase 4 - TIBET Policy Handoff

Add:

- provenance-aware interpretation
- signed SBOM / manifest linkage
- policy status for model legitimacy

Goal:

- transition from discovery-only to governance-aware AI-SBOM

## Recommended Next Step

The next implementation step should **not** be deep memory forensics.

It should be:

- static broad model discovery
- external provider detection
- evidence grades
- risk flags

This yields the fastest product gain with the lowest platform friction.

Then the runtime and TIBET policy layers can be added on top of a clean
model evidence structure.
