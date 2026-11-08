# Android vulnerability learning harness

Project setup, model interface, deterministic ingestion, frozen scan plans, and a resumable static scanner with source-evidence validation. No live detection results or recall lift are claimed; provider credentials have not been configured.

## Quick start (offline fixture)

Requires Python 3.11+. From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
cp config.example.yaml config.yaml
cyber-scan validate-config --config config.yaml
cyber-scan ingest --config config.yaml
python -m unittest discover -s tests -v
```

The included sample is a tiny synthetic fixture, not InsecureShop. Config paths resolve relative to the YAML file. The command emits the output path and coverage report. Repeating ingestion with identical inputs and settings produces identical artifacts.

## Real APK workflow

Choose an explicit APK asset from https://github.com/hax0rgb/InsecureShop/releases and retain the release URL. Install JADX from https://github.com/skylot/jadx/releases following its Java requirements, then:

```bash
cyber-scan download --url 'https://github.com/OWNER/REPO/releases/download/TAG/APP.apk' --output data/app.apk
# Add --sha256 EXPECTED_HASH when an independently trusted hash is available.
cyber-scan decompile --apk data/app.apk --output data/app-run --jadx jadx
```

The URL above is a template, not a real asset. Set `input_dir: data/app-run/decompiled` in config.yaml and run ingestion. Existing download/decompile destinations are rejected. Download records the source URL, SHA-256, and size. Decompilation stores the APK hash, JADX version, exact command, exit code, and log outside the source directory. Nonzero exits/timeouts are treated as partial failures. Inspect the log before explicitly ingesting partial output; never describe it as complete.

Real APK validation: InsecureShop v1.0 was downloaded and processed with JADX 1.5.6. JADX returned 11 errors and a nonzero exit; the wrapper correctly rejected this as a complete run. We explicitly ingested the partial output for pipeline validation. See `docs/validation.md` for coverage and limitations.

## Ingestion artifacts

`runs/<content-and-settings-hash>/ingest/` contains:

- `metadata.json`: pipeline version and ingestion settings.
- `inventory.json`: paths, raw-content hashes for readable files within the size limit, sizes, line counts, file types, inclusion status and ownership hints.
- `manifest.json`: raw application/component attributes, permissions, SDK attributes, and intent filters. Missing `exported` is preserved as missing, not inferred to be false.
- `coverage.json`: loaded/bundled counts, unsupported/oversized files, parsing errors, omitted coverage and token estimates.
- `bundles.jsonl`: immutable experiment inputs with code, stable paths, line numbers, hashes, and omitted related files.

One bundle per primary file preserves class boundaries. It adds parseable manifests, class-name references, and XML resource references within budgets. Every supported file is a primary candidate; dependency code is not silently discarded. Package matching is only an ordering hint. Cross-file relationships are heuristic, not a call graph or taint analysis. Oversized files are reported as uncovered instead of truncated. No file-count cap hides coverage.

`utf8_bytes` is a conservative byte-based budget estimate, not actual model token usage. Optionally install `pip install -e '.[tokens]'` and configure `tiktoken:<encoding>`. This is only exact for that encoding; use a compatible tokenizer for your models. Budgets apply to bundle text only: reserve additional capacity for instructions, schemas, lessons, and output when implementing scans. Freeze bundles before baseline/lesson comparisons.

Native binaries, assets with unsupported formats, obfuscated relationships, reflection and runtime flows are not analyzed. All XML remains available as source; only the manifest is semantically extracted. The source directory must remain unchanged during ingestion. When the wrapper's `decompile.json` exists next to the input directory, ingestion carries it into metadata and emits a warning for partial output. Oversized/unreadable skipped files lack content hashes; the run ID identifies included inputs/settings, not a byte-perfect hash of the entire APK. Keep the decompilation provenance alongside outputs.

## Model interface

`ModelClient.generate(messages, response_schema=None)` returns normalized text, model ID, usage, finish reason, attempts and latency. The OpenAI-compatible adapter uses HTTPS, environment credentials, explicit timeout/retry limits and configurable output-token/structured-output parameters. Different providers/models may require different parameters; there is no silent fallback. Structured-output support is configurable, not assumed. Downstream code must validate JSON against the application schema and reject truncated responses.

Set real teacher/student IDs in config.yaml. Export credentials in your shell; .env.example is documentation and is not automatically loaded. Then explicitly run a paid/API call:

```bash
cyber-scan model-smoke --config config.yaml --role teacher --output runs/teacher-smoke.json
cyber-scan model-smoke --config config.yaml --role student --output runs/student-smoke.json
```

The smoke test sends only a request to reply OK, not app code. It saves a request/response record with model settings and usage; keys are never written. Cost in currency is not calculated because model pricing is not configured. No live provider requests were made during initial validation. Provider compatibility reference: https://console.groq.com/docs/openai.

## Full static scan

See [docs/scanning.md](docs/scanning.md) for preparation, provider configuration, resuming, and interpreting results.

```bash
# Use the actual ingestion path printed by the ingest command.
cyber-scan plan-scan --config config.yaml --ingest-dir runs/INGEST_RUN_ID/ingest --output runs/full-plan
cyber-scan scan --config config.yaml --plan runs/full-plan --output runs/teacher-full --role teacher
```

Plan creation is offline and scans every ingested text file as a primary, including dependencies. It retains existing whole-file bundles and splits over-budget files into overlapping windows, including long-line fragments when necessary. It does not hide the original ingestion exclusions or partial-decompilation warning. The frozen source plan is reused across teacher and student runs.

The scanner validates JSON and evidence spans, keeps raw responses and rejected findings, and collapses exact duplicates only. Source-consistent findings still require security review. Empty model output, failed requests and truncated responses are not counted as clean scans. The command exits with code 1 for incomplete scans, and 2 for configuration/preflight failures.

## Next milestones

1. Configure a teacher model/API key and execute the full plan; review real findings and noise.
2. Run the baseline student on the same plan; synthesize general lessons once; rescan the student.
3. Evaluate with an isolated ground-truth catalog, explicit matching and reviewed ambiguity.
4. Report recall gains/losses, unsupported findings, cost, and limitations; write the dynamic-analysis proposal.

Ground-truth labels must never enter scan/lesson prompts. Treat decompiled code/comments/resources as untrusted data, not agent instructions. Fine-tuning and external cybersecurity datasets remain optional independent experiments.

## Validation

36 tests use unittest and mocked HTTP/subprocesses. They cover reproducibility, related-file inclusion, manifest parsing, malformed XML, binary/symlink exclusions, token/size limits, configuration errors, request construction, retry/error behavior, and APK provenance. They do not establish vulnerability-detection quality.
