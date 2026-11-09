# Running the full static scan

## Prepare

Install the package and ingest the decompiled app as described in the README. Input paths in YAML are relative to that file. CLI paths are relative to your current working directory.

```bash
cyber-scan plan-scan --config config.yaml --ingest-dir runs/INGEST_RUN_ID/ingest --output runs/full-plan
```

Replace INGEST_RUN_ID with the directory from your ingest command. This offline command verifies source hashes against the inventory, freezes source snippets and request units, and writes `plan.json` and `units.jsonl`. It rejects changed source rather than silently changing an experiment. Existing plan directories are rejected. Use the identical plan directory for teacher/baseline/lesson comparisons.

The whole-file bundles retain their original manifest/helper context. Oversized files are split with up to ten overlapping lines; lines too large for a window are fragmented and labeled. All supported ingested primary files are represented, including dependencies and generated code. This addresses size-based ingestion gaps, but a window can miss validation or data flow elsewhere. Unsupported files and partial decompiler output remain explicit limitations.

## Configure and execute

Set a real teacher model ID and its supported parameters under `models.teacher` in your ignored `config.yaml`. The existing example is for an HTTPS OpenAI-compatible endpoint. Select the correct `token_parameter` (`max_tokens` or `max_completion_tokens`), `response_format` (`prompt`, `json_object`, or `json_schema`), output budget, and optionally temperature. A 4,096-token output budget is the new default; raise it if responses are truncated. Bundle estimates do not include instructions, schema, output capacity, or model reasoning tokens. Verify your model's context limit.

Set the key through the execution environment using the name in `api_key_env`, e.g. `TEACHER_API_KEY`. The program reads environment variables; it does not read .env automatically. Do not commit credentials. A ChatGPT account/GitHub connection alone does not provide a provider API credential to this process.

```bash
cyber-scan model-smoke --config config.yaml --role teacher --output runs/teacher-smoke.json
cyber-scan scan --config config.yaml --plan runs/full-plan --output runs/teacher-full --role teacher
```

No request cap is applied by default. Processing is sequential; optional `--delay-seconds 1` reduces sustained rate. The provider adapter applies bounded retries to transient failures. A persistent provider failure stops the run, preserving pending units instead of making thousands of doomed requests.

For an explicit pilot, append `--max-requests 3`; this reports an incomplete run. Resume without the cap to process remaining units:

```bash
cyber-scan scan --config config.yaml --plan runs/full-plan --output runs/teacher-full --role teacher --resume --retry-failed
```

Resume refuses a different plan, model configuration, prompt, or response schema. To change settings, use a new run directory. Completed unit records are reused. `--retry-failed` archives failed/invalid attempts before retrying; otherwise they remain failed. If a process is killed, verify it has stopped before manually removing its `.running` directory lock. A crash while a request is in flight can require a repeated API call; provider-side exactly-once billing is not guaranteed.

## Interpret outputs

- `run.json`: model config (environment variable name only), plan hash, prompt and response schema.
- `requests/<unit-id>.json`: supplied prompt/source and raw model response, usage, status, accepted/rejected findings and notes.
- `summary.json`: completion, failed and pending units, primary file coverage, usage, original ingestion exclusions/warnings, and limitations.
- `findings.json`: findings whose snippets match the cited file and lines in the exact source supplied to that request.
- `rejected.json`: schema-invalid findings or evidence outside the supplied file/range. These may include real bugs with incorrect citations and need review.
- `duplicates.json`: exact repeated findings; semantic duplicates remain separate for review.
- `history/`: prior failed/invalid attempts. Their saved-response usage is reported separately as `prior_attempt_usage`.

Only normal `stop` responses containing the expected JSON object count as processed. Truncated/malformed/refused outputs remain failed; their raw responses are retained. Valid sibling findings survive an invalid individual finding. `completed_with_rejections` means a response was processed with some findings rejected, not a fully clean result. No JSON repair model silently changes answers. Ground truth is never loaded by the scanner.

Evidence validation confirms that the cited source exists in the supplied bundle; it does not validate reachability, exploitability, severity, or semantic correctness. Deduplication is intentionally conservative. Finding counts are not recall or precision. All measurements must account for incomplete decompilation and unsupported source formats.

## InsecureShop preparation on November 8, 2026

Prepared (not executed):

| Item | Count |
|---|---:|
| Ingested text files | 2,777 |
| Original whole-file bundles | 2,467 |
| Oversized files split | 310 |
| Additional window units | 1,469 |
| Total planned model requests | 3,936 |
| Unsupported inventory entries | 667 |
| Source-text bytes across requests | 36,703,622 |

Plan ID: `55665bdfa8fa048477eafbb7411cec6698d05808a5023c4eda67d04846b8bf91`.

The byte count is not a tokenizer-derived token count or currency estimate. Repeated context, prompts, schemas and outputs add cost. No supported text files were skipped due to the size threshold in this ingestion; all 667 original exclusions were unsupported extensions. JADX's 11 errors remain a partial-decompilation warning. Real models and API credentials were absent, so preflight stopped before the first request. No security findings were produced or claimed.

Validation: 36 offline tests passed, including source integrity, long-line/window coverage, schema/evidence checks, truncated responses, resumability, retry history and credential preflight. Tests use fake model responses and do not measure vulnerability detection quality.

## GitHub Actions cloud run

The **OpenAI teacher scan** workflow uses the repository Actions secret `TEACHER_API_KEY`.
`config.cloud.yaml` selects `gpt-4.1`, strict structured output, and a 16,384-token completion budget. No temperature override is sent. The first scan request verifies account model access and billing. Model documentation: https://developers.openai.com/api/docs/models/gpt-4.1.

The workflow starts when its YAML file is pushed to main (including initial setup), or manually under **Actions → OpenAI teacher scan → Run workflow**. It downloads the pinned public InsecureShop v1.0 APK, verifies its known SHA-256, runs JADX 1.5.6, preserves any partial-decompilation warning, freezes all supported text, and partitions requests into eight disjoint jobs. Partial JADX output is allowed only when a nonzero exit is recorded and extracted source exists; a timeout or missing output fails setup.

The first run starts the full teacher scan automatically. It incurs API charges for actual usage. Each shard checkpoints each completed response. The command timeout allows artifact-upload time before the job timeout. Persistent provider errors stop the affected shard, and report aggregation marks missing/failed requests incomplete. Findings remain unconfirmed pending review.

Artifacts are retained for 14 days:

- `teacher-plan`: complete frozen plan and eight shard plans.
- `teacher-setup`: JADX status and logs.
- `teacher-results-0` through `teacher-results-7`: request/response records, checkpoints, and per-shard summaries.
- `teacher-combined-report`: combined summary, source-consistent findings, rejections and duplicate details.

To resume an interrupted run, manually run the workflow with its previous Actions **run ID** in `resume_run_id`. Keep the same model config, scanner version and prompt. The workflow restores the original frozen plan and each shard's checkpoints; completed requests are not repeated. Failed attempts are archived and retried. If a shard never produced an artifact, a full automatic restore cannot succeed; download the available records and recover deliberately. Artifacts must still exist within retention. Manually cancelled workflows may be unable to finish artifact uploads.

Repository secret values are never read back into the chat.

The current cloud workflow groups the frozen primary source spans into **50 model requests**. It keeps all ingested text and original line references, shares the manifest across groups, and estimates sizes with the `o200k_base` tokenizer. Eight checkpoint shards run one at a time. Setup makes no model requests. Transient HTTP errors can trigger additional attempts for the same group. A grouped run has a new plan identity and cannot reuse responses from the prior one-file-per-request plan.
