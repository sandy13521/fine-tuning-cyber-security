# Student lesson prompts and LoRA distillation

Use the same frozen APK plan and base student checkpoint in all three arms. The existing hosted lesson-assisted workflow still uses its saved checkpoint and token limits. The CLI can also apply the lesson prompt to a local checkpoint.

| Arm | Scan options | Teacher contribution |
| --- | --- | --- |
| Baseline | No lesson or adapter flag | None |
| Lesson prompt | `--lessons PATH` | The lesson patterns and reporting thresholds are appended at inference |
| Distilled | `--adapter PATH` | Reviewed teacher responses supervised the trained adapter |

## Export supervised examples

Extract the saved [Luna run artifact](https://github.com/sandy13521/fine-tuning-cyber-security/actions/runs/42643352316) under `runs/luna`. It contains both the frozen plan and the teacher response records.

Review the responses before training. A review file maps unit IDs to zero-based indices in each request record's `accepted` array. Include a unit only after checking the labels against the source. An explicit empty list means you reviewed that bundle as a negative example. Omit ambiguous units.

```bash
cyber-scan distill-data \
  --plan runs/luna/qwen-plan/full-plan \
  --teacher-run runs/luna/luna-teacher \
  --review runs/review.json \
  --output runs/teacher-dataset
```

The exporter checks that the records match the frozen plan and revalidates the teacher's evidence. Each example pairs the scan prompt and source with JSON findings. It excludes rejected candidates. To preview the Luna data before review, replace `--review runs/review.json` with `--allow-unreviewed`. That exports 16 provisional positive examples with 39 source-consistent candidate labels from this artifact. Training on these provisional examples requires the same explicit opt-in. Empty unreviewed teacher responses are excluded.

## Train a local adapter

Use a local Transformers instruction checkpoint directory with safetensors weights, tokenizer, and chat template. The GGUF used for the llama.cpp pilot has a different format. The CLI loads local files only.

```bash
python -m pip install -e '.[distill]'
cyber-scan distill-train \
  --base-model runs/models/student \
  --dataset runs/teacher-dataset \
  --output runs/student-adapter \
  --epochs 1 --max-length 8192
```

For 4-bit QLoRA training, install `.[qlora]` and add `--qlora` on a CUDA machine. The trainer masks the input tokens out of the loss and trains on the assistant's JSON completion. It rejects overlong examples so they can be rebundled. Repeat `--dataset` to combine reviewed exports. The adapter directory contains the weights and fingerprints for the base checkpoint, dataset, and adapter files. Keep datasets, checkpoints, and raw scan outputs under `runs/`.

## Run the matched comparison

Set `plan` to the frozen test plan and use a separate output directory for each arm.

```bash
plan=runs/test-apk/full-plan
base=runs/models/student
lessons=runs/luna/luna-teacher/lessons.json

cyber-scan scan --role student --config config.student.yaml \
  --local-model "$base" --plan "$plan" --output runs/test-baseline

cyber-scan scan --role student --config config.student.yaml \
  --local-model "$base" --plan "$plan" --output runs/test-lessons --lessons "$lessons"

cyber-scan scan --role student --config config.student.yaml \
  --local-model "$base" --plan "$plan" --output runs/test-distilled --adapter runs/student-adapter
```

The three local scans use the same JSON schema and source-evidence validator. Local generation requests JSON in the prompt, so malformed or truncated responses can still fail. For a hosted baseline or lesson run, omit `--local-model` and use the provider credential from the student config. Adapter inference runs locally.

Use an APK outside the training set for a generalization test. The adapter scan records the training plan IDs and available APK hashes in `run.json`. A rerun on InsecureShop after training on the Luna artifact is an in-sample check. Compare published issue matches, false positives, citation validity, and usable coverage on matched bundles. Source consistency alone does not establish exploitability.
