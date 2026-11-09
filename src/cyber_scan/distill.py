"""Export source-checked teacher responses as supervised student examples."""

import json
from pathlib import Path

from .ingest.pipeline import digest
from .scan.plan import load_plan
from .scan.prompts import messages_for
from .scan.runner import ScanResponse, atomic_json, review_response
from .schemas import ModelResponse


def prepare_distill(plan_path, teacher_run, output, review_path=None, *, allow_unreviewed=False):
    if output.exists():
        raise ValueError('Dataset output already exists')
    if (review_path is None and not allow_unreviewed) or (review_path is not None and allow_unreviewed):
        raise ValueError('Choose a review file or explicitly allow provisional teacher labels')

    plan, units = load_plan(plan_path)
    identity = json.loads((teacher_run / 'run.json').read_text(encoding='utf-8'))
    if identity.get('role') != 'teacher' or identity.get('plan_id') != plan['plan_id']:
        raise ValueError('Teacher run does not match the frozen plan')

    review = None
    if review_path is not None:
        review = json.loads(review_path.read_text(encoding='utf-8'))
        if not isinstance(review, dict) or not review.keys() <= {unit['id'] for unit in units}:
            raise ValueError('Review must map known unit IDs to lists of accepted finding indices')

    rows = []
    for unit in units:
        unit_id = unit['id']
        if review is not None and unit_id not in review:
            continue
        request = teacher_run / 'requests' / f'{unit_id}.json'
        if not request.is_file():
            if review is not None:
                raise ValueError(f'Review references an unavailable response: {unit_id}')
            continue
        record = json.loads(request.read_text(encoding='utf-8'))
        messages = messages_for(unit)
        if record['unit_id'] != unit_id or record['messages'] != messages:
            raise ValueError(f'Teacher response does not match the frozen request: {unit_id}')
        if record['status'] not in {'completed', 'completed_with_rejections'}:
            if review is not None:
                raise ValueError(f'Review references an unusable response: {unit_id}')
            continue

        response = ModelResponse.model_validate(record['response'])
        checked = review_response(response, unit)
        if checked['status'] != record['status'] or checked['accepted'] != record['accepted']:
            raise ValueError(f'Teacher findings failed source revalidation: {unit_id}')
        findings = checked['accepted']
        if review is not None:
            indices = review[unit_id]
            if (not isinstance(indices, list)
                    or any(type(index) is not int or not 0 <= index < len(findings) for index in indices)
                    or len(indices) != len(set(indices))):
                raise ValueError(f'Invalid accepted finding indices: {unit_id}')
            findings = [findings[index] for index in indices]
        elif not findings:
            # A model returning no findings is not a reviewed clean example.
            continue

        rows.append({
            'unit_id': unit_id,
            'messages': messages,
            'completion': ScanResponse(findings=findings).model_dump(mode='json'),
        })

    if not rows:
        raise ValueError('No usable distillation examples')
    raw = ''.join(json.dumps(row, ensure_ascii=False, sort_keys=True) + '\n' for row in rows).encode()
    negatives = sum(not row['completion']['findings'] for row in rows)
    manifest = {
        'version': 1,
        'plan_id': plan['plan_id'],
        'apk_sha256': (plan.get('decompilation') or {}).get('apk_sha256'),
        'teacher_model': identity['model']['model'],
        'reviewed': review is not None,
        'examples': len(rows),
        'positive_examples': len(rows) - negatives,
        'negative_examples': negatives,
        'findings': sum(len(row['completion']['findings']) for row in rows),
        'examples_sha256': digest(raw),
    }
    output.mkdir(parents=True)
    (output / 'examples.jsonl').write_bytes(raw)
    atomic_json(output / 'dataset.json', manifest)
    return manifest


def load_distill_dataset(path: Path, *, allow_unreviewed=False):
    manifest = json.loads((path / 'dataset.json').read_text(encoding='utf-8'))
    raw = (path / 'examples.jsonl').read_bytes()
    if manifest.get('version') != 1 or manifest.get('examples_sha256') != digest(raw):
        raise ValueError(f'Distillation dataset failed integrity verification: {path}')
    if manifest.get('reviewed') is not True and not allow_unreviewed:
        raise ValueError('Provisional teacher labels need review or --allow-unreviewed for an experiment')
    rows = [json.loads(line) for line in raw.splitlines()]
    if not rows or len(rows) != manifest['examples']:
        raise ValueError(f'Distillation dataset has an invalid example count: {path}')
    return manifest, rows
