"""Compare lesson-assisted student inference on the completed baseline bundles."""
import argparse
import json
import math
import re
import time
from pathlib import Path

from cyber_scan.config import ModelConfig, load_config
from cyber_scan.ingest.pipeline import digest, token_counter, write_json
from cyber_scan.models import create_client
from cyber_scan.models.openai_compatible import ModelError, chat_payload
from cyber_scan.scan.plan import load_plan, primary_files
from cyber_scan.scan.prompts import SYSTEM_PROMPT, lesson_appendix, messages_for
from cyber_scan.scan.runner import ScanResponse, atomic_json, run_scan
from cyber_scan.schemas import LessonSet

SUCCESS = {'completed', 'completed_with_rejections'}
BASELINE_PLAN = '209b803ce99263c9d028860aa7cf4aabedc00aa8135af1ea0a3e65f6239c4eff'
BASELINE = Path('runs/student-baseline')
PLAN = Path('runs/student-plan/full-plan')
LESSONS = Path('runs/luna-teacher/lessons.json')
MATCHED_PLAN = Path('runs/matched-student-plan')
OUTPUT = Path('runs/student-lesson-assisted')


def preflight(config, plan_path, baseline_path, lessons_path, matched_path):
    plan, units = load_plan(plan_path)
    baseline = json.loads((baseline_path / 'run.json').read_text())
    model = config.models['student']
    schema = ScanResponse.model_json_schema()
    if plan['plan_id'] != BASELINE_PLAN or baseline['plan_id'] != BASELINE_PLAN:
        raise ValueError('Unexpected student baseline plan')
    if baseline['role'] != 'student' or ModelConfig.model_validate(baseline['model']) != model:
        raise ValueError('Student model configuration differs from the baseline')
    if baseline['prompt'] != SYSTEM_PROMPT or baseline['response_schema'] != schema:
        raise ValueError('Student prompt or response schema differs from the baseline')

    raw_lessons = lessons_path.read_bytes()
    lessons = LessonSet.model_validate_json(raw_lessons).lessons
    appendix = lesson_appendix(lessons)
    count = token_counter(plan['tokenizer'])
    reservations, selected, excluded = [], [], []
    for unit in units:
        record = json.loads((baseline_path / 'requests' / (unit['id'] + '.json')).read_text())
        messages = messages_for(unit)
        if record['unit_id'] != unit['id'] or record['messages'] != messages:
            raise ValueError('Baseline request differs from the frozen input')
        if record['status'] not in SUCCESS:
            excluded.append({'unit_id': unit['id'], 'primary': unit['primary'], 'status': record['status']})
            continue
        baseline_payload = chat_payload(model, messages, schema)
        framing = record['response']['usage']['prompt_tokens'] - sum(
            count(message['content']) for message in baseline_payload['messages']
        )
        messages[0]['content'] += '\n\n' + appendix
        payload = chat_payload(model, messages, schema)
        reserved = (sum(count(message['content']) for message in payload['messages'])
                    + max(framing, 0) + 15 + model.max_output_tokens)
        reservations.append(reserved)
        selected.append(unit)

    if len(selected) != 27 or len(lessons) != 14:
        raise ValueError('Expected 27 comparable baseline bundles and 14 teacher lessons')
    if max(reservations) > 8_000 or sum(reservations) > 196_000:
        raise ValueError(f'Student token allowance exceeded: {max(reservations)} per call, {sum(reservations)} total')
    raw_units = ''.join(json.dumps(unit, sort_keys=True) + '\n' for unit in selected).encode()
    matched_id = digest(raw_units)
    selected_files = {file for unit in selected for file in primary_files(unit)}
    metadata = {**plan, 'source_plan_id': plan['plan_id'], 'plan_id': matched_id,
                'units_sha256': matched_id, 'unit_count': len(selected),
                'primary_files_in_plan': len(selected_files),
                'total_bundle_tokens_or_estimate': sum(unit['tokens_or_estimate'] for unit in selected),
                'max_bundle_tokens_or_estimate': max(unit['tokens_or_estimate'] for unit in selected),
                'limitations': [*plan['limitations'], 'Two baseline bundles without usable responses were excluded.']}
    if matched_path.exists():
        if load_plan(matched_path) != (metadata, selected):
            raise ValueError('Restored comparison plan differs from the original')
    else:
        matched_path.mkdir(parents=True)
        (matched_path / 'units.jsonl').write_bytes(raw_units)
        write_json(matched_path / 'plan.json', metadata)
    comparison = {
        'baseline_plan_id': plan['plan_id'], 'comparison_plan_id': matched_id,
        'lessons_sha256': digest(raw_lessons), 'lesson_count': len(lessons),
        'lesson_fields': ['pattern', 'reporting_threshold'],
        'planned_bundles': len(selected), 'excluded_baseline_bundles': excluded,
        'max_reserved_tokens_per_request': max(reservations),
        'total_reserved_tokens': sum(reservations),
    }
    return appendix, comparison


class StudentQuotaClient:
    def __init__(self, client):
        self.client = client
        self.wait_budget = 900

    def generate(self, messages, response_schema):
        while True:
            try:
                return self.client.generate(messages, response_schema=response_schema)
            except ModelError as exc:
                match = re.fullmatch(
                    r'Provider returned HTTP 429 \(rate_limit_(?:tokens|requests)_per_(?:day|minute)\) '
                    r'\[retry-after ([0-9]+(?:\.[0-9]+)?)s\]', str(exc))
                if not match:
                    raise
                delay = math.ceil(float(match[1])) + 2
                if delay > min(300, self.wait_budget):
                    raise
                self.wait_budget -= delay
                print(f'Groq quota reached. Waiting {delay} seconds before retrying the rejected request.', flush=True)
                time.sleep(delay)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--resume', action='store_true')
    args = parser.parse_args()
    config = load_config(Path('config.student.yaml'))
    appendix, comparison = preflight(config, PLAN, BASELINE, LESSONS, MATCHED_PLAN)
    print(json.dumps(comparison), flush=True)
    if args.resume:
        records = [json.loads(path.read_text()) for path in (OUTPUT / 'requests').glob('*.json')]
        for record in records:
            if record['status'] == 'provider_error' and record.get('error', '').startswith('Provider returned HTTP 429'):
                # Retry a rejected rate-limited request while preserving all paid responses.
                path = OUTPUT / 'requests' / (record['unit_id'] + '.json')
                history = OUTPUT / 'history' / record['unit_id']
                history.mkdir(parents=True, exist_ok=True)
                path.rename(history / f'quota-{len(list(history.glob("*.json")))}.json')
    client = StudentQuotaClient(create_client(config.models['student']))
    result = run_scan(config, MATCHED_PLAN, OUTPUT, role='student', resume=args.resume, delay_seconds=60, client=client,
                      system_appendix=appendix, progress=lambda event: print(json.dumps(event), flush=True))
    atomic_json(OUTPUT / 'comparison.json', comparison)
    print(json.dumps({k: result[k] for k in ('status', 'completed_units', 'planned_units',
                                            'accepted_unique_findings', 'rejected_findings', 'usage')}))
    raise SystemExit(0 if result['status'] == 'completed' else 1)
