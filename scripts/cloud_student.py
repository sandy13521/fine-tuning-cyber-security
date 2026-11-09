"""Freeze a student evaluation plan within Groq's published free-tier token limits."""
import argparse
import json
from pathlib import Path

from cloud_teacher import freeze_source, prepare_apk
from cyber_scan.config import load_config
from cyber_scan.ingest.pipeline import token_counter, write_json
from cyber_scan.models.openai_compatible import chat_payload
from cyber_scan.scan.plan import group_plan, load_plan
from cyber_scan.scan.prompts import messages_for
from cyber_scan.scan.runner import ScanResponse

REQUESTS = 29
PER_REQUEST_ALLOWANCE = 7_750
PER_RUN_ALLOWANCE = 196_000
PLAN_DIR = Path('runs/student-plan')


def freeze_student(config, destination):
    source = freeze_source(config, destination)
    plan_dir = destination / 'full-plan'
    group_plan(source, plan_dir, REQUESTS, config.tokenizer, 4_600)
    plan, units = load_plan(plan_dir)
    count = token_counter(config.tokenizer)
    model = config.models['student']
    schema = ScanResponse.model_json_schema()
    reservations = []
    for unit in units:
        payload = chat_payload(model, messages_for(unit), schema)
        # Reserve output tokens and a margin for message framing/provider instructions.
        reservations.append(sum(count(message['content']) for message in payload['messages'])
                            + model.max_output_tokens + 256)
    if max(reservations) > PER_REQUEST_ALLOWANCE or sum(reservations) > PER_RUN_ALLOWANCE:
        raise ValueError('Frozen baseline exceeds the student token allowance')
    budget = {
        'model': model.model,
        'plan_id': plan['plan_id'],
        'planned_requests': len(units),
        'planned_primary_files': plan['primary_files_in_plan'],
        'ingested_text_files': plan['loaded_files'],
        'max_reserved_tokens_per_request': max(reservations),
        'total_reserved_tokens': sum(reservations),
    }
    write_json(destination / 'budget.json', budget)
    print(json.dumps(budget, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--jadx', default='jadx')
    args = parser.parse_args()
    config = load_config(Path('config.student.yaml'))
    prepare_apk(config, args.jadx)
    freeze_student(config, PLAN_DIR)
