"""Freeze a focused Android review plan sized for Groq's free-tier limits."""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import re

from cloud_teacher import freeze_source, prepare_apk
from cyber_scan.config import load_config
from cyber_scan.ingest.pipeline import token_counter, write_json
from cyber_scan.models.openai_compatible import chat_payload
from cyber_scan.scan.plan import group_plan, load_plan, segment
from cyber_scan.scan.prompts import messages_for
from cyber_scan.scan.runner import ScanResponse

PLAN_DIR = Path('runs/qwen-plan')
REQUESTS = 17
INPUT_LIMIT = 7_700
DAILY_LIMIT = 190_000
REVIEW_FOCUS = """Trace inputs across Android entry points, method calls, and data sinks.
Review each meaningful branch independently, including where a check is incomplete.
Cover credential handling, IPC, URI and file access, WebView and network behavior, and
configuration when present. Cite the exact statement that creates the flaw, such as the
sink or the ineffective check. Prefer short single-line snippets copied from the given
line, with no line-number prefix. Keep explanations concise. Include distinct issues in
different branches even when they share a sink. Avoid repeating manifest-only observations
when stronger code evidence is available."""


def arrange_source(spans):
    """Keep referenced classes near one another and omit Kotlin compiler annotations."""
    by_file = defaultdict(list)
    for span in spans:
        path = span['file']
        lines = span['text'].split('\n')
        start = 0
        for index, line in enumerate(lines):
            if path.endswith('.java') and line.startswith('@Metadata(') and not span['partial_line']:
                if index > start:
                    by_file[path].append(segment(path, '\n'.join(lines[start:index]), span['start_line'] + start))
                start = index + 1
        if start < len(lines):
            by_file[path].append(segment(path, '\n'.join(lines[start:]), span['start_line'] + start, span['partial_line']))
        if not by_file[path]:
            by_file[path].append(span)

    symbols = defaultdict(list)
    references = {}
    for path, fragments in by_file.items():
        if path.endswith(('.java', '.kt')):
            symbols[Path(path).stem].append(path)
            references[path] = set(re.findall(r'\b[A-Za-z_$][\w$]*\b',
                                              '\n'.join(span['text'] for span in fragments)))
    remaining = dict(by_file)
    arranged = []
    while remaining:
        path = next(iter(remaining))
        arranged.extend(remaining.pop(path))
        related = {candidate for name in references.get(path, ()) for candidate in symbols.get(name, ())
                   if candidate in remaining}
        for candidate in sorted(related):
            arranged.extend(remaining.pop(candidate))
    return arranged


def freeze_teacher(config, destination):
    source = freeze_source(config, destination)
    target = destination / 'full-plan'
    group_plan(source, target, REQUESTS, config.tokenizer, 4_450,
               arrange_spans=arrange_source, review_focus=REVIEW_FOCUS)
    plan, units = load_plan(target)
    plan['limitations'].append('Kotlin compiler metadata annotations were omitted; original code line numbers were preserved.')
    write_json(target / 'plan.json', plan)
    counters = [token_counter(config.tokenizer), token_counter('tiktoken:cl100k_base')]
    model = config.models['teacher']
    schema = ScanResponse.model_json_schema()
    reserves = []
    for unit in units:
        payload = chat_payload(model, messages_for(unit), schema)
        strings = [message['content'] for message in payload['messages']]
        strings.append(json.dumps(payload['response_format'], separators=(',', ':')))
        reserves.append(max(sum(count(value) for value in strings) for count in counters)
                        + model.max_output_tokens + 350)
    if max(reserves) > INPUT_LIMIT or sum(reserves) > DAILY_LIMIT:
        raise ValueError(f'Estimated Qwen budget exceeded: max {max(reserves)}, total {sum(reserves)}')
    budget = {
        'model': model.model,
        'plan_id': plan['plan_id'],
        'planned_requests': len(units),
        'planned_primary_files': plan['primary_files_in_plan'],
        'max_reserved_tokens_per_request': max(reserves),
        'total_reserved_tokens': sum(reserves),
        'scope': 'Focused source with generated binding/UI resources and Kotlin compiler annotations omitted.',
    }
    write_json(destination / 'budget.json', budget)
    print(json.dumps(budget, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--jadx', default='jadx')
    args = parser.parse_args()
    config = load_config(Path('config.qwen-teacher.yaml'))
    prepare_apk(config, args.jadx)
    freeze_teacher(config, PLAN_DIR)
