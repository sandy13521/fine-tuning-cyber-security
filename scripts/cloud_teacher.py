"""Cloud orchestration for the public InsecureShop fixture; no secret values on disk."""
import argparse
import json
import re
from pathlib import Path
import sys

from cyber_scan.config import load_config
from cyber_scan.ingest.apk import download_apk, decompile
from cyber_scan.ingest.pipeline import ANDROID, ingest, digest, write_json
from cyber_scan.models.openai_compatible import chat_payload
from cyber_scan.scan.plan import build_plan, group_plan, load_plan, primary_files, read_source
from cyber_scan.scan.prompts import messages_for
from cyber_scan.scan.runner import ScanResponse, run_scan, summarize

SHARDS = 8
REQUESTS = SHARDS
MAX_SOURCE_BYTES = 48_000
# Flex rates per million tokens, in microdollars per token.
INPUT_RATE = 0.05
OUTPUT_RATE = 0.25
BUDGET_USD = 0.05
RESOURCE_REF = re.compile(r'(?:@|R\.)(xml|raw|layout|menu|navigation)[/.]([A-Za-z0-9_]+)')
RESOURCE_FILE = re.compile(r'resources/res/(xml|raw|layout|menu|navigation)(?:-[^/]+)?/([^/]+)')
APK_URL = 'https://github.com/hax0rgb/InsecureShop/releases/download/v1.0/InsecureShop.apk'
APK_SHA = 'a83298ae4a37fcab8101e8b41e513dd2199af71a94ea537d556a318e07d4d1bd'


def partition(plan_path, destination, shards=SHARDS):
    parent, units = load_plan(plan_path)
    for index in range(shards):
        selected = units[index::shards]
        if not selected:
            continue
        folder = destination / str(index)
        folder.mkdir(parents=True)
        raw = ''.join(json.dumps(unit, sort_keys=True) + '\n' for unit in selected)
        checksum = digest(raw.encode())
        metadata = {**parent, 'parent_plan_id': parent['plan_id'], 'plan_id': checksum,
                    'units_sha256': checksum, 'unit_count': len(selected),
                    'primary_files_in_plan': len({file for unit in selected for file in primary_files(unit)}),
                    'total_bundle_tokens_or_estimate': sum(unit['tokens_or_estimate'] for unit in selected),
                    'shard_index': index, 'shard_count': shards}
        (folder / 'units.jsonl').write_text(raw, encoding='utf-8')
        write_json(folder / 'plan.json', metadata)
    return parent


def select_files(config, inventory, manifests):
    """Keep app code, declared Android components, and relevant text resources."""
    if not any(manifest['package'] for manifest in manifests):
        raise ValueError('Focused scan requires a parseable Android manifest with a package')
    classes = set()
    for manifest in manifests:
        package = manifest['package']
        entries = [manifest['application'], *(entry['attributes'] for entry in manifest['components'])]
        for entry in entries:
            for key in ('name', 'targetActivity'):
                name = entry.get(ANDROID + key)
                if not name or not package:
                    continue
                if name.startswith('.'):
                    name = package + name
                elif '.' not in name:
                    name = package + '.' + name
                classes.add(name.split('$', 1)[0].replace('.', '/'))

    items = {item['path']: item for item in inventory if item['status'] == 'loaded'}
    selected = {manifest['path'] for manifest in manifests}
    by_resource = {}
    app_sources = set()
    for path, item in items.items():
        source = Path(path)
        if source.suffix in {'.java', '.kt', '.smali'}:
            if item.get('ownership_hint') == 'application' and not (
                source.stem == 'R' or source.stem.startswith('R$')
            ):
                app_sources.add(path)
            if path.removeprefix('sources/').rsplit('.', 1)[0] in classes:
                selected.add(path)
        resource = RESOURCE_FILE.fullmatch(path)
        if resource:
            by_resource.setdefault((resource[1], source.stem), set()).add(path)
            if resource[1] in {'xml', 'raw'}:
                selected.add(path)
        if path.startswith('resources/assets/') or path == 'resources/res/values/strings.xml':
            selected.add(path)
    if not app_sources:
        raise ValueError('No app-owned source identified for focused teacher scan')
    selected.update(app_sources)
    pending = list(selected)
    while pending:
        path = pending.pop()
        for ref in RESOURCE_REF.findall(read_source(config.input_dir, items[path])):
            new = by_resource.get(ref, set()) - selected
            selected.update(new)
            pending.extend(new)
    return selected


def freeze_source(config, destination):
    ingested, _ = ingest(config)
    inventory = json.loads((ingested / 'inventory.json').read_text())
    manifests = json.loads((ingested / 'manifest.json').read_text())
    selected = select_files(config, inventory, manifests)
    build_plan(config, ingested, destination / 'source-plan', selected_paths=selected)
    write_json(destination / 'teacher-inventory.json', [
        {**item, 'teacher_primary': item['path'] in selected} for item in inventory
    ])

    return destination / 'source-plan'


def freeze(config, destination):
    source = freeze_source(config, destination)
    group_plan(source, destination / 'full-plan', REQUESTS, 'utf8_bytes', MAX_SOURCE_BYTES)
    partition(destination / 'full-plan', destination / 'shards')


def check_budget(config, plan, units):
    model = config.models['teacher']
    if (model.model, model.base_url, model.service_tier, model.retries, model.token_parameter) != (
        'gpt-6-luna', 'https://api.openai.com/v1', 'flex', 0, 'max_completion_tokens'
    ):
        raise ValueError('Cloud budget requires GPT-6 Luna Flex with automatic retries disabled')
    if plan['scope'] != 'selected_ingested_files' or len(units) != REQUESTS:
        raise ValueError('Cloud budget requires the focused eight-request plan')
    schema = ScanResponse.model_json_schema()
    # Count serialized UTF-8 bytes as a conservative proxy for input tokens.
    # Include the complete wire payload and allowance for provider prompt overhead.
    inputs = [len(json.dumps(chat_payload(model, messages_for(unit), schema),
                             ensure_ascii=False).encode('utf-8')) + 1024 for unit in units]
    if max(inputs) > 64_000:
        raise ValueError('A request exceeds the 64,000-byte input allowance')
    output = len(units) * model.max_output_tokens
    estimate = (sum(inputs) * INPUT_RATE + output * OUTPUT_RATE) / 1_000_000
    if estimate > BUDGET_USD:
        raise ValueError(f'Estimated maximum ${estimate:.4f} exceeds the ${BUDGET_USD:.2f} plan budget')
    return {
        'model': model.model, 'service_tier': model.service_tier,
        'planned_requests': len(units), 'ingested_text_files': plan['loaded_files'],
        'planned_primary_files': plan['primary_files_in_plan'],
        'out_of_scope_files': plan['out_of_scope_files'],
        'estimated_input_token_ceiling': sum(inputs), 'max_output_tokens': output,
        'estimated_max_cost_usd': round(estimate, 6), 'budget_usd': BUDGET_USD,
    }


def preflight(config, destination):
    plan, units = load_plan(destination / 'full-plan')
    budget = check_budget(config, plan, units)
    for index in range(SHARDS):
        shard, assigned = load_plan(destination / 'shards' / str(index))
        if shard['parent_plan_id'] != plan['plan_id'] or assigned != units[index::SHARDS]:
            raise ValueError('Shard does not match the budgeted full plan')
    write_json(destination / 'full-plan/cost.json', budget)
    print(json.dumps(budget, indent=2))


def prepare_apk(config, jadx):
    apk = Path('data/app.apk')
    download_apk(APK_URL, apk, APK_SHA)
    try:
        decompile(apk, Path('data/cloud'), jadx=jadx)
    except ValueError:
        metadata_path = Path('data/cloud/decompile.json')
        if not metadata_path.exists():
            raise
        metadata = json.loads(metadata_path.read_text())
        if metadata['status'] != 'partial_or_failed' or not config.input_dir.is_dir():
            raise
        print('JADX returned partial output; proceeding with the explicit partial-decompilation warning.', flush=True)


def prepare(jadx):
    config = load_config(Path('config.cloud.yaml'))
    prepare_apk(config, jadx)
    freeze(config, Path('runs'))


def scan(index):
    config = load_config(Path('config.cloud.yaml'))
    preflight(config, Path('cloud-plan'))
    output = Path('cloud-results') / str(index)
    report = run_scan(config, Path('cloud-plan/shards') / str(index), output,
                      resume=(output / 'run.json').exists(), retry_failed=True, delay_seconds=10,
                      progress=lambda item: print(json.dumps(item), flush=True))
    print(json.dumps({key: report[key] for key in ('status', 'completed_units', 'planned_units', 'accepted_unique_findings')}, indent=2))
    return 0 if report['status'] == 'completed' else 1


def aggregate():
    # Requests are the durable source of truth, even if a runner timed out before summary.
    plan, units = load_plan(Path('cloud-plan/full-plan'))
    records = {}
    for path in Path('collected').rglob('requests/*.json'):
        record = json.loads(path.read_text())
        if record['unit_id'] in records:
            raise ValueError('Duplicate request records across shard artifacts')
        records[record['unit_id']] = record
    expected = {unit['id'] for unit in units}
    if set(records) - expected:
        raise ValueError('Collected records do not belong to the frozen plan')
    output = Path('combined')
    (output / 'requests').mkdir(parents=True)
    for unit_id, record in records.items():
        write_json(output / 'requests' / (unit_id + '.json'), record)
    report = summarize(plan, units, output)
    if 'out_of_scope_files' in plan:
        report.update(scope=plan['scope'], ingested_text_files=plan['loaded_files'],
                      out_of_scope_files=plan['out_of_scope_files'])
        report['budget'] = json.loads(Path('cloud-plan/full-plan/cost.json').read_text())
    # Include saved previous-attempt usage separately.
    previous_usage = {}
    for path in Path('collected').rglob('history/*/*.json'):
        for name, amount in json.loads(path.read_text()).get('response', {}).get('usage', {}).items():
            if isinstance(amount, (int, float)) and not isinstance(amount, bool):
                previous_usage[name] = previous_usage.get(name, 0) + amount
    report['prior_attempt_usage'] = previous_usage
    write_json(output / 'summary.json', report)
    Path('combined/STATUS.md').write_text(
        f"# Teacher scan: {report['status']}\n\n"
        f"Completed {report['completed_units']} / {report['planned_units']} requests.\n\n"
        f"Reviewed {report['fully_processed_primary_files']} / {report['planned_primary_files']} "
        f"selected primary files; {report.get('out_of_scope_files', 0)} ingested files outside scope.\n\n"
        f"Source-consistent unique findings: {report['accepted_unique_findings']}. "
        "These require security review and are not confirmed vulnerabilities or measured recall.\n\n"
        "See summary.json for failures, pending requests, usage and decompilation gaps.\n")
    return 0 if report['status'] == 'completed' else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', choices=['prepare', 'preflight', 'scan', 'aggregate'])
    parser.add_argument('--jadx', default='jadx')
    parser.add_argument('--shard', type=int, choices=range(SHARDS))
    args = parser.parse_args()
    if args.operation == 'prepare':
        prepare(args.jadx)
    elif args.operation == 'preflight':
        preflight(load_config(Path('config.cloud.yaml')), Path('runs'))
    elif args.operation == 'scan':
        if args.shard is None:
            parser.error('--shard is required for scan')
        sys.exit(scan(args.shard))
    else:
        sys.exit(aggregate())
