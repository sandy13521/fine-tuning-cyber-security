"""Cloud orchestration for the public InsecureShop fixture; no secret values on disk."""
import argparse
import json
from pathlib import Path
import sys

from cyber_scan.config import load_config
from cyber_scan.ingest.apk import download_apk, decompile
from cyber_scan.ingest.pipeline import ingest, digest, write_json
from cyber_scan.scan.plan import build_plan, group_plan, load_plan, primary_files
from cyber_scan.scan.runner import run_scan

SHARDS = 8
REQUESTS = 50
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
                    'scope': f'all_ingested_files_partition_{index}_of_{shards}',
                    'total_bundle_tokens_or_estimate': sum(unit['tokens_or_estimate'] for unit in selected),
                    'shard_index': index, 'shard_count': shards}
        (folder / 'units.jsonl').write_text(raw, encoding='utf-8')
        write_json(folder / 'plan.json', metadata)
    return parent


def prepare(jadx):
    config = load_config(Path('config.cloud.yaml'))
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
    source, _ = ingest(config)
    build_plan(config, source, Path('runs/source-plan'))
    report = group_plan(Path('runs/source-plan'), Path('runs/full-plan'), REQUESTS,
                        'tiktoken:o200k_base', 160_000)
    partition(Path('runs/full-plan'), Path('runs/shards'))
    print(json.dumps({key: report[key] for key in ('plan_id', 'unit_count', 'loaded_files', 'total_bundle_tokens_or_estimate',
                                              'max_bundle_tokens_or_estimate', 'warnings')}, indent=2))


def scan(index):
    config = load_config(Path('config.cloud.yaml'))
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
    from cyber_scan.scan.runner import summarize
    output = Path('combined')
    (output / 'requests').mkdir(parents=True)
    for unit_id, record in records.items():
        write_json(output / 'requests' / (unit_id + '.json'), record)
    report = summarize(plan, units, output)
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
        f"Source-consistent unique findings: {report['accepted_unique_findings']}. "
        "These require security review and are not confirmed vulnerabilities or measured recall.\n\n"
        "See summary.json for failures, pending requests, usage and decompilation gaps.\n")
    return 0 if report['status'] == 'completed' else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', choices=['prepare', 'scan', 'aggregate'])
    parser.add_argument('--jadx', default='jadx')
    parser.add_argument('--shard', type=int, choices=range(SHARDS))
    args = parser.parse_args()
    if args.operation == 'prepare':
        prepare(args.jadx)
    elif args.operation == 'scan':
        if args.shard is None:
            parser.error('--shard is required for scan')
        sys.exit(scan(args.shard))
    else:
        sys.exit(aggregate())
