import json
from pathlib import Path, PurePosixPath
from ..ingest.pipeline import digest, render, token_counter, write_json

PLAN_VERSION = 1


def read_source(root, item):
    relative = PurePosixPath(item['path'])
    if relative.is_absolute() or '..' in relative.parts or '\\' in item['path']:
        raise ValueError('Unsafe source path in inventory')
    path = root.joinpath(*relative.parts)
    if root.resolve() not in path.resolve().parents or path.is_symlink():
        raise ValueError('Source path escapes input directory')
    raw = path.read_bytes()
    if digest(raw) != item['sha256']:
        raise ValueError(f"Source changed since ingestion: {item['path']}; ingest again")
    return raw.decode('utf-8-sig')


def segment(path, text, start=1, partial_line=False):
    return {'file': path, 'start_line': start,
            'end_line': start + max(0, len(text.split('\n')) - 1),
            'text': text, 'partial_line': partial_line}


def render_segment(span):
    label = f"FILE {span['file']}"
    if span['partial_line']:
        label += ' [partial long line; neighboring fragments omitted]'
    return label + '\n' + '\n'.join(
        f'{number}: {line}' for number, line in enumerate(span['text'].split('\n'), span['start_line']))


def windows(path, text, count, budget, overlap=10):
    """Preserve line numbers; fragment a single over-budget line without dropping text."""
    lines = text.splitlines()
    if not lines:
        yield segment(path, '')
        return
    start = 0
    while start < len(lines):
        one = segment(path, lines[start], start + 1)
        if count(render_segment(one)) > budget:
            remaining = lines[start]
            while remaining:
                low, high, best = 1, len(remaining), 0
                while low <= high:
                    middle = (low + high) // 2
                    piece = segment(path, remaining[:middle], start + 1, True)
                    if count(render_segment(piece)) <= budget:
                        best, low = middle, middle + 1
                    else:
                        high = middle - 1
                if not best:
                    raise ValueError('Bundle budget cannot fit a source character and header')
                yield segment(path, remaining[:best], start + 1, True)
                remaining = remaining[best:]
            start += 1
            continue
        # Binary search for a whole-line window. Verify the chosen window's actual size.
        low, high, end = start + 1, len(lines), start + 1
        while low <= high:
            middle = (low + high) // 2
            candidate = segment(path, '\n'.join(lines[start:middle]), start + 1)
            if count(render_segment(candidate)) <= budget:
                end, low = middle, middle + 1
            else:
                high = middle - 1
        yield segment(path, '\n'.join(lines[start:end]), start + 1)
        if end == len(lines):
            break
        start = max(start + 1, end - overlap)


def build_plan(config, ingest_dir, output):
    if output.exists():
        raise ValueError('Plan output already exists; use a fresh directory')
    if config.input_dir.resolve() == output.resolve() or config.input_dir.resolve() in output.resolve().parents:
        raise ValueError('Scan plan must be outside the input directory')
    metadata = json.loads((ingest_dir / 'metadata.json').read_text())
    coverage = json.loads((ingest_dir / 'coverage.json').read_text())
    inventory = json.loads((ingest_dir / 'inventory.json').read_text())
    settings = metadata['settings']
    # Freeze the original ingestion budgets, independent of later model config changes.
    count = token_counter(settings['tokenizer'])
    budget = settings['bundle_token_budget']
    source = {item['path']: read_source(config.input_dir, item)
              for item in inventory if item['status'] == 'loaded'}
    units = []
    primaries = set()
    for line in (ingest_dir / 'bundles.jsonl').read_text().splitlines():
        bundle = json.loads(line)
        if bundle['primary'] in primaries:
            raise ValueError('Duplicate primary file in ingestion bundles')
        primaries.add(bundle['primary'])
        reconstructed = '\n\n'.join(render(path, source[path]) for path in bundle['files'])
        if reconstructed != bundle['content'] or digest(reconstructed.encode()) != bundle['id']:
            raise ValueError('Ingestion bundle does not match source hashes')
        spans = [segment(path, '\n'.join(source[path].splitlines())) for path in bundle['files']]
        content = '\n\n'.join(render_segment(span) for span in spans)
        units.append({'primary': bundle['primary'], 'kind': 'whole_file', 'segments': spans,
                      'content': content, 'omitted_related_files': bundle['omitted_related_files']})
    oversized = sorted(set(source) - primaries)
    for path in oversized:
        for span in windows(path, source[path], count, budget):
            units.append({'primary': path, 'kind': 'oversized_window', 'segments': [span],
                          'content': render_segment(span), 'omitted_related_files': [],
                          'context_limitation': 'Window-only analysis; cross-window and cross-file flows may be missed'})
    if not units:
        raise ValueError('No scan units were produced')
    for sequence, unit in enumerate(units):
        unit['sequence'] = sequence
        unit['tokens_or_estimate'] = count(unit['content'])
        if unit['tokens_or_estimate'] > budget:
            raise ValueError('Scan unit exceeds ingestion budget')
        unit['id'] = digest(json.dumps(unit, sort_keys=True).encode())
    jsonl = ''.join(json.dumps(unit, sort_keys=True) + '\n' for unit in units)
    plan_id = digest(jsonl.encode())
    report = {
        'plan_version': PLAN_VERSION, 'plan_id': plan_id, 'units_sha256': plan_id,
        'ingest_run_id': metadata['run_id'], 'scope': 'all_ingested_files_including_dependencies',
        'unit_count': len(units), 'loaded_files': len(source),
        'whole_file_units': len(primaries), 'oversized_files_split': len(oversized),
        'window_units': sum(unit['kind'] == 'oversized_window' for unit in units),
        'primary_files_in_plan': len({unit['primary'] for unit in units}),
        'tokenizer': settings['tokenizer'], 'is_estimate': settings['tokenizer'] == 'utf8_bytes',
        'total_bundle_tokens_or_estimate': sum(unit['tokens_or_estimate'] for unit in units),
        'max_bundle_tokens_or_estimate': max(unit['tokens_or_estimate'] for unit in units),
        'skipped': coverage['skipped'], 'warnings': coverage['warnings'],
        'decompilation': metadata.get('decompilation'),
        'status': 'prepared_not_scanned',
        'limitations': ['Coverage applies to ingested text; binary/skipped files remain unscanned.',
                       'Windows retain local overlap, not whole-program data flow.',
                       'Prompt/schema/output tokens are additional to bundle estimates.'],
    }
    output.mkdir(parents=True)
    (output / 'units.jsonl').write_text(jsonl, encoding='utf-8')
    write_json(output / 'plan.json', report)
    return report


def load_plan(path):
    metadata = json.loads((path / 'plan.json').read_text())
    raw = (path / 'units.jsonl').read_bytes()
    if metadata['plan_version'] != PLAN_VERSION or digest(raw) != metadata['units_sha256']:
        raise ValueError('Scan plan is unsupported or has changed')
    units = [json.loads(line) for line in raw.decode().splitlines()]
    if len(units) != metadata['unit_count'] or len({unit['id'] for unit in units}) != len(units):
        raise ValueError('Scan plan has missing or duplicate units')
    for unit in units:
        content = '\n\n'.join(render_segment(span) for span in unit['segments'])
        identity = {key: value for key, value in unit.items() if key != 'id'}
        if content != unit['content'] or digest(json.dumps(identity, sort_keys=True).encode()) != unit['id']:
            raise ValueError('Scan unit integrity check failed')
    return metadata, units
