import json
import os
import time
from pathlib import Path
from pydantic import ValidationError
from ..config import StrictModel
from ..schemas import Finding
from ..models import create_client
from ..models.openai_compatible import ModelError, ModelOutputError
from ..ingest.pipeline import digest, write_json
from .plan import load_plan, primary_files
from .prompts import SYSTEM_PROMPT, messages_for
from pydantic import Field

class ScanResponse(StrictModel):
    findings: list[Finding]
    notes: list[str] = Field(default_factory=list)


def evidence_errors(finding, unit):
    errors = []
    for name, span in [('location', finding.location), *[(f'evidence[{i}]', value) for i, value in enumerate(finding.evidence)]]:
        matches = [segment for segment in unit['segments'] if segment['file'] == span.file
                   and segment['start_line'] <= span.start_line <= span.end_line <= segment['end_line']]
        if not matches:
            errors.append(name + ': file or range absent from supplied bundle')
            continue
        consistent = False
        for segment in matches:
            lines = segment['text'].split('\n')
            first = span.start_line - segment['start_line']
            last = span.end_line - segment['start_line'] + 1
            source = '\n'.join(lines[first:last])
            # Compare indentation independently while preserving interior whitespace.
            normalized_snippet = '\n'.join(line.strip() for line in span.snippet.split('\n'))
            normalized_source = '\n'.join(line.strip() for line in lines[first:last])
            if span.snippet in source or (normalized_snippet.strip() and normalized_snippet in normalized_source):
                consistent = True
        if not consistent:
            errors.append(name + ': snippet absent from cited lines')
    return errors


def atomic_json(path, value):
    temporary = path.with_suffix('.tmp')
    write_json(temporary, value)
    temporary.replace(path)


def review_response(response, unit):
    result = {'response': response.model_dump(mode='json'), 'accepted': [], 'rejected': [], 'notes': []}
    if response.finish_reason != 'stop':
        result.update(status='invalid_response', error='Response was truncated, refused, or lacked a successful stop reason')
        return result
    try:
        data = json.loads(response.text)
        if not isinstance(data, dict) or set(data) - {'findings', 'notes'} or not isinstance(data.get('findings'), list):
            raise ValueError()
        notes = data.get('notes', [])
        if not isinstance(notes, list) or not all(isinstance(note, str) for note in notes):
            raise ValueError()
        result['notes'] = notes
    except (ValueError, TypeError):
        result.update(status='invalid_response', error='Expected JSON object with findings list and optional string notes')
        return result
    for index, candidate in enumerate(data['findings']):
        try:
            finding = Finding.model_validate(candidate)
        except ValidationError as exc:
            result['rejected'].append({'index': index, 'finding': candidate, 'errors': [
                'schema:' + '.'.join(map(str, item['loc'])) for item in exc.errors()]})
            continue
        errors = evidence_errors(finding, unit)
        if errors:
            result['rejected'].append({'index': index, 'finding': candidate, 'errors': errors})
        else:
            result['accepted'].append(finding.model_dump(mode='json'))
    result['status'] = 'completed_with_rejections' if result['rejected'] else 'completed'
    return result


def summarize(plan, units, output):
    successes, failed, missing, rejected, accepted, reasons, usage, duplicates = 0, [], [], [], [], {}, {}, []
    unique = {}
    checked_files = set()
    total_latency = 0
    for unit in units:
        path = output / 'requests' / (unit['id'] + '.json')
        if not path.exists():
            missing.append(unit['id'])
            continue
        record = json.loads(path.read_text())
        if record['unit_id'] != unit['id']:
            raise ValueError('Request record does not match scan unit')
        status = record['status']
        reasons[status] = reasons.get(status, 0) + 1
        if status in {'completed', 'completed_with_rejections'}:
            successes += 1
            checked_files.update(primary_files(unit))
        else:
            failed.append({'unit_id': unit['id'], 'primary': unit['primary'], 'status': status})
        response = record.get('response', {})
        total_latency += response.get('latency_seconds', 0)
        for name, amount in response.get('usage', {}).items():
            if isinstance(amount, (int, float)) and not isinstance(amount, bool):
                usage[name] = usage.get(name, 0) + amount
        for entry in record.get('rejected', []):
            rejected.append({'unit_id': unit['id'], **entry})
        for finding in record.get('accepted', []):
            # Conservative: only identical normalized findings are collapsed.
            key = digest(json.dumps(finding, sort_keys=True).encode())
            if key in unique:
                duplicates.append({'finding_id': key, 'unit_id': unit['id']})
                unique[key]['unit_ids'].append(unit['id'])
            else:
                item = {'finding_id': key, 'unit_ids': [unit['id']], 'finding': finding,
                        'validation': 'source_consistent_not_security_confirmed'}
                unique[key] = item
                accepted.append(item)
    unsuccessful_ids = set(missing) | {item['unit_id'] for item in failed}
    unsuccessful = {file for unit in units if unit['id'] in unsuccessful_ids
                    for file in primary_files(unit)}
    report = {'plan_id': plan['plan_id'], 'planned_units': len(units), 'completed_units': successes,
              'status': 'completed' if successes == len(units) else 'incomplete',
              'failed_units': failed, 'pending_unit_ids': missing, 'response_status_counts': reasons,
              'fully_processed_primary_files': len(checked_files - unsuccessful),
              'planned_primary_files': plan['primary_files_in_plan'],
              'accepted_unique_findings': len(accepted), 'rejected_findings': len(rejected),
              'exact_duplicates': len(duplicates), 'usage': usage, 'response_latency_seconds': total_latency,
              'ingestion_skipped': plan['skipped'], 'ingestion_warnings': plan['warnings'],
              'limitations': plan['limitations'] + ['Evidence checks do not prove exploitability or measure recall.',
                'Only exact duplicate findings are collapsed; semantic duplicates need review.',
                'Usage totals cover saved responses; provider failures may incur unreported usage.']}
    atomic_json(output / 'summary.json', report)
    atomic_json(output / 'findings.json', accepted)
    atomic_json(output / 'rejected.json', rejected)
    atomic_json(output / 'duplicates.json', duplicates)
    return report


def run_scan(config, plan_path, output, role='teacher', resume=False, retry_failed=False,
             max_requests=None, delay_seconds=0, client=None, progress=None):
    plan, units = load_plan(plan_path)
    model = config.models.get(role)
    if model is None:
        raise ValueError(f'No model configured for {role}')
    # Fail before creating a misleading run with zero actual requests.
    if client is None:
        if model.model.startswith('REPLACE_'):
            raise ValueError('Configure a real model ID before scanning')
        if not os.environ.get(model.api_key_env):
            raise ValueError(f'Set environment variable {model.api_key_env} before scanning')
        client = create_client(model)
    schema = ScanResponse.model_json_schema()
    model_settings = model.model_dump(mode='json', exclude={
        name for name in ('reasoning_effort', 'reasoning_format', 'service_tier')
        if getattr(model, name) is None
    })
    if model.schema_in_prompt:
        model_settings.pop('schema_in_prompt')
    identity = {'runner_version': 1, 'plan_id': plan['plan_id'], 'role': role,
                'model': model_settings, 'prompt': SYSTEM_PROMPT, 'response_schema': schema}
    if output.exists():
        if not resume:
            raise ValueError('Scan output exists; use --resume or choose a new directory')
        if json.loads((output / 'run.json').read_text()) != identity:
            raise ValueError('Cannot resume with different inputs, prompt, schema or model settings')
    else:
        if resume:
            raise ValueError('Cannot resume a nonexistent run')
        output.mkdir(parents=True)
        write_json(output / 'run.json', identity)
    lock = output / '.running'
    try:
        lock.mkdir()
    except FileExistsError:
        raise ValueError('Run is locked; ensure no process is running before removing .running') from None
    try:
        requests = output / 'requests'
        requests.mkdir(exist_ok=True)
        called = 0
        for unit in units:
            path = requests / (unit['id'] + '.json')
            if path.exists():
                previous = json.loads(path.read_text())
                if previous['status'] in {'completed', 'completed_with_rejections'} or not retry_failed:
                    continue
            if max_requests is not None and called >= max_requests:
                break
            if path.exists():
                history = output / 'history' / unit['id']
                history.mkdir(parents=True, exist_ok=True)
                path.rename(history / (str(time.time_ns()) + '.json'))
            messages = messages_for(unit)
            record = {'unit_id': unit['id'], 'primary': unit['primary'], 'messages': messages}
            try:
                response = client.generate(messages, response_schema=schema)
                record.update(review_response(response, unit))
            except ModelOutputError as exc:
                record.update(status='invalid_response', error=str(exc))
            except ModelError as exc:
                record.update(status='provider_error', error=str(exc))
            atomic_json(path, record)
            called += 1
            if progress:
                progress({'requests_this_run': called, 'unit': unit['id'], 'primary': unit['primary'], 'status': record['status'], **({'error': record['error']} if 'error' in record else {})})
            # Abort systemic failures rather than send thousands of doomed requests.
            if record['status'] == 'provider_error':
                break
            if delay_seconds:
                time.sleep(delay_seconds)
        report = summarize(plan, units, output)
        # Retry history is retained; report usage separately instead of hiding extra costs.
        history_usage = {}
        for history in (output / 'history').glob('*/*.json'):
            for name, amount in json.loads(history.read_text()).get('response', {}).get('usage', {}).items():
                if isinstance(amount, (int, float)) and not isinstance(amount, bool):
                    history_usage[name] = history_usage.get(name, 0) + amount
        report['prior_attempt_usage'] = history_usage
        atomic_json(output / 'summary.json', report)
        return report
    finally:
        lock.rmdir()
