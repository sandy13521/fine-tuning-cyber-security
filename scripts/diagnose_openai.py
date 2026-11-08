"""Small model/endpoint probes. Only redacted error diagnostics are persisted."""
import json
import os
from pathlib import Path
import re
import httpx
from cyber_scan.config import load_config


def redact(value, key):
    text = str(value).replace(key, '[REDACTED_KEY]') if key else str(value)
    text = re.sub(r'sk-[A-Za-z0-9_-]+', '[REDACTED_KEY]', text)
    text = re.sub(r'\b(?:proj|org)[-_][A-Za-z0-9_-]+', '[REDACTED_ACCOUNT]', text)
    return text[:1200]


def describe(response, key):
    result = {'http_status': response.status_code,
              'content_type': response.headers.get('content-type', '').split(';')[0]}
    if not response.is_success:
        try:
            body = response.json()
            error = body.get('error', body) if isinstance(body, dict) else body
            if isinstance(error, dict):
                result.update({name: redact(error.get(name), key) for name in ('code', 'type', 'message')})
            else:
                result['message'] = redact(error, key)
        except ValueError:
            result['message'] = redact(response.text, key)
    return result


def main():
    model = load_config(Path('config.cloud.yaml')).models['teacher']
    key = os.environ.get(model.api_key_env)
    if not key:
        raise SystemExit('Configured teacher secret is missing')
    results = []
    with httpx.Client(timeout=60, follow_redirects=False) as client:
        requests = [('model_access', 'GET', f'/models/{model.model}', None)]
        for cap in (128, model.max_output_tokens):
            requests.append((f'completion_budget_{cap}', 'POST', '/chat/completions',
                             {'model': model.model, 'messages': [{'role':'user','content':'Reply with exactly OK.'}],
                              model.token_parameter: cap}))
        for name, method, endpoint, payload in requests:
            try:
                response = client.request(method, model.base_url + endpoint,
                    headers={'Authorization': 'Bearer ' + key}, **({'json': payload} if payload else {}))
                results.append({'probe': name, **describe(response, key)})
            except httpx.TransportError:
                results.append({'probe': name, 'transport_error': True})
            print(json.dumps({'probe': name, 'status': results[-1].get('http_status'),
                              'code': results[-1].get('code')}), flush=True)
    Path('runs').mkdir(exist_ok=True)
    Path('runs/provider-diagnostics.json').write_text(json.dumps(results, indent=2) + '\n')


if __name__ == '__main__':
    main()
