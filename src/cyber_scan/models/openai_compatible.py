import json
import os
import time
import httpx
from ..schemas import ModelResponse

class ModelError(RuntimeError):
    pass

def strict_json_schema(schema):
    """Strict structured output requires all declared properties, including nullable ones."""
    if isinstance(schema, list):
        return [strict_json_schema(item) for item in schema]
    if not isinstance(schema, dict):
        return schema
    result = {key: strict_json_schema(value) for key, value in schema.items() if key != 'default'}
    if result.get('type') == 'object' and 'properties' in result:
        result['required'] = list(result['properties'])
        result['additionalProperties'] = False
    return result


def provider_error_code(response):
    # Fixed allowlist only: never log arbitrary provider response text or secrets.
    try:
        error = response.json().get('error', {})
        code = error.get('code') or error.get('type')
    except (ValueError, AttributeError, TypeError):
        return None
    allowed = {'insufficient_quota', 'rate_limit_exceeded', 'invalid_api_key',
               'model_not_found', 'permission_denied', 'billing_hard_limit_reached'}
    return code if isinstance(code, str) and code in allowed else None


class OpenAICompatibleClient:
    def __init__(self, config, transport=None):
        self.config = config
        self.transport = transport

    def generate(self, messages, response_schema=None):
        config = self.config
        key = os.environ.get(config.api_key_env)
        if not key:
            raise ModelError(f"Set environment variable {config.api_key_env}")
        if config.model.startswith("REPLACE_"):
            raise ModelError("Choose a real model ID in configuration")
        messages = [dict(message) for message in messages]
        payload = {"model": config.model, "messages": messages,
                   config.token_parameter: config.max_output_tokens}
        if config.temperature is not None:
            payload["temperature"] = config.temperature
        if response_schema:
            messages.append({"role": "system", "content": "Return only valid JSON matching this schema: " + json.dumps(response_schema)})
            if config.response_format == "json_schema":
                payload["response_format"] = {"type": "json_schema", "json_schema": {"name": "result", "schema": strict_json_schema(response_schema), "strict": True}}
            elif config.response_format == "json_object":
                payload["response_format"] = {"type": "json_object"}
        start = time.monotonic()
        with httpx.Client(timeout=config.timeout_seconds, transport=self.transport, follow_redirects=False) as client:
            for attempt in range(config.retries + 1):
                try:
                    response = client.post(config.base_url + "/chat/completions", json=payload,
                                           headers={"Authorization": "Bearer " + key})
                except httpx.TransportError:
                    if attempt == config.retries:
                        raise ModelError("Provider transport failure after retries") from None
                    time.sleep(min(2 ** attempt, 8))
                    continue
                error_code = provider_error_code(response) if not response.is_success else None
                if error_code in {'insufficient_quota', 'billing_hard_limit_reached'}:
                    raise ModelError(f"Provider returned HTTP {response.status_code} ({error_code})")
                if response.status_code == 429 or response.status_code >= 500:
                    if attempt < config.retries:
                        try:
                            delay = min(max(float(response.headers.get("retry-after", 2 ** attempt)), 0), 30)
                        except ValueError:
                            delay = 2 ** attempt
                        time.sleep(delay)
                        continue
                if not response.is_success:
                    # Never echo provider bodies: they can contain request data or credentials.
                    raise ModelError(f"Provider returned HTTP {response.status_code}" + (f" ({error_code})" if error_code else ""))
                try:
                    body = response.json()
                    choice = body["choices"][0]
                    content = choice["message"]["content"]
                    if not isinstance(content, str):
                        raise ValueError()
                    return ModelResponse(model=body.get("model", config.model), text=content,
                                         usage=body.get("usage") or {}, finish_reason=choice.get("finish_reason"),
                                         latency_seconds=time.monotonic()-start, attempts=attempt+1)
                except (ValueError, KeyError, IndexError, TypeError):
                    raise ModelError("Malformed provider response") from None
