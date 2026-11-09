import json
import os
import unittest
from unittest.mock import patch
import httpx
from cyber_scan.config import ModelConfig
from cyber_scan.models.openai_compatible import ModelError, OpenAICompatibleClient

class ModelTests(unittest.TestCase):
    def config(self, **kwargs):
        return ModelConfig(model='test-model',base_url='https://example.test/v1',api_key_env='TEST_API_KEY',**kwargs)

    @patch.dict(os.environ, {'TEST_API_KEY':'secret'})
    def test_request_response(self):
        requests=[]
        def handler(request):
            requests.append(request)
            return httpx.Response(200,json={'model':'resolved-model','choices':[{'message':{'content':'OK'},'finish_reason':'stop'}],'usage':{'total_tokens':4}})
        client=OpenAICompatibleClient(self.config(),httpx.MockTransport(handler))
        response=client.generate([{'role':'user','content':'Hello'}])
        self.assertEqual(response.text,'OK')
        self.assertEqual(response.model,'resolved-model')
        self.assertEqual(response.usage['total_tokens'],4)
        self.assertEqual(requests[0].headers['Authorization'],'Bearer secret')
        self.assertNotIn('secret',response.model_dump_json())

    @patch.dict(os.environ, {'TEST_API_KEY':'secret'})
    @patch('cyber_scan.models.openai_compatible.time.sleep')
    def test_retry(self,sleep):
        calls=[]
        def handler(request):
            calls.append(request)
            if len(calls)==1:return httpx.Response(429,headers={'retry-after':'0'})
            return httpx.Response(200,json={'choices':[{'message':{'content':'OK'}}]})
        response=OpenAICompatibleClient(self.config(),httpx.MockTransport(handler)).generate([])
        self.assertEqual(response.attempts,2)

    @patch.dict(os.environ, {'TEST_API_KEY':'secret'})
    def test_http_error_does_not_echo_body(self):
        client=OpenAICompatibleClient(self.config(),httpx.MockTransport(lambda r:httpx.Response(401,text='secret')))
        with self.assertRaisesRegex(ModelError,'HTTP 401') as error: client.generate([])
        self.assertNotIn('secret',str(error.exception))

    @patch.dict(os.environ, {}, clear=True)
    def test_missing_credentials(self):
        with self.assertRaisesRegex(ModelError,'TEST_API_KEY'):
            OpenAICompatibleClient(self.config()).generate([])

    @patch.dict(os.environ, {'TEST_API_KEY':'secret'})
    def test_schema_and_token_parameter(self):
        def handler(request):
            body=json.loads(request.content)
            self.assertIn('max_completion_tokens',body)
            self.assertNotIn('max_tokens',body)
            self.assertEqual(body['response_format']['type'],'json_object')
            self.assertEqual(body['service_tier'], 'flex')
            self.assertEqual(body['reasoning_effort'], 'low')
            return httpx.Response(200,json={'choices':[{'message':{'content':'{}'}}]})
        client=OpenAICompatibleClient(self.config(token_parameter='max_completion_tokens', response_format='json_object',
                             service_tier='flex', reasoning_effort='low'), httpx.MockTransport(handler))
        client.generate([],{'type':'object'})

    def test_credential_url_rejected(self):
        with self.assertRaises(ValueError):
            ModelConfig(model='x',base_url='https://user:password@example.test',api_key_env='KEY')

    @patch.dict(os.environ, {'TEST_API_KEY':'secret'})
    def test_malformed_response(self):
        client=OpenAICompatibleClient(self.config(),httpx.MockTransport(lambda r:httpx.Response(200,json={'choices':[]})))
        with self.assertRaisesRegex(ModelError,'Malformed'): client.generate([])

    @patch.dict(os.environ, {'TEST_API_KEY':'secret'})
    @patch('cyber_scan.models.openai_compatible.time.sleep')
    def test_retry_exhaustion(self,sleep):
        calls=[]
        def handler(request):
            calls.append(request)
            return httpx.Response(503)
        client=OpenAICompatibleClient(self.config(retries=1),httpx.MockTransport(handler))
        with self.assertRaisesRegex(ModelError,'HTTP 503'):client.generate([])
        self.assertEqual(len(calls),2)

    def test_strict_schema_requires_nullable_defaults(self):
        from cyber_scan.models.openai_compatible import strict_json_schema
        from cyber_scan.scan.runner import ScanResponse
        original=ScanResponse.model_json_schema()
        result=strict_json_schema(original)
        self.assertEqual(set(result['required']),{'findings','notes'})
        self.assertNotIn('default',result['properties']['notes'])
        self.assertIn('cwe',result['$defs']['Finding']['required'])
        self.assertFalse(result['additionalProperties'])

    @patch.dict(os.environ, {'TEST_API_KEY':'secret'})
    def test_insufficient_quota_does_not_retry_or_echo_body(self):
        calls=[]
        def handler(request):
            calls.append(request)
            return httpx.Response(429,json={'error':{'code':'insufficient_quota','message':'secret'}})
        client=OpenAICompatibleClient(self.config(),httpx.MockTransport(handler))
        with self.assertRaisesRegex(ModelError,'insufficient_quota') as error:client.generate([])
        self.assertNotIn('secret',str(error.exception))
        self.assertEqual(len(calls),1)

    def test_error_code_allowlist(self):
        from cyber_scan.models.openai_compatible import provider_error_code
        self.assertIsNone(provider_error_code(httpx.Response(401,json={'error':{'code':'secret'}})))

    def test_rate_limit_backoff_uses_reset_duration(self):
        from cyber_scan.models.openai_compatible import retry_delay
        reply = httpx.Response(429, headers={
            'retry-after': '15', 'x-ratelimit-reset-tokens': '1m2.5s',
        })
        self.assertEqual(retry_delay(reply, 0), 62.5)
        self.assertEqual(retry_delay(httpx.Response(429), 0), 60)
