import importlib.util
from pathlib import Path
import unittest
import httpx
spec=importlib.util.spec_from_file_location('diagnose',Path(__file__).resolve().parents[1]/'scripts/diagnose_openai.py')
diagnostic=importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostic)

class DiagnosticTests(unittest.TestCase):
    def test_redacts_key_and_account(self):
        result=diagnostic.describe(httpx.Response(429,json={'error':{'message':'sk-fake-secret proj-abc org-def','code':'rate_limit_exceeded'}}),'sk-fake-secret')
        self.assertNotIn('sk-fake-secret',str(result))
        self.assertNotIn('proj-abc',str(result))
        self.assertEqual(result['code'],'rate_limit_exceeded')
    def test_success_does_not_save_body(self):
        result=diagnostic.describe(httpx.Response(200,json={'anything':'private'}),'key')
        self.assertNotIn('private',str(result))
