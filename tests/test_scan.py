import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from cyber_scan.config import AppConfig, ModelConfig
from cyber_scan.ingest.pipeline import ingest
from cyber_scan.scan.plan import build_plan, group_plan, load_plan, segment, windows, render_segment
from cyber_scan.scan.runner import run_scan, review_response
from cyber_scan.schemas import ModelResponse
from cyber_scan.models.openai_compatible import ModelError


def response(findings=None, finish='stop', text=None):
    return ModelResponse(model='fake',text=text if text is not None else json.dumps({'findings': findings or [], 'notes': []}),
                         usage={'prompt_tokens':3,'completion_tokens':2},finish_reason=finish,latency_seconds=.01,attempts=1)


def finding(file='Main.java', start=2, end=2, snippet='danger(input);'):
    span={'file':file,'start_line':start,'end_line':end,'snippet':snippet}
    return {'type':'example_only','cwe':None,'severity':'medium','location':span,
            'evidence':[span], 'explanation':'Synthetic test finding; not real security evidence.',
            'preconditions':[],'confidence':.5,'status':'needs_runtime_validation'}

class FakeClient:
    def __init__(self, results):
        self.results=iter(results)
        self.calls=[]
    def generate(self,messages,response_schema=None):
        self.calls.append(messages)
        result=next(self.results)
        if isinstance(result,Exception):raise result
        return result

class ScanTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.source=self.root/'source'
        self.source.mkdir()
        (self.source/'Main.java').write_text('class Main {\n  danger(input);\n}\n')
        (self.source/'Helper.java').write_text('class Helper {}\n')
        self.config=AppConfig(input_dir=self.source,output_dir=self.root/'ingested',bundle_token_budget=400,
            models={'teacher':ModelConfig(model='fake',base_url='https://example.test/v1',api_key_env='MISSING_TEST_KEY')})
        self.ingest_dir,_=ingest(self.config)
        self.plan=self.root/'plan'
        self.output=self.root/'scan'

    def build(self):
        return build_plan(self.config,self.ingest_dir,self.plan)

    def test_large_files_and_long_lines_not_dropped(self):
        (self.source/'Large.java').write_text('\n'.join('method'+str(i)+'();' for i in range(100)))
        (self.source/'OneLine.java').write_text('é'*2000)
        self.ingest_dir,_=ingest(self.config)
        report=self.build()
        _,units=load_plan(self.plan)
        self.assertEqual(report['primary_files_in_plan'],4)
        self.assertEqual(report['oversized_files_split'],2)
        self.assertEqual(len({u['id'] for u in units}),len(units))
        fragments=[u['segments'][0]['text'] for u in units if u['primary']=='OneLine.java']
        self.assertEqual(''.join(fragments),'é'*2000)
        ranges=[u['segments'][0] for u in units if u['primary']=='Large.java']
        covered={i for s in ranges for i in range(s['start_line'],s['end_line']+1)}
        self.assertEqual(covered,set(range(1,101)))
        self.assertTrue(all(u['tokens_or_estimate']<=400 for u in units))

    def test_source_change_refused(self):
        (self.source/'Main.java').write_text('changed')
        with self.assertRaisesRegex(ValueError,'Source changed'):self.build()

    def test_plan_tampering_refused(self):
        self.build()
        with (self.plan/'units.jsonl').open('a') as f:f.write(' ') 
        with self.assertRaisesRegex(ValueError,'changed'):load_plan(self.plan)

    def test_evidence_exact_lines_and_supplied_files(self):
        unit={'segments':[segment('Main.java','class Main {\n  danger(input);\n}',1)]}
        accepted=review_response(response([finding()]),unit)
        self.assertEqual(len(accepted['accepted']),1)
        for bad in [finding(file='../secret'),finding(start=1,end=1),finding(snippet='invented();')]:
            rejected=review_response(response([bad]),unit)
            self.assertEqual(len(rejected['accepted']),0)
            self.assertEqual(len(rejected['rejected']),1)

    def test_truncated_and_malformed_outputs_not_clean_scans(self):
        unit={'segments':[]}
        for bad in [response(finish='length'),response(text='not JSON'),response(text='{"findings": "none"}')]:
            result=review_response(bad,unit)
            self.assertEqual(result['status'],'invalid_response')
            self.assertIn('response',result)

    def test_schema_failure_does_not_drop_valid_sibling(self):
        unit={'segments':[segment('Main.java','x\n  danger(input);',1)]}
        result=review_response(response([finding(),{'type':'incomplete'}]),unit)
        self.assertEqual(len(result['accepted']),1)
        self.assertEqual(len(result['rejected']),1)
        self.assertEqual(result['status'],'completed_with_rejections')

    def test_capped_run_resume_and_usage(self):
        report=self.build()
        client=FakeClient([response(),response()])
        first=run_scan(self.config,self.plan,self.output,max_requests=1,client=client)
        self.assertEqual(first['status'],'incomplete')
        self.assertEqual(first['completed_units'],1)
        final=run_scan(self.config,self.plan,self.output,resume=True,client=client)
        self.assertEqual(final['status'],'completed')
        self.assertEqual(len(client.calls),2)
        self.assertEqual(final['usage']['prompt_tokens'],6)
        self.assertEqual(final['planned_units'],report['unit_count'])
        self.assertFalse((self.output/'.running').exists())

    def test_resume_configuration_must_match(self):
        self.build()
        run_scan(self.config,self.plan,self.output,max_requests=1,client=FakeClient([response()]))
        self.config.models['teacher'].model='different'
        with self.assertRaisesRegex(ValueError,'different inputs'):
            run_scan(self.config,self.plan,self.output,resume=True,client=FakeClient([]))

    def test_provider_failure_stops_and_retry_preserves_history(self):
        self.build()
        first=run_scan(self.config,self.plan,self.output,client=FakeClient([ModelError('HTTP 401')]))
        self.assertEqual(first['completed_units'],0)
        self.assertEqual(len(first['failed_units']),1)
        second=run_scan(self.config,self.plan,self.output,resume=True,retry_failed=True,client=FakeClient([response(),response()]))
        self.assertEqual(second['status'],'completed')
        self.assertEqual(len(list((self.output/'history').glob('*/*.json'))),1)

    def test_invalid_response_retry_usage_retained(self):
        self.build()
        run_scan(self.config,self.plan,self.output,max_requests=1,client=FakeClient([response(finish='length')]))
        report=run_scan(self.config,self.plan,self.output,resume=True,retry_failed=True,client=FakeClient([response(),response()]))
        self.assertEqual(report['status'],'completed')
        self.assertEqual(report['prior_attempt_usage']['prompt_tokens'],3)

    @patch.dict('os.environ',{},clear=True)
    def test_missing_credentials_fail_without_run_artifacts(self):
        self.build()
        with self.assertRaisesRegex(ValueError,'MISSING_TEST_KEY'):
            run_scan(self.config,self.plan,self.output)
        self.assertFalse(self.output.exists())

    def test_source_can_be_removed_after_freezing(self):
        self.build()
        for file in self.source.iterdir():file.unlink()
        result=run_scan(self.config,self.plan,self.output,client=FakeClient([response(),response()]))
        self.assertEqual(result['status'],'completed')

    def test_lock_prevents_concurrent_run(self):
        self.build()
        run_scan(self.config,self.plan,self.output,max_requests=1,client=FakeClient([response()]))
        (self.output/'.running').mkdir()
        with self.assertRaisesRegex(ValueError,'locked'):
            run_scan(self.config,self.plan,self.output,resume=True,client=FakeClient([]))

    def test_grouped_run_accounts_for_every_primary(self):
        self.build()
        path = self.root / 'grouped'
        plan = group_plan(self.plan, path, 1, 'utf8_bytes', 2000)
        self.assertEqual(plan['unit_count'], 1)
        result = run_scan(self.config, path, self.output, client=FakeClient([response()]))
        self.assertEqual(result['completed_units'], 1)
        self.assertEqual(result['fully_processed_primary_files'], 2)

    def test_multiline_citation_accepts_indentation_but_preserves_literal_contents(self):
        unit = {'segments': [segment('Main.java', '  first("a b");\n  second();')]}
        valid = finding(start=1, end=2, snippet='first("a b");\nsecond();')
        invalid = finding(start=1, end=2, snippet='first("ab");\nsecond();')
        reviewed = review_response(response([valid, invalid]), unit)
        self.assertEqual(len(reviewed['accepted']), 1)
        self.assertEqual(len(reviewed['rejected']), 1)
