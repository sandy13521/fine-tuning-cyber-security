import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from cyber_scan.config import AppConfig, load_config
from cyber_scan.ingest.pipeline import ingest
from cyber_scan.scan.plan import build_plan, load_plan, primary_files

SPEC = importlib.util.spec_from_file_location('cloud_teacher', Path(__file__).resolve().parents[1] / 'scripts/cloud_teacher.py')
cloud = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cloud)

class CloudTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        source = self.root / 'source'
        source.mkdir()
        for index in range(10):
            (source / f'File{index}.java').write_text(f'class File{index} {{}}')
        config = AppConfig(input_dir=source, output_dir=self.root / 'runs')
        ingested, _ = ingest(config)
        self.plan = self.root / 'cloud-plan/full-plan'
        build_plan(config, ingested, self.plan)

    def test_partitions_cover_all_units_exactly_once(self):
        cloud.partition(self.plan, self.root / 'shards')
        _, full = load_plan(self.plan)
        collected = []
        for index in range(cloud.SHARDS):
            metadata, units = load_plan(self.root / 'shards' / str(index))
            self.assertEqual(metadata['shard_index'], index)
            collected.extend(unit['id'] for unit in units)
        self.assertEqual(set(collected), {unit['id'] for unit in full})
        self.assertEqual(len(collected), len(full))

    def test_aggregate_marks_missing_records_incomplete(self):
        old = Path.cwd()
        os.chdir(self.root)
        try:
            code = cloud.aggregate()
            report = json.loads(Path('combined/summary.json').read_text())
        finally:
            os.chdir(old)
        self.assertEqual(code, 1)
        self.assertEqual(report['completed_units'], 0)
        self.assertEqual(report['planned_units'], 10)

    def test_cloud_config(self):
        config = load_config(Path(__file__).resolve().parents[1] / 'config.cloud.yaml')
        model = config.models['teacher']
        self.assertEqual(model.model, 'gpt-6-luna')
        self.assertEqual(model.api_key_env, 'TEACHER_API_KEY')
        self.assertEqual(model.token_parameter, 'max_completion_tokens')
        self.assertEqual(model.service_tier, 'flex')
        self.assertEqual(model.retries, 0)

    def test_focused_plan_excludes_unrelated_text_from_all_prompts(self):
        config = load_config(Path(__file__).resolve().parents[1] / 'config.cloud.yaml')
        config.input_dir = self.root / 'fixture'
        config.output_dir = self.root / 'focused'
        fixture = {
            'resources/AndroidManifest.xml': '<manifest package="demo.app" '
                'xmlns:android="http://schemas.android.com/apk/res/android">'
                '<application><provider android:name="vendor.lib.Provider"/></application></manifest>',
            'resources/res/xml/provider_paths.xml': '<paths/>',
            'resources/res/xml/network_security_config.xml': '<network-security-config/>',
            'resources/res/layout/web.xml': '<include layout="@layout/view"/>',
            'resources/res/layout/view.xml': '<view/>',
            'resources/res/layout/unused.xml': '<view/>',
            'resources/res/values/strings.xml': '<resources/>',
            'resources/assets/test.js': 'const asset = 1;',
            'sources/demo/app/Main.java': 'package demo.app; class Main { int id = R.layout.web; }',
            'sources/demo/app/R.java': 'package demo.app; class R {}',
            'sources/vendor/lib/Provider.java': 'package vendor.lib; class Provider {}',
            'sources/vendor/lib/Other.java': 'package vendor.lib; class Other {}',
        }
        for path, content in fixture.items():
            target = config.input_dir / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        cloud.freeze(config, config.output_dir)
        plan, units = load_plan(config.output_dir / 'full-plan')
        excluded = {'resources/res/layout/unused.xml', 'sources/demo/app/R.java',
                    'sources/vendor/lib/Other.java'}
        self.assertEqual({path for unit in units for path in primary_files(unit)}, set(fixture) - excluded)
        self.assertTrue(all(span['file'] not in excluded for unit in units for span in unit['segments']))
        self.assertEqual(plan['loaded_files'], len(fixture))
        self.assertEqual(plan['out_of_scope_files'], len(excluded))
        self.assertEqual(cloud.check_budget(config, plan, units)['planned_requests'], 8)
        config.models['teacher'].max_output_tokens = 100_000
        with self.assertRaisesRegex(ValueError, 'exceeds.*plan budget'):
            cloud.check_budget(config, plan, units)
        config.models['teacher'].service_tier = 'default'
        with self.assertRaisesRegex(ValueError, 'requires GPT-6 Luna Flex'):
            cloud.check_budget(config, plan, units)
