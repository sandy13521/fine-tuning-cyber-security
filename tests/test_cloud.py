import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from cyber_scan.config import AppConfig
from cyber_scan.ingest.pipeline import ingest
from cyber_scan.scan.plan import build_plan, load_plan

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
        from cyber_scan.config import load_config
        config = load_config(Path(__file__).resolve().parents[1] / 'config.cloud.yaml')
        self.assertEqual(config.models['teacher'].model, 'gpt-4.1')
        self.assertEqual(config.models['teacher'].api_key_env, 'TEACHER_API_KEY')
        self.assertEqual(config.models['teacher'].token_parameter, 'max_completion_tokens')
