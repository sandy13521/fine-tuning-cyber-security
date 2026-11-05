import json
import os
import tempfile
import unittest
from pathlib import Path
from cyber_scan.config import AppConfig, load_config
from cyber_scan.ingest.pipeline import ingest

class IngestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / 'input'
        self.source.mkdir()
        (self.source / 'AndroidManifest.xml').write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="demo"><application><activity android:name=".Main" /></application></manifest>')
        (self.source / 'Main.java').write_text('package demo;\nclass Main { Helper helper; }\n')
        (self.source / 'Helper.java').write_text('package demo;\nclass Helper {}\n')
        self.config = AppConfig(input_dir=self.source, output_dir=self.root / 'runs')

    def test_reproducibility_and_context(self):
        target, coverage = ingest(self.config)
        first = {p.name:p.read_bytes() for p in target.iterdir()}
        again, _ = ingest(self.config)
        self.assertEqual(target, again)
        self.assertEqual(first, {p.name:p.read_bytes() for p in again.iterdir()})
        bundles = [json.loads(line) for line in (target/'bundles.jsonl').read_text().splitlines()]
        main = next(b for b in bundles if b['primary']=='Main.java')
        self.assertIn('Helper.java', main['files'])
        self.assertIn('AndroidManifest.xml', main['files'])
        self.assertIn('1: package demo;', main['content'])
        self.assertEqual(coverage['bundled_unique_files'], 3)
        self.assertNotIn('{http://schemas.android.com/apk/res/android}exported', json.loads((target/'manifest.json').read_text())[0]['components'][0]['attributes'])

    def test_changes_have_new_identity(self):
        first,_ = ingest(self.config)
        (self.source/'Helper.java').write_text('class Changed {}')
        second,_ = ingest(self.config)
        self.assertNotEqual(first,second)
        self.config.context_char_budget = 0
        third,_ = ingest(self.config)
        self.assertNotEqual(second,third)

    def test_skips_and_parse_errors(self):
        (self.source/'binary.java').write_bytes(b'\x00\xff')
        (self.source/'huge.java').write_text('a'*3000)
        (self.source/'bad.xml').write_text('<broken')
        (self.source/'out.java').symlink_to('/etc/passwd')
        (self.source/'linked').symlink_to(self.root, target_is_directory=True)
        self.config.max_file_bytes = 2000
        _,coverage = ingest(self.config)
        skipped={i['path']:i['reason'] for i in coverage['skipped']}
        self.assertEqual(skipped['huge.java'],'file_size_limit')
        self.assertEqual(skipped['out.java'],'symlink')
        self.assertEqual(skipped['linked'],'symlink_directory')
        self.assertIn('binary.java',skipped)
        self.assertTrue(any(w.get('path')=='bad.xml' for w in coverage['warnings']))

    def test_no_truncation(self):
        (self.source/'large.java').write_text('x'*400)
        self.config.bundle_token_budget = 256
        target,coverage = ingest(self.config)
        self.assertTrue(any(i['path']=='large.java' for i in coverage['uncovered']))
        for line in (target/'bundles.jsonl').read_text().splitlines():
            self.assertLessEqual(json.loads(line)['tokens_or_estimate'],256)

    def test_no_output_inside_source(self):
        self.config.output_dir=self.source/'runs'
        with self.assertRaises(ValueError): ingest(self.config)

    def test_invalid_manifest_kept_as_source(self):
        (self.source/'AndroidManifest.xml').write_text('<broken')
        target,coverage=ingest(self.config)
        self.assertTrue(any(w['reason']=='manifest_parse_error' for w in coverage['warnings']))
        self.assertIn('AndroidManifest.xml',(target/'bundles.jsonl').read_text())

    def test_config_paths_relative_to_config(self):
        path=self.root/'test.yaml'
        path.write_text('input_dir: input\noutput_dir: runs\n')
        config=load_config(path)
        self.assertEqual(config.input_dir,self.source)
        path.write_text('input_dir: input\nunknown: true\n')
        with self.assertRaises(ValueError): load_config(path)

    def test_partial_decompile_warning_propagated(self):
        (self.root/'decompile.json').write_text('{"status":"partial_or_failed", "apk_sha256":"test"}')
        target,coverage=ingest(self.config)
        self.assertTrue(any(w['reason']=='partial_decompilation' for w in coverage['warnings']))
        self.assertEqual(json.loads((target/'metadata.json').read_text())['decompilation']['apk_sha256'],'test')
