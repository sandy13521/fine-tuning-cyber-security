from contextlib import nullcontext
import hashlib
import io
import json
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
import httpx
from cyber_scan.ingest.apk import download_apk, decompile

class ApkTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,'w') as z:z.writestr('AndroidManifest.xml','fixture')
        self.raw=stream.getvalue()
        self.apk=self.root/'app.apk'

    def test_download_provenance_and_checksum(self):
        with patch('cyber_scan.ingest.apk.httpx.stream',return_value=nullcontext(httpx.Response(200,content=self.raw,request=httpx.Request('GET','https://example.test/app.apk')))):
            checksum=download_apk('https://example.test/app.apk',self.apk,hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(json.loads(self.apk.with_suffix('.download.json').read_text())['sha256'],checksum)
        self.assertEqual(self.apk.read_bytes(),self.raw)
        with self.assertRaises(ValueError):download_apk('https://example.test/app.apk',self.apk)

    def test_bad_checksum_leaves_no_apk(self):
        with patch('cyber_scan.ingest.apk.httpx.stream',return_value=nullcontext(httpx.Response(200,content=self.raw,request=httpx.Request('GET','https://example.test/app.apk')))):
            with self.assertRaises(ValueError):download_apk('https://example.test/app.apk',self.apk,'bad')
        self.assertFalse(self.apk.exists())
        self.assertFalse(self.apk.with_suffix('.part').exists())

    def test_decompile_command_and_record(self):
        self.apk.write_bytes(self.raw)
        output=self.root/'result'
        with patch('cyber_scan.ingest.apk.subprocess.run',side_effect=[subprocess.CompletedProcess([],0,'test-version'),subprocess.CompletedProcess([],0)]) as run:
            destination=decompile(self.apk,output)
        self.assertEqual(destination,output/'decompiled')
        self.assertEqual(json.loads((output/'decompile.json').read_text())['jadx_version'],'test-version')
        self.assertEqual(run.call_args.args[0][0],'jadx')
        self.assertFalse(run.call_args.kwargs.get('shell',False))

    def test_partial_failure_recorded(self):
        self.apk.write_bytes(self.raw)
        output=self.root/'result'
        with patch('cyber_scan.ingest.apk.subprocess.run',side_effect=[subprocess.CompletedProcess([],0,'test-version'),subprocess.CompletedProcess([],1)]):
            with self.assertRaises(ValueError):decompile(self.apk,output)
        self.assertEqual(json.loads((output/'decompile.json').read_text())['status'],'partial_or_failed')

    def test_timeout_recorded(self):
        self.apk.write_bytes(self.raw)
        output=self.root/'timeout'
        with patch('cyber_scan.ingest.apk.subprocess.run',side_effect=[subprocess.CompletedProcess([],0,'test-version'),subprocess.TimeoutExpired('jadx',1)]):
            with self.assertRaises(ValueError):decompile(self.apk,output)
        self.assertEqual(json.loads((output/'decompile.json').read_text())['status'],'timeout')

    def test_download_size_limit(self):
        with patch('cyber_scan.ingest.apk.httpx.stream',return_value=nullcontext(httpx.Response(200,content=self.raw,request=httpx.Request('GET','https://example.test/app.apk')))):
            with self.assertRaisesRegex(ValueError,'size limit'):download_apk('https://example.test/app.apk',self.apk,max_bytes=1)
        self.assertFalse(self.apk.exists())
