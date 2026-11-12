import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from sentinel.core import Engine, detect, report_html
from sentinel.gitleaks import Gitleaks

class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name)
        self.root=self.base/'scope'
        self.root.mkdir()
        self.engine=Engine(self.base/'data')
    def scan(self,**kwargs):
        self.engine.start(self.root,**kwargs)
        self.engine.worker.join(10)
        self.assertFalse(self.engine.worker.is_alive())
        return self.engine.history()[0]
    def test_redaction_persistence_and_reports(self):
        secret='SYNTHETIC_SECRET_NEVER_PERSIST_456'
        (self.root/'example.env').write_text('api_key='+secret)
        result=self.scan()
        self.assertEqual(len(result['findings']),1)
        for output in [json.dumps(result),report_html(result),self.engine.db.read_bytes().decode('latin1')]:
            self.assertNotIn(secret,output)
        self.assertEqual(result['findings'][0]['validity'],'not_checked')
    def test_symlink_outside_scope(self):
        outside=self.base/'outside.env'
        outside.write_text('password=OUTSIDE_SECRET_12345')
        try:
            (self.root/'link.env').symlink_to(outside)
        except OSError as error:
            if getattr(error, "winerror", None) == 1314:
                self.skipTest("Windows symlink creation privilege unavailable")
            raise
        report=self.scan()
        self.assertEqual(report['scanned'],0)
        self.assertEqual(report['skipped']['symlink'],1)
        self.assertEqual(report['status'],'partial')
    def test_binary_and_large(self):
        (self.root/'binary.txt').write_bytes(b'\0password=SYNTHETIC_12345')
        (self.root/'large.txt').write_bytes(b'a'*(1024*1024+1))
        report=self.scan()
        self.assertEqual(report['scanned'],0)
        self.assertEqual(sum(report['skipped'].values()),2)
    def test_report_escapes_html(self):
        self.assertNotIn('<script>',report_html({'path':'<script>alert(1)</script>'}))
    def test_missing_gitleaks_is_failure(self):
        with patch('sentinel.gitleaks.shutil.which',return_value=None):
            self.assertEqual(self.scan(use_gitleaks=True)['status'],'failed')
    def test_gitleaks_discards_untrusted_fields(self):
        from subprocess import CompletedProcess
        adapter=object.__new__(Gitleaks)
        adapter.binary='/fake/gitleaks'
        raw=json.dumps([{'Secret':'RAW_SENTINEL_TOKEN','Match':'RAW_SENTINEL_TOKEN','StartLine':2}]).encode()
        with patch('sentinel.gitleaks.subprocess.run',return_value=CompletedProcess([],1,raw,b'')):
            result=adapter.scan('anything','file.env')
        self.assertNotIn('RAW_SENTINEL_TOKEN',json.dumps(result))
    def test_placeholder(self):
        self.assertEqual(detect('password=changeme',b'x','f'),[])
    def test_recovery(self):
        self.engine.save({'id':'interrupted','status':'running','limitations':[]})
        self.assertEqual(Engine(self.engine.data).history()[0]['status'],'partial')
    def test_cancellation(self):
        entered=threading.Event()
        release=threading.Event()
        (self.root/'test.env').write_text('password=synthetic_example_123')
        def slow(*args):
            entered.set()
            release.wait(5)
            return []
        with patch('sentinel.core.detect',side_effect=slow):
            self.engine.start(self.root)
            self.assertTrue(entered.wait(2))
            self.engine.cancel()
            release.set()
            self.engine.worker.join(5)
        self.assertEqual(self.engine.history()[0]['status'],'cancelled')
    def test_fingerprint_keyed(self):
        text='password=synthetic_example_123'
        a=detect(text,b'a','f')[0]['fingerprint']
        self.assertEqual(a,detect(text,b'a','f')[0]['fingerprint'])
        self.assertNotEqual(a,detect(text,b'b','f')[0]['fingerprint'])
if __name__=='__main__':
    unittest.main()
