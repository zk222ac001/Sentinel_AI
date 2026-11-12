import copy
import tempfile
import unittest
from pathlib import Path
from sentinel.core import Engine
from sentinel.reviews import ReviewStore
from sentinel.reporting import export_report, report_html

class ReviewReportTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.engine=Engine(Path(self.temp.name)/'state')
        self.report={'id':'scan','status':'completed','scope':'PRIVATE_PATH','started':'2026-01-01','scanned':1,'mode':'files','limitations':['<script>alert(1)</script>'], 'findings':[{'id':'secret-id','path':'<script>PRIVATE_PATH</script>','line':2,'rule':'credential-assignment','severity':'High','fingerprint':'PRIVATE_FINGERPRINT','evidence':'[REDACTED]'}], 'remote':{'url':'PRIVATE_URL'}}
        self.engine.save(self.report)
        self.store=ReviewStore(self.engine.db)
    def test_review_persists_without_changing_evidence(self):
        before=copy.deepcopy(self.engine.history())
        self.store.set('scan','secret-id','In review')
        self.store.set('scan','secret-id','In review')
        self.assertEqual(ReviewStore(self.engine.db).get('scan')['secret-id']['status'],'In review')
        self.assertEqual(len(self.store.events('scan')),1)
        self.assertEqual(before,self.engine.history())
    def test_invalid_review_and_running_scan_rejected(self):
        for args in [('scan','secret-id','bad'),('missing','secret-id','In review'),('scan','bad','In review')]:
            with self.assertRaises(ValueError): self.store.set(*args)
        self.report['status']='running'; self.engine.save(self.report)
        with self.assertRaises(ValueError): self.store.set('scan','secret-id','In review')
    def test_minimized_export_whitelist_and_no_mutation(self):
        before=copy.deepcopy(self.report)
        output=export_report(self.report,{'secret-id':{'status':'In review'}},True)
        rendered=report_html(output)
        for text in ['PRIVATE_PATH','PRIVATE_FINGERPRINT','PRIVATE_URL','secret-id','alert(1)']:
            self.assertNotIn(text,rendered)
        self.assertEqual(output['findings'][0]['review'],'In review')
        self.assertEqual(before,self.report)
    def test_full_report_escapes_untrusted_content(self):
        output=report_html(export_report(self.report))
        self.assertNotIn('<script>',output)
        self.assertIn('&lt;script&gt;',output)
        self.assertIn('PRIVATE_PATH',output)
