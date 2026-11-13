from sentinel.runtime import close_runtimes
"""Offline API contract fixtures. These tests never contact GitHub."""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch, MagicMock
from urllib.error import HTTPError
from sentinel.core import Engine
from sentinel.github_scan import GitHubClient, NoRedirect, RemoteError, RemoteLimit, validate_repository


class GitHubTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.engine=Engine(Path(self.temp.name)/'state')
        self.raw=b'password=SYNTHETIC_REMOTE_CREDENTIAL_12345'
        self.blob=hashlib.sha1(b'blob '+str(len(self.raw)).encode()+b'\0'+self.raw).hexdigest()
        self.sha='a'*40
        self.meta={'full_name':'owner/repo','private':False,'default_branch':'main'}
        self.commit={'sha':self.sha,'commit':{'tree':{'sha':'b'*40}}}
        self.entry={'path':'demo.env','mode':'100644','type':'blob','sha':self.blob,'size':len(self.raw)}
        self.tree={'truncated':False,'tree':[self.entry]}
        self.payload={'encoding':'base64','content':base64.b64encode(self.raw).decode()}
    def scan(self,responses=None):
        with patch('sentinel.github_scan.GitHubClient.get',side_effect=responses or [self.meta,self.commit,self.tree,self.payload]):
            self.engine.start('owner/repo',mode='github',allow_network=True)
            self.engine.worker.join(10)
        self.assertFalse(self.engine.worker.is_alive())
        return self.engine.history()[0]
    def test_requires_network_authorization(self):
        with patch('sentinel.github_scan.GitHubClient.get') as get:
            with self.assertRaises(ValueError):
                self.engine.start('owner/repo',mode='github')
        get.assert_not_called()
    def test_rejects_urls_and_path_injection(self):
        for value in ['https://github.com/owner/repo','owner/..','../repo','owner/repo?x=1','owner/repo/extra','owner/%2e%2e']:
            with self.assertRaises(ValueError): validate_repository(value)
    def test_public_snapshot_redacted_with_evidence(self):
        with patch.dict(os.environ,{'SENTINEL_GITHUB_TOKEN':'SYNTHETIC_CONNECTOR_TOKEN'}):
            report=self.scan()
        self.assertEqual(report['status'],'completed')
        finding=report['findings'][0]
        self.assertEqual(finding['exposure'],'public_repository_content')
        self.assertEqual(finding['commit'],self.sha)
        self.assertEqual(finding['validity'],'not_checked')
        self.assertEqual(finding['billing'],'unknown')
        self.assertIn('/blob/'+self.sha+'/',finding['evidence_url'])
        stored=self.engine.db.read_bytes()
        self.assertNotIn(self.raw,stored)
        self.assertNotIn(b'SYNTHETIC_CONNECTOR_TOKEN',stored)
    def test_private_is_not_public(self):
        self.meta['private']=True
        self.assertEqual(self.scan()['findings'][0]['exposure'],'private_repository_content')
    def test_truncated_tree_partial(self):
        self.tree['truncated']=True
        self.assertEqual(self.scan()['status'],'partial')
    def test_rate_limit_retains_partial_findings(self):
        extra=dict(self.entry,sha='c'*40,path='other.env')
        self.tree['tree'].append(extra)
        report=self.scan([self.meta,self.commit,self.tree,self.payload,RemoteError('Rate limited')])
        self.assertEqual(report['status'],'partial')
        self.assertEqual(len(report['findings']),1)
    def test_blob_integrity_failure(self):
        self.payload['content']=base64.b64encode(b'altered').decode()
        self.assertEqual(self.scan()['status'],'failed')
    def test_symlinks_skipped(self):
        self.entry['mode']='120000'
        report=self.scan([self.meta,self.commit,self.tree])
        self.assertEqual(report['scanned'],0)
        self.assertEqual(report['status'],'partial')
    def test_blob_cap(self):
        with patch('sentinel.github_scan.MAX_REMOTE_BLOBS',0):
            self.assertEqual(self.scan([self.meta,self.commit,self.tree])['status'],'partial')
    def test_identity_mismatch(self):
        self.meta['full_name']='other/repo'
        self.assertEqual(self.scan([self.meta])['status'],'failed')
    def test_redirects_rejected(self):
        self.assertIsNone(NoRedirect().redirect_request(None,None,302,'',{},'https://elsewhere.invalid'))
    def test_http_error_does_not_expose_response(self):
        client=GitHubClient('owner/repo',threading.Event())
        client.opener=MagicMock()
        client.opener.open.side_effect=HTTPError('https://api.github.com/',403,'SENSITIVE_ERROR',{},io.BytesIO(b'SENSITIVE_BODY'))
        with self.assertRaises(RemoteError) as caught: client.get()
        self.assertNotIn('SENSITIVE',str(caught.exception))
    def test_response_limit(self):
        client=GitHubClient('owner/repo',threading.Event())
        response=MagicMock()
        response.__enter__.return_value=response
        response.read.side_effect=[b'abcdef',b'']
        client.opener=MagicMock()
        client.opener.open.return_value=response
        with patch('sentinel.github_scan.MAX_RESPONSE',3):
            with self.assertRaises(RemoteLimit): client.get()
    def test_fixed_host_get_and_no_raw_token_in_url(self):
        with patch.dict(os.environ,{'SENTINEL_GITHUB_TOKEN':'SYNTHETIC_HEADER_ONLY'}):
            client=GitHubClient('owner/repo',threading.Event())
        response=MagicMock()
        response.__enter__.return_value=response
        response.read.side_effect=[b'{}',b'']
        client.opener=MagicMock()
        client.opener.open.return_value=response
        client.get()
        req=client.opener.open.call_args.args[0]
        self.assertEqual(req.full_url,'https://api.github.com/repos/owner/repo')
        self.assertEqual(req.get_method(),'GET')
        self.assertEqual(req.get_header('Authorization'),'Bearer SYNTHETIC_HEADER_ONLY')
    def test_cancelled_before_request(self):
        from sentinel.github_scan import RemoteCancelled
        cancel=threading.Event()
        cancel.set()
        client=GitHubClient('owner/repo',cancel)
        with patch.object(client.opener,'open') as opened:
            with self.assertRaises(RemoteCancelled): client.get()
        opened.assert_not_called()

    @unittest.skipUnless(__import__('importlib').util.find_spec('streamlit'), 'Streamlit unavailable')
    def test_dashboard_network_gate_and_scan(self):
        from streamlit.testing.v1 import AppTest
        from streamlit import cache_resource
        import time
        with patch.dict(os.environ,{'SENTINEL_DATA_DIR':str(Path(self.temp.name)/'ui-state')}):
            with patch('sentinel.github_scan.GitHubClient.get',side_effect=[self.meta,self.commit,self.tree,self.payload]):
                close_runtimes(); cache_resource.clear()
                try:
                    app=AppTest.from_file(str(Path(__file__).resolve().parents[1]/'app.py')).run(timeout=20)
                    app.radio(key='navigation').set_value('New scan').run()
                    app.selectbox(key='mode').select('github').run()
                    app.text_input(key='repository').input('owner/repo').run()
                    app.checkbox(key='authorize').check().run()
                    self.assertTrue(app.button(key='start_scan').disabled)
                    app.checkbox(key='network_authorize').check().run()
                    self.assertFalse(app.button(key='start_scan').disabled)
                    app.button(key='start_scan').click().run()
                    deadline=time.monotonic()+5
                    while time.monotonic()<deadline:
                        app.run()
                        if len(app.metric)==3 and app.metric[2].value!='RUNNING': break
                        time.sleep(.05)
                    self.assertFalse(app.exception)
                    self.assertEqual(app.metric[2].value,'COMPLETED')
                    self.assertEqual(app.metric[1].value,'1')
                finally:
                    close_runtimes(); cache_resource.clear()
