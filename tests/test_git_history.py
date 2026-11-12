"""Real local Git fixtures; no credentials, remotes or internet required."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch
from sentinel.core import Engine
from sentinel.git_history import git_read, HistoryCancelled, HistoryLimit


@unittest.skipUnless(shutil.which('git'), 'Git unavailable')
class GitHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / 'repo'
        self.root.mkdir()
        self.engine = Engine(self.base/'state')
        self.git('init', '-b', 'main')
        self.git('config', 'user.email', 'synthetic@example.invalid')
        self.git('config', 'user.name', 'Synthetic Test')
    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.root), *args],capture_output=True,check=True).stdout
    def commit(self, text=None):
        if text is not None:
            (self.root/'sample.env').write_text(text)
        self.git('add', '-A')
        self.git('commit', '--allow-empty', '-m', 'Synthetic test commit')
    def scan(self, root=None):
        self.engine.start(root or self.root, mode='git_history')
        self.engine.worker.join(20)
        self.assertFalse(self.engine.worker.is_alive())
        return self.engine.history()[0]
    def test_deleted_secret_found_and_redacted(self):
        value = 'SYNTHETIC_HISTORY_ONLY_123456'
        self.commit('password='+value)
        old = self.git('rev-parse', 'HEAD').decode().strip()
        (self.root/'sample.env').unlink()
        self.commit()
        report = self.scan()
        self.assertEqual(report['status'], 'completed')
        self.assertEqual(len(report['findings']), 1)
        finding = report['findings'][0]
        self.assertEqual(finding['commit'], old)
        self.assertEqual(finding['path'], 'sample.env')
        self.assertEqual(finding['exposure'], 'local_history_only')
        self.assertNotIn(value, json.dumps(report))
        self.assertNotIn(value.encode(), self.engine.db.read_bytes())
    def test_duplicate_blobs_scanned_once(self):
        self.commit('password=SYNTHETIC_HISTORY_123456')
        self.commit()
        report = self.scan()
        self.assertEqual(report['history']['commits_completed'], 2)
        self.assertEqual(report['scanned'], 1)
        self.assertEqual(len(report['findings']), 1)
    def test_other_branch_is_not_claimed_as_scanned(self):
        self.commit('safe=true')
        self.git('checkout', '-b', 'other')
        self.commit('password=SYNTHETIC_OTHER_BRANCH_123')
        self.git('checkout', 'main')
        report = self.scan()
        self.assertEqual(report['findings'], [])
        self.assertEqual(report['history']['ref'], 'HEAD')
    def test_commit_limit_partial(self):
        self.commit('safe=true')
        self.commit()
        with patch('sentinel.git_history.MAX_COMMITS', 1):
            report = self.scan()
        self.assertEqual(report['status'], 'partial')
        self.assertEqual(report['history']['commits_completed'], 1)
    def test_shallow_history_is_partial(self):
        self.commit('safe=true')
        self.commit('safe=false')
        target = self.base/'shallow'
        subprocess.run(['git','clone','--depth=1',self.root.as_uri(),str(target)],capture_output=True,check=True)
        report = self.scan(target)
        self.assertTrue(report['history']['shallow'])
        self.assertEqual(report['status'], 'partial')
    def test_symlink_blob_not_read(self):
        try:
            (self.root/'secret.env').symlink_to('../outside.env')
        except OSError as error:
            if getattr(error, "winerror", None) == 1314:
                self.skipTest("Windows symlink creation privilege unavailable")
            raise
        self.commit()
        report = self.scan()
        self.assertEqual(report['scanned'], 0)
        self.assertEqual(report['skipped']['git_symlink_or_submodule'], 1)
    def test_subfolder_and_empty_repository_fail(self):
        self.assertEqual(self.scan()['status'], 'failed')
        self.commit('safe=true')
        nested = self.root/'nested'
        nested.mkdir()
        self.assertEqual(self.scan(nested)['status'], 'failed')
    def test_git_output_bounded(self):
        self.commit('safe=true')
        with self.assertRaises(HistoryLimit):
            git_read(self.root, ['rev-parse','HEAD'], threading.Event(), max_bytes=2)
    def test_git_cancelled(self):
        self.commit('safe=true')
        cancel = threading.Event()
        cancel.set()
        with self.assertRaises(HistoryCancelled):
            git_read(self.root, ['rev-parse','HEAD'], cancel)
    def test_blob_limit_partial(self):
        self.commit('safe=true')
        with patch('sentinel.git_history.MAX_BLOBS', 0):
            self.assertEqual(self.scan()['status'], 'partial')
    def test_external_diff_and_filters_not_executed(self):
        marker = self.base/'EXECUTED'
        script = self.base/'bad.sh'
        script.write_text('#!/bin/sh\ntouch "'+str(marker)+'"\n')
        script.chmod(0o700)
        self.commit('safe=true')
        (self.root/'.gitattributes').write_text('*.env diff=evil filter=evil\n')
        self.git('add','.gitattributes')
        self.git('commit','-m','Attributes fixture')
        self.git('config','diff.evil.textconv',str(script))
        self.git('config','filter.evil.smudge',str(script))
        self.git('config','core.fsmonitor',str(script))
        self.assertEqual(self.scan()['status'], 'completed')
        self.assertFalse(marker.exists())
