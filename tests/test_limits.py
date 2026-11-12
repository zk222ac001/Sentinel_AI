"""Regression checks for bounded traversal and private exports."""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from sentinel.core import Engine


class LimitsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'scope'
        self.root.mkdir()
        self.engine = Engine(self.base / 'state')

    def scan(self):
        self.engine.start(self.root)
        self.engine.worker.join(10)
        self.assertFalse(self.engine.worker.is_alive())
        return self.engine.history()[0]

    def test_nested_limit_propagates_to_scan(self):
        nested = self.root / 'nested'
        nested.mkdir()
        for name in ('a.env', 'b.env'):
            (nested / name).write_text('password=SYNTHETIC_VALUE_12345')
        with patch('sentinel.core.MAX_FILES', 1):
            report = self.scan()
        self.assertEqual(report['scanned'], 1)
        self.assertEqual(report['status'], 'partial')
        self.assertTrue(any('limit reached' in x for x in report['limitations']))
        self.assertNotIn('unreadable_or_encoding', report['skipped'])

    def test_global_findings_capped(self):
        (self.root / 'a.env').write_text('\n'.join('password=SYNTHETIC_VALUE_'+str(i) for i in range(10)))
        with patch('sentinel.core.MAX_FINDINGS', 3):
            report = self.scan()
        self.assertEqual(len(report['findings']), 3)
        self.assertEqual(report['status'], 'partial')

    def test_per_file_limit_is_not_clean_completion(self):
        (self.root / 'a.env').write_text('\n'.join('password=SYNTHETIC_VALUE_'+str(i) for i in range(1001)))
        report = self.scan()
        self.assertEqual(len(report['findings']), 1000)
        self.assertEqual(report['status'], 'partial')

    def test_skipped_details_bounded(self):
        for i in range(5):
            (self.root / f'{i}.zip').write_text('not inspected')
        with patch('sentinel.core.MAX_SKIP_DETAILS', 2):
            report = self.scan()
        self.assertEqual(report['skipped'], {'unsupported_type': 5})
        self.assertEqual(len(report['skipped_details']), 2)
        self.assertEqual(report['skipped_details_omitted'], 3)
        self.assertTrue(all(not Path(x['path']).is_absolute() for x in report['skipped_details']))

    def test_state_root_rejected(self):
        with self.assertRaises(ValueError):
            self.engine.start(self.engine.data)
        child = self.engine.data / 'nested'
        child.mkdir()
        with self.assertRaises(ValueError):
            self.engine.start(child)

    def test_symlink_loop_is_skipped(self):
        (self.root / 'loop').symlink_to('loop')
        report = self.scan()
        self.assertEqual(report['skipped']['symlink'], 1)
        self.assertEqual(report['status'], 'partial')

    def test_cli_exports_private_under_permissive_umask(self):
        (self.root / 'demo.env').write_text('password=SYNTHETIC_VALUE_12345')
        prefix = self.base / 'audit'
        command = [sys.executable, '-m', 'sentinel', str(self.root), '--data', str(self.base/'cli-state'), '--output', str(prefix)]
        # Child inherits a permissive umask; exclusive open must set 0600 itself.
        old = os.umask(0)
        try:
            result = subprocess.run(command, capture_output=True, timeout=10)
        finally:
            os.umask(old)
        self.assertEqual(result.returncode, 0, result.stderr)
        for suffix in ('.json', '.html'):
            self.assertEqual(stat.S_IMODE(Path(str(prefix)+suffix).stat().st_mode), 0o600)
        before = Path(str(prefix)+'.json').read_bytes()
        repeat = subprocess.run(command, capture_output=True, timeout=10)
        self.assertNotEqual(repeat.returncode, 0)
        self.assertEqual(Path(str(prefix)+'.json').read_bytes(), before)
