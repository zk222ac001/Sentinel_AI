"""Executed on Windows CI, not mocked platform flags on Linux."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from sentinel.core import Engine


@unittest.skipUnless(os.name == 'nt', 'Native Win32 handle tests')
class WindowsFilesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base/'scope'
        self.root.mkdir()
        self.engine = Engine(self.base/'state')

    def scan(self):
        self.engine.start(self.root)
        self.engine.worker.join(10)
        self.assertFalse(self.engine.worker.is_alive())
        return self.engine.history()[0]

    def test_unicode_and_spaces(self):
        folder = self.root/'Zuhair æøå projects'
        folder.mkdir()
        (folder/'settings.env').write_text('password=SYNTHETIC_WINDOWS_VALUE_12345',encoding='utf-8')
        result = self.scan()
        self.assertEqual(result['status'],'completed')
        self.assertEqual(len(result['findings']),1)
        self.assertEqual(result['filesystem_backend'],'windows-win32-handles')

    def test_junction_not_followed(self):
        target = self.base/'outside'
        target.mkdir()
        (target/'private.env').write_text('password=SYNTHETIC_OUTSIDE_12345')
        link = self.root/'junction'
        subprocess.run(['cmd.exe','/d','/c','mklink','/J',str(link),str(target)],capture_output=True,check=True)
        result = self.scan()
        self.assertEqual(result['findings'],[])
        self.assertEqual(result['status'],'partial')
        self.assertEqual(result['skipped']['reparse_or_placeholder'],1)
        self.assertTrue((target/'private.env').exists())

    def test_direct_open_outside_scope_rejected(self):
        from sentinel.windows_files import checked_file, UnsafeEntry
        outside = self.base/'outside.env'
        outside.write_text('password=SYNTHETIC_OUTSIDE_12345')
        with self.assertRaises(UnsafeEntry):
            with checked_file(outside,self.root):
                self.fail('Outside scope handle must not be yielded')

    def test_directory_cannot_be_swapped_while_open(self):
        from sentinel.windows_files import checked_handle
        child=self.root/'child'
        child.mkdir()
        with checked_handle(child,self.root,directory=True):
            with self.assertRaises(OSError):
                child.rename(self.root/'replaced')
        child.rename(self.root/'released')
        self.assertTrue((self.root/'released').is_dir())

    def test_opened_junction_rejected(self):
        from sentinel.windows_files import checked_handle, UnsafeEntry
        target=self.base/'outside'
        target.mkdir()
        link=self.root/'junction'
        subprocess.run(['cmd.exe','/d','/c','mklink','/J',str(link),str(target)],capture_output=True,check=True)
        with self.assertRaises(UnsafeEntry):
            with checked_handle(link,self.root,directory=True):
                self.fail('Junction handle must not be yielded')
