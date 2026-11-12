import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch
from sentinel.folder_picker import choose_folder, FolderPickerError


class FolderPickerTests(unittest.TestCase):
    def test_selection_uses_isolated_process_and_preserves_unicode(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp)/'Folder with spaces æøå'
            folder.mkdir()
            with patch('sentinel.folder_picker.subprocess.run',return_value=Mock(returncode=0,stdout=json.dumps(str(folder)).encode())) as run:
                self.assertEqual(choose_folder(tmp),str(folder))
            self.assertEqual(run.call_args.args[0][1],'-I')
            self.assertEqual(run.call_args.kwargs['timeout'],60)
            self.assertNotIn('shell',run.call_args.kwargs)
    def test_cancel_returns_none(self):
        with patch('sentinel.folder_picker.subprocess.run',return_value=Mock(returncode=0,stdout=b'""')):
            self.assertIsNone(choose_folder())
    def test_timeout_and_missing_desktop(self):
        for error in [subprocess.TimeoutExpired('picker',60),OSError('private details')]:
            with patch('sentinel.folder_picker.subprocess.run',side_effect=error):
                with self.assertRaises(FolderPickerError) as raised: choose_folder()
                self.assertNotIn('private details',str(raised.exception))
        with patch('sentinel.folder_picker.subprocess.run',return_value=Mock(returncode=1)):
            with self.assertRaises(FolderPickerError): choose_folder()
    def test_invalid_responses_rejected(self):
        for value in [b'not json',b'null',b'{}',b'"relative/path"',b'"bad\\u0000path"']:
            with patch('sentinel.folder_picker.subprocess.run',return_value=Mock(returncode=0,stdout=value)):
                with self.assertRaises(FolderPickerError): choose_folder()
