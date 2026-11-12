"""Synthetic UI smoke test; skipped when optional UI dependencies are absent."""
import importlib.util
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch


@unittest.skipUnless(importlib.util.find_spec('streamlit'), 'Streamlit not installed')
class DashboardTests(unittest.TestCase):
    def test_demo_scan(self):
        from streamlit.testing.v1 import AppTest
        from streamlit import cache_resource
        with tempfile.TemporaryDirectory() as data:
            with patch.dict(os.environ, {'SENTINEL_DATA_DIR': data}):
                cache_resource.clear()
                try:
                    app = AppTest.from_file(str(Path(__file__).resolve().parents[1]/'app.py')).run(timeout=20)
                    self.assertFalse(app.exception)
                    app.checkbox[2].check().run()
                    app.button[0].click().run()
                    deadline = time.monotonic()+10
                    while time.monotonic()<deadline:
                        app.run()
                        if len(app.metric)==3 and app.metric[2].value != 'RUNNING':
                            break
                        time.sleep(.05)
                    self.assertFalse(app.exception)
                    self.assertEqual(app.metric[1].value, '2')
                    self.assertEqual(app.metric[2].value, 'COMPLETED')
                finally:
                    cache_resource.clear()
