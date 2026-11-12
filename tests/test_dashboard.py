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
                    app.radio(key='navigation').set_value('New scan').run()
                    app.checkbox(key='authorize').check().run()
                    app.button(key='start_scan').click().run()
                    deadline = time.monotonic()+10
                    while time.monotonic()<deadline:
                        app.run()
                        if len(app.metric)==3 and app.metric[2].value != 'RUNNING':
                            break
                        time.sleep(.05)
                    self.assertFalse(app.exception)
                    self.assertEqual(app.metric[1].value, '2')
                    self.assertEqual(app.metric[2].value, 'COMPLETED')
                    app.text_input(key='finding_search').input('no-match-expected').run()
                    self.assertIn('No findings match', app.info[0].value)
                    app.text_input(key='finding_search').input('').run()
                    decision=next(x for x in app.selectbox if x.label=='Manual review decision')
                    decision.select('In review').run()
                    app.button(key='save_review').click().run()
                    app.selectbox(key='review_filter').select('In review').run()
                    self.assertIn('1 of 2', next(x.value for x in app.caption if 'of 2 candidates' in x.value))
                    app.radio(key='navigation').set_value('Reports').run()
                    self.assertFalse(app.exception)
                    self.assertTrue(app.toggle(key='minimize_export').value)
                    self.assertEqual(len(app.get('download_button')),2)
                    app.radio(key='navigation').set_value('Settings').run()
                    self.assertFalse(app.exception)

                finally:
                    cache_resource.clear()
