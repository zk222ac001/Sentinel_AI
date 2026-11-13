"""Real process-lock and migration tests, including crash recovery."""
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from sentinel.core import Engine
from sentinel.runtime import InstanceLock, InstanceInUse, open_engine, close_runtimes
from sentinel.storage import migrate, StorageError

ROOT=Path(__file__).resolve().parents[1]

class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(close_runtimes)
        self.data=Path(self.tmp.name)/'state'

    def child(self, code):
        return subprocess.run([sys.executable,'-c',code,str(self.data)],cwd=ROOT,capture_output=True,text=True,timeout=15)

    def test_second_process_rejected_without_recovering_live_scan(self):
        engine=open_engine(self.data)
        engine.save({'id':'active','status':'running','limitations':[]})
        result=self.child('from sentinel.runtime import open_engine; import sys; open_engine(sys.argv[1])')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('Another Sentinel instance',result.stderr)
        self.assertEqual(engine.history()[0]['status'],'running')
        self.assertIs(open_engine(self.data),engine)

    def test_cli_respects_dashboard_owner(self):
        open_engine(self.data)
        result=subprocess.run([sys.executable,'-m','sentinel','demo','--data',str(self.data)],cwd=ROOT,capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,2)
        self.assertIn('Another Sentinel instance',result.stderr)
        self.assertNotIn('Traceback',result.stderr)

    def test_os_releases_lock_after_crash_and_recovery_once(self):
        code="from sentinel.runtime import open_engine; import sys,os; e=open_engine(sys.argv[1]); e.save({'id':'crashed','status':'running','limitations':[]}); os._exit(7)"
        result=self.child(code)
        self.assertEqual(result.returncode,7)
        engine=open_engine(self.data)
        self.assertEqual(engine.history()[0]['status'],'partial')
        self.assertEqual(len(engine.history()[0]['limitations']),1)
        close_runtimes()
        self.assertEqual(len(open_engine(self.data).history()[0]['limitations']),1)

    def test_separate_data_folders_and_lock_reuse(self):
        with InstanceLock(self.data):
            with self.assertRaises(InstanceInUse): InstanceLock(self.data)
            with InstanceLock(Path(self.tmp.name)/'other'): pass
        with InstanceLock(self.data): pass
        self.assertTrue((self.data/'instance.lock').exists())

    def test_startup_failure_releases_ownership(self):
        self.data.mkdir()
        (self.data/'fingerprint.key').write_bytes(b'broken')
        with self.assertRaises(StorageError): open_engine(self.data)
        with InstanceLock(self.data): pass


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db=Path(self.tmp.name)/'scans.sqlite3'

    def test_legacy_upgrade_preserves_reports_and_reviews(self):
        with closing(sqlite3.connect(self.db)) as c,c:
            c.execute('CREATE TABLE scans (id TEXT PRIMARY KEY, body TEXT NOT NULL)')
            c.execute('INSERT INTO scans VALUES (?,?)',('one','original evidence'))
            c.execute('CREATE TABLE reviews (scan TEXT, finding TEXT, status TEXT, updated TEXT, PRIMARY KEY(scan,finding))')
            c.execute('INSERT INTO reviews VALUES (?,?,?,?)',('one','f','In review','date'))
        migrate(self.db); migrate(self.db)
        with closing(sqlite3.connect(self.db)) as c:
            self.assertEqual(c.execute('PRAGMA user_version').fetchone()[0],1)
            self.assertEqual(c.execute('SELECT body FROM scans').fetchone()[0],'original evidence')
            self.assertEqual(c.execute('SELECT status FROM reviews').fetchone()[0],'In review')

    def test_future_version_refused_without_rewriting(self):
        with closing(sqlite3.connect(self.db)) as c,c: c.execute('PRAGMA user_version=99')
        before=self.db.read_bytes()
        with self.assertRaises(StorageError): migrate(self.db)
        self.assertEqual(before,self.db.read_bytes())

    def test_incompatible_schema_rolls_back_created_tables(self):
        with closing(sqlite3.connect(self.db)) as c,c: c.execute('CREATE TABLE scans (unexpected TEXT)')
        with self.assertRaises(StorageError): migrate(self.db)
        with closing(sqlite3.connect(self.db)) as c:
            self.assertEqual(c.execute('PRAGMA user_version').fetchone()[0],0)
            self.assertFalse(c.execute("SELECT name FROM sqlite_master WHERE name='reviews'").fetchall())

    def test_corrupt_database_not_replaced(self):
        self.db.write_bytes(b'not a sqlite database')
        with self.assertRaises(sqlite3.DatabaseError): migrate(self.db)
        self.assertEqual(self.db.read_bytes(),b'not a sqlite database')

    def test_recovery_is_atomic_for_invalid_record(self):
        data=Path(self.tmp.name)/'data'
        engine=Engine(data)
        engine.save({'id':'valid','status':'running','limitations':[]})
        with closing(sqlite3.connect(engine.db)) as c,c:
            c.execute('INSERT INTO scans VALUES (?,?)',('bad','not JSON'))
        with self.assertRaises(StorageError): Engine(data)
        with closing(sqlite3.connect(engine.db)) as c:
            body=c.execute("SELECT body FROM scans WHERE id='valid'").fetchone()[0]
            self.assertEqual(json.loads(body)['status'],'running')

    def test_missing_key_is_not_silently_replaced(self):
        data=Path(self.tmp.name)/'data'
        engine=Engine(data)
        (data/'fingerprint.key').unlink()
        with self.assertRaises(StorageError): Engine(data)
        self.assertFalse((data/'fingerprint.key').exists())
