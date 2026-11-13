"""Transactional, additive schema migration for local audit state."""
from contextlib import closing
import sqlite3

SCHEMA_VERSION = 1

class StorageError(RuntimeError):
    pass


def migrate(db):
    with closing(sqlite3.connect(db, timeout=10)) as conn, conn:
        conn.execute('BEGIN IMMEDIATE')
        version = conn.execute('PRAGMA user_version').fetchone()[0]
        if version > SCHEMA_VERSION:
            raise StorageError('This data was created by a newer Sentinel version. Update the app; do not downgrade this database.')
        if conn.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
            raise StorageError('The local database failed its integrity check. Keep a copy and restore a known-good backup.')
        conn.execute('CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, body TEXT NOT NULL)')
        conn.execute('CREATE TABLE IF NOT EXISTS reviews (scan TEXT, finding TEXT, status TEXT, updated TEXT, PRIMARY KEY(scan,finding))')
        conn.execute('CREATE TABLE IF NOT EXISTS review_events (scan TEXT, finding TEXT, status TEXT, updated TEXT)')
        expected = {'scans':['id','body'], 'reviews':['scan','finding','status','updated'], 'review_events':['scan','finding','status','updated']}
        for table, columns in expected.items():
            actual = [row[1] for row in conn.execute(f'PRAGMA table_info({table})')]
            if actual != columns:
                raise StorageError('The local database schema is incompatible. Keep a backup and use the matching app version.')
        conn.execute('CREATE INDEX IF NOT EXISTS review_events_scan ON review_events(scan)')
        conn.execute(f'PRAGMA user_version={SCHEMA_VERSION}')
