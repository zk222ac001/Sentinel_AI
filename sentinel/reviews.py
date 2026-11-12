"""Local, manual triage kept separate from scanner evidence."""
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone

STATUSES = ('Open', 'In review', 'Accepted risk', 'False positive', 'Resolved (manual)')

class ReviewStore:
    def __init__(self, db):
        self.db = db
        with closing(sqlite3.connect(db)) as conn, conn:
            conn.execute('CREATE TABLE IF NOT EXISTS reviews (scan TEXT, finding TEXT, status TEXT, updated TEXT, PRIMARY KEY(scan,finding))')
            conn.execute('CREATE TABLE IF NOT EXISTS review_events (scan TEXT, finding TEXT, status TEXT, updated TEXT)')

    def get(self, scan):
        with closing(sqlite3.connect(self.db)) as conn:
            return {fid: {'status': status, 'updated': updated} for fid, status, updated in conn.execute('SELECT finding,status,updated FROM reviews WHERE scan=?', (scan,))}

    def set(self, scan, finding, status):
        if status not in STATUSES:
            raise ValueError('Unknown review status.')
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute('BEGIN IMMEDIATE')
            row = conn.execute('SELECT body FROM scans WHERE id=?', (scan,)).fetchone()
            report = json.loads(row[0]) if row else None
            if not report or report['status'] == 'running' or not any(f['id'] == finding for f in report['findings']):
                raise ValueError('Select a finding from a finished scan.')
            old = conn.execute('SELECT status FROM reviews WHERE scan=? AND finding=?', (scan, finding)).fetchone()
            if (old[0] if old else 'Open') == status:
                return
            now = datetime.now(timezone.utc).isoformat()
            conn.execute('INSERT OR REPLACE INTO reviews VALUES (?,?,?,?)', (scan, finding, status, now))
            conn.execute('INSERT INTO review_events VALUES (?,?,?,?)', (scan, finding, status, now))

    def events(self, scan):
        with closing(sqlite3.connect(self.db)) as conn:
            return [{'finding': f, 'status': s, 'updated': t} for f,s,t in conn.execute('SELECT finding,status,updated FROM review_events WHERE scan=? ORDER BY rowid DESC', (scan,))]
