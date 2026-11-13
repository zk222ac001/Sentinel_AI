"""Shared audit engine with Windows and POSIX filesystem adapters."""
from contextlib import closing
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import sqlite3
import stat
import threading
import time
import uuid
from pathlib import Path
from .storage import migrate, StorageError

RULES = [
    ('github-token', re.compile(r'\bgh[pousr]_[A-Za-z0-9]{30,255}\b'), 'High'),
    ('aws-access-id', re.compile(r'\bAKIA[A-Z0-9]{16}\b'), 'Medium'),
    ('private-key', re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'), 'High'),
    ('credential-assignment', re.compile(r'''(?im)\b(?:api[_-]?key|password|secret|token)\s*[:=]\s*["']?([^\s"'#,;]{8,256})'''), 'Medium'),
]
EXTENSIONS = {'.py','.js','.ts','.json','.yaml','.yml','.toml','.ini','.txt','.log','.cfg','.conf','.sh','.env','.xml','.md'}
EXCLUDED = {'.git','.venv','venv','node_modules','__pycache__','.ssh','.aws','.gnupg','Library'}
MAX_BYTES = 1024 * 1024
MAX_FILES = 10000
MAX_ENTRIES = 50000
MAX_FINDINGS = 5000
MAX_SKIP_DETAILS = 500


class ScanLimitReached(Exception):
    """Control flow distinct from filesystem OSError/TimeoutError."""


def detect(text, key, path):
    findings = []
    for rule, pattern, severity in RULES:
        for match in pattern.finditer(text):
            value = match.group(1) if match.lastindex else match.group()
            if value.lower() in {'changeme','your_api_key','placeholder','example_password'}:
                continue
            fingerprint = hmac.new(key, value.encode(), hashlib.sha256).hexdigest()
            findings.append(dict(id=str(uuid.uuid4()), rule=rule, severity=severity,
                confidence='candidate', path=path, line=text.count('\n',0,match.start())+1,
                evidence='[REDACTED]', fingerprint=fingerprint,
                validity='not_checked', exposure='local_only', billing='unknown',
                remediation='Review the source locally. If genuine, rotate at the issuer, update consumers, and remove the stored copy.'))
            if len(findings) >= 1000:
                return findings
    return findings


from .reporting import report_html


class Engine:
    def __init__(self, data):
        self.data = Path(data).expanduser().resolve()
        self.data.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.data, 0o700)
        # MVP key is permission-protected locally, NOT in an OS keyring.
        keyfile = self.data / 'fingerprint.key'
        if not keyfile.exists() and (self.data/'scans.sqlite3').exists():
            raise StorageError('The fingerprint key is missing from existing audit storage. Restore the matching key and database backup; no replacement key was generated.')
        try:
            fd = os.open(keyfile, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
            with os.fdopen(fd,'wb') as f:
                f.write(secrets.token_bytes(32))
        except FileExistsError:
            pass
        self.key = keyfile.read_bytes()
        if len(self.key) != 32:
            raise StorageError('The local fingerprint key is invalid. Restore the matching key and database backup; it has not been regenerated.')
        self.db = self.data / 'scans.sqlite3'
        fd = os.open(self.db, os.O_CREAT|os.O_RDWR, 0o600)
        os.close(fd)
        self.lock = threading.Lock()
        self.cancel_event = threading.Event()
        self.worker = None
        migrate(self.db)
        with closing(sqlite3.connect(self.db)) as conn, conn:
            # A previous process may have ended while scanning.
            for sid, body in conn.execute('SELECT id,body FROM scans').fetchall():
                try:
                    report = json.loads(body)
                    if not isinstance(report, dict) or 'status' not in report or not isinstance(report.get('limitations'), list):
                        raise ValueError('Invalid scan record')
                except (ValueError, TypeError) as exc:
                    raise StorageError('A stored scan record is invalid. Keep a copy of the data folder and restore a known-good backup.') from exc
                if report['status'] == 'running':
                    report['status'] = 'partial'
                    report['limitations'].append('Previous process interrupted; start a new scan.')
                    conn.execute('UPDATE scans SET body=? WHERE id=?',(json.dumps(report),sid))

    def save(self, report):
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute('INSERT OR REPLACE INTO scans VALUES (?,?)',(report['id'],json.dumps(report)))

    def history(self):
        with closing(sqlite3.connect(self.db)) as conn, conn:
            return [json.loads(row[0]) for row in conn.execute('SELECT body FROM scans ORDER BY rowid DESC')]

    def start(self, root, use_gitleaks=False, mode="files", allow_network=False):
        if mode not in {"files", "git_history", "github"}:
            raise ValueError("Unknown scan mode.")
        if mode != "files" and use_gitleaks:
            raise ValueError("Gitleaks is only supported in file mode.")
        if os.name not in {'posix', 'nt'}:
            raise ValueError('Supported platforms: Windows, macOS and Linux.')
        if mode == "github":
            if not allow_network:
                raise ValueError("GitHub scanning requires explicit network authorization.")
            from .github_scan import validate_repository
            root = validate_repository(root)
        else:
            root = Path(root).expanduser().resolve(strict=True)
            if root == self.data or self.data in root.parents:
                raise ValueError('Application state cannot be scanned.')
            if not root.is_dir():
                raise ValueError('Choose a directory.')
        with self.lock:
            if self.worker and self.worker.is_alive():
                raise ValueError('A scan is already running.')
            self.cancel_event.clear()
            report = dict(id=str(uuid.uuid4()), scope=str(root), status='running', mode=mode,
                started=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()), scanned=0,
                considered=0, skipped={}, skipped_details=[], skipped_details_omitted=0, findings=[], engine='builtin-rules-v1',
                limitations=['Selected text files only; no Git history, permissions audit, billing or AI analysis.',
                              'Built-in rules are limited. Findings are candidates; zero findings does not establish security.'])
            self.save(report)
            self.worker = threading.Thread(target=self._run,args=(root,report,use_gitleaks),daemon=True)
            self.worker.start()
            return report['id']

    def cancel(self):
        self.cancel_event.set()

    def _run(self, root, report, use_gitleaks):
        started = time.monotonic()
        def skip(reason, path):
            if len(report['skipped_details']) < MAX_SKIP_DETAILS:
                report['skipped_details'].append(dict(path=path, reason=reason))
            else:
                report['skipped_details_omitted'] += 1
            report['skipped'][reason] = report['skipped'].get(reason,0)+1
        try:
            if report.get('mode') == 'github':
                from .github_scan import scan_github
                scan_github(root, report, self.key, self.cancel_event, self.save)
                return
            if report.get('mode') == 'git_history':
                from .git_history import scan_history
                scan_history(root, report, self.key, self.cancel_event, self.save)
                return
            if os.name == 'nt':
                from .windows_files import scan_windows
                scan_windows(root, report, self.key, self.cancel_event, self.save, self.data, use_gitleaks)
                return
            report['filesystem_backend'] = 'posix-directory-descriptors'
            from .gitleaks import Gitleaks
            scanner = Gitleaks() if use_gitleaks else None
            if scanner:
                report['engine'] += ' + ' + scanner.version
            rootfd = os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            def walk(fd, relative='', depth=0):
                if depth > 40:
                    skip('depth_limit', relative)
                    return
                # All opens are relative to an already opened directory descriptor.
                with os.scandir(fd) as entries:
                    for entry in entries:
                        if self.cancel_event.is_set():
                            return
                        if report['considered'] >= MAX_ENTRIES or report['scanned'] >= MAX_FILES or time.monotonic()-started > 120:
                            raise ScanLimitReached
                        report['considered'] += 1
                        name = entry.name
                        rel = str(Path(relative)/name)
                        if name in EXCLUDED or root/rel == self.data:
                            skip('excluded', rel)
                            continue
                        try:
                            info = entry.stat(follow_symlinks=False)
                            if stat.S_ISLNK(info.st_mode):
                                skip('symlink', rel)
                                continue
                            if stat.S_ISDIR(info.st_mode):
                                child = os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                                try:
                                    walk(child,rel,depth+1)
                                finally:
                                    os.close(child)
                                continue
                            if not stat.S_ISREG(info.st_mode):
                                skip('special_file', rel)
                                continue
                            if Path(name).suffix.lower() not in EXTENSIONS and not name.startswith('.env'):
                                skip('unsupported_type', rel)
                                continue
                            filefd = os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
                            with os.fdopen(filefd,'rb') as source:
                                before = os.fstat(source.fileno())
                                if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_BYTES:
                                    skip('size_or_type', rel)
                                    continue
                                raw = source.read(MAX_BYTES+1)
                                after = os.fstat(source.fileno())
                            if len(raw)>MAX_BYTES or (before.st_mtime_ns,before.st_size)!=(after.st_mtime_ns,after.st_size):
                                skip('changed_or_large', rel)
                                continue
                            if b'\0' in raw:
                                skip('binary', rel)
                                continue
                            text = raw.decode('utf-8')
                            found = detect(text,self.key,rel)
                            if scanner:
                                found += scanner.scan(text,rel)
                            remaining = MAX_FINDINGS - len(report['findings'])
                            report['findings'].extend(found[:remaining])
                            report['scanned'] += 1
                            if report['scanned'] % 20 == 0:
                                self.save(report)
                            if len(report['findings']) >= MAX_FINDINGS or len(found) >= 1000:
                                raise ScanLimitReached
                        except (OSError, UnicodeError):
                            skip('unreadable_or_encoding', rel)
            try:
                walk(rootfd)
            finally:
                os.close(rootfd)
            report['status'] = 'cancelled' if self.cancel_event.is_set() else ('partial' if report['skipped'] else 'completed')
        except ScanLimitReached:
            report['status'] = 'partial'
            report['limitations'].append('Resource, time or per-file finding limit reached; findings may be incomplete.')
        except Exception:
            report['status'] = 'failed'
            report['limitations'].append('Collector failed; check dependency availability. Raw exceptions are suppressed to avoid sensitive output.')
        finally:
            report['elapsed_seconds'] = round(time.monotonic()-started,2)
            self.save(report)
