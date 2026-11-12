"""Opt-in, read-only snapshot audit of one explicitly selected GitHub repository."""
import base64
import hashlib
import json
import os
import re
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

REPOSITORY = re.compile(r'[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}')
SHA = re.compile(r'[0-9a-f]{40}')
MAX_RESPONSE = 4 * 1024 * 1024
MAX_REMOTE_BLOBS = 100


class RemoteError(Exception):
    pass


class RemoteCancelled(Exception):
    pass


class RemoteLimit(Exception):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_repository(value):
    if not isinstance(value, str) or not REPOSITORY.fullmatch(value) or value.split('/')[1] in {'.', '..'}:
        raise ValueError('Enter owner/repository, not a URL or filesystem path.')
    return value


class GitHubClient:
    def __init__(self, repository, cancel):
        self.repository = validate_repository(repository)
        self.cancel = cancel
        self.deadline = time.monotonic() + 120
        # Intentionally supplied connector token only; never a discovered token.
        self.token = os.environ.get('SENTINEL_GITHUB_TOKEN', '')
        self.opener = build_opener(ProxyHandler({}), NoRedirect())
        self.requests = 0

    def get(self, suffix=''):
        if self.cancel.is_set():
            raise RemoteCancelled
        if time.monotonic() >= self.deadline or self.requests >= MAX_REMOTE_BLOBS + 4:
            raise RemoteLimit('Network request or time limit reached.')
        # Only internally constructed relative API suffixes; never follow response URLs.
        if suffix and (not suffix.startswith('/') or '..' in suffix or '://' in suffix):
            raise RemoteError('Invalid API path.')
        url = 'https://api.github.com/repos/' + self.repository + suffix
        headers = {'Accept': 'application/vnd.github+json', 'User-Agent': 'Sentinel-AI-local-audit',
                   'X-GitHub-Api-Version': '2022-11-28', 'Accept-Encoding': 'identity'}
        if self.token:
            headers['Authorization'] = 'Bearer ' + self.token
        self.requests += 1
        try:
            request = Request(url, headers=headers, method='GET')
            with self.opener.open(request, timeout=10) as response:
                chunks = bytearray()
                while True:
                    if self.cancel.is_set():
                        raise RemoteCancelled
                    if time.monotonic() >= self.deadline:
                        raise RemoteLimit('Network time limit reached.')
                    chunk = response.read(65536)
                    if not chunk:
                        break
                    if len(chunks) + len(chunk) > MAX_RESPONSE:
                        raise RemoteLimit('API response size limit reached.')
                    chunks.extend(chunk)
            data = json.loads(chunks)
            if not isinstance(data, dict):
                raise RemoteError('Unexpected API response.')
            return data
        except HTTPError as error:
            code = error.code
            error.close()
            if code in (403, 429):
                raise RemoteError('GitHub denied access or rate-limited this scan; no retry was attempted.') from None
            raise RemoteError('GitHub request failed (HTTP '+str(code)+'); check repository access.') from None
        except (URLError, OSError, ValueError):
            raise RemoteError('GitHub connection or response failed; sensitive response details suppressed.') from None


def scan_github(repository, report, key, cancel, save):
    from .core import detect, MAX_BYTES, MAX_FINDINGS, MAX_SKIP_DETAILS
    client = GitHubClient(repository, cancel)
    report['engine'] = 'builtin-rules-v1 + github-default-branch-snapshot'
    report['remote'] = dict(repository=repository, commit=None, visibility='unknown',
                            observed_at=report['started'], requests=0, tree_truncated=False)
    report['limitations'] = [
        'One default-branch commit snapshot only; Git history, other refs, forks, issues and logs are not scanned.',
        'Repository visibility is observed metadata, not proof of credential validity or duration of public exposure.',
        'Each unique regular-file blob is scanned once with one representative path; built-in candidate rules only.',
        'Explicitly authorized HTTPS GET requests to api.github.com; no credential validation, writes or AI requests.',
    ]
    def skip(reason, path):
        report['skipped'][reason] = report['skipped'].get(reason, 0) + 1
        if len(report['skipped_details']) < MAX_SKIP_DETAILS:
            report['skipped_details'].append(dict(reason=reason, path=path))
        else:
            report['skipped_details_omitted'] += 1
    def oid(value):
        if not isinstance(value, str) or not SHA.fullmatch(value):
            raise RemoteError('Unexpected Git object identifier.')
        return value
    try:
        meta = client.get()
        if str(meta.get('full_name', '')).lower() != repository.lower() or type(meta.get('private')) is not bool:
            raise RemoteError('Repository identity or visibility could not be verified.')
        visibility = 'private' if meta['private'] else 'public'
        report['remote']['visibility'] = visibility
        branch = meta.get('default_branch')
        if not isinstance(branch, str) or not branch:
            raise RemoteError('Default branch unavailable.')
        commit = client.get('/commits/' + quote(branch, safe=''))
        sha = oid(commit['sha'])
        tree_sha = oid(commit['commit']['tree']['sha'])
        report['remote']['commit'] = sha
        tree = client.get('/git/trees/' + tree_sha + '?recursive=1')
        if type(tree.get('truncated')) is not bool or not isinstance(tree.get('tree'), list):
            raise RemoteError('Unexpected tree response.')
        report['remote']['tree_truncated'] = tree['truncated']
        seen = set()
        for entry in tree['tree']:
            if cancel.is_set():
                raise RemoteCancelled
            report['considered'] += 1
            path = entry['path']
            if not isinstance(path, str):
                raise RemoteError('Unexpected path metadata.')
            if entry.get('type') == 'tree':
                continue
            if entry.get('type') != 'blob' or entry.get('mode') not in ('100644', '100755'):
                skip('remote_symlink_or_submodule', path)
                continue
            blob = oid(entry['sha'])
            if blob in seen:
                continue
            if len(seen) >= MAX_REMOTE_BLOBS:
                raise RemoteLimit('Remote blob limit reached.')
            seen.add(blob)
            size = entry.get('size')
            if type(size) is not int or size < 0:
                raise RemoteError('Unexpected size metadata.')
            if size > MAX_BYTES:
                skip('size_limit', path)
                continue
            payload = client.get('/git/blobs/' + blob)
            if payload.get('encoding') != 'base64' or not isinstance(payload.get('content'), str):
                raise RemoteError('Unsupported blob encoding.')
            raw = base64.b64decode(''.join(payload['content'].split()), validate=True)
            if len(raw) > MAX_BYTES:
                raise RemoteLimit('Blob size limit reached.')
            actual = hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
            if actual != blob:
                raise RemoteError('Blob integrity check failed.')
            if b'\0' in raw:
                skip('binary', path)
                continue
            try:
                content = raw.decode('utf-8')
            except UnicodeError:
                skip('encoding', path)
                continue
            found = detect(content, key, path)
            for finding in found:
                finding.update(commit=sha, blob=blob, repository=repository,
                    exposure='public_repository_content' if visibility=='public' else 'private_repository_content',
                    evidence_url='https://github.com/'+repository+'/blob/'+sha+'/'+quote(path, safe='/'),
                    observed_at=report['remote']['observed_at'])
            report['findings'].extend(found[:MAX_FINDINGS-len(report['findings'])])
            report['scanned'] += 1
            report['remote']['requests'] = client.requests
            save(report)
            if len(found) >= 1000 or len(report['findings']) >= MAX_FINDINGS:
                raise RemoteLimit('Finding limit reached.')
        report['status'] = 'partial' if report['skipped'] or tree['truncated'] else 'completed'
        if tree['truncated']:
            report['limitations'].append('GitHub truncated the recursive tree; omitted paths were not scanned.')
    except RemoteCancelled:
        report['status'] = 'cancelled'
    except RemoteLimit as error:
        report['status'] = 'partial'
        report['limitations'].append(str(error))
    except RemoteError as error:
        report['status'] = 'partial' if report['scanned'] else 'failed'
        report['limitations'].append(str(error))
    except (KeyError, TypeError, ValueError):
        report['status'] = 'failed'
        report['limitations'].append('Unexpected remote data; scan stopped without exposing response contents.')
    finally:
        report['remote']['requests'] = client.requests
        client.token = ''
