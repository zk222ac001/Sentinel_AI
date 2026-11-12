"""Read local HEAD history without checkout, filters, hooks or network fetching."""
import os
from pathlib import Path
import re
import selectors
import shutil
import subprocess
import time

MAX_COMMITS = 100
MAX_BLOBS = 1000
MAX_TREE_BYTES = 2 * 1024 * 1024
COMMAND_SECONDS = 10
OID = re.compile(r'^[0-9a-f]{40,64}$')


class HistoryError(Exception):
    """Sanitized collector failure; never include Git stderr or object contents."""


class HistoryLimit(Exception):
    pass


class HistoryCancelled(Exception):
    pass


def git_read(root, args, cancel, max_bytes=4096):
    """Bound stdout while draining/discarding stderr; terminate on cancel/timeout."""
    binary = shutil.which('git')
    if not binary:
        raise HistoryError('Git is not installed.')
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
               GIT_TERMINAL_PROMPT='0', GIT_NO_LAZY_FETCH='1',
               GIT_NO_REPLACE_OBJECTS='1', GIT_OPTIONAL_LOCKS='0')
    command = [binary, '-c', 'protocol.allow=never', '-c', 'core.hooksPath='+os.devnull,
               '-c', 'core.fsmonitor=false', '--no-pager', '-C', str(root), *args]
    process = subprocess.Popen(command, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, env=env)
    output = bytearray()
    deadline = time.monotonic() + COMMAND_SECONDS
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                if cancel.is_set():
                    raise HistoryCancelled
                if time.monotonic() > deadline:
                    raise HistoryLimit('Git command timeout; history incomplete.')
                for key, _ in selector.select(.05):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        break
                    if len(output) + len(chunk) > max_bytes:
                        raise HistoryLimit('Git output limit reached; history incomplete.')
                    output.extend(chunk)
            while process.poll() is None:
                if cancel.is_set():
                    raise HistoryCancelled
                if time.monotonic() > deadline:
                    raise HistoryLimit('Git command timeout; history incomplete.')
                time.sleep(.01)
        if process.returncode:
            raise HistoryError('Git could not read local history. Check the repository and local objects.')
        return bytes(output)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()


def scan_history(root, report, key, cancel, save):
    # Imported here to avoid a circular import in the worker.
    from .core import detect, MAX_BYTES, MAX_FINDINGS, MAX_SKIP_DETAILS
    started = time.monotonic()
    report['engine'] = 'builtin-rules-v1 + local-git-history'
    report['history'] = dict(ref='HEAD', head=None, commits_considered=0,
                             commits_completed=0, unique_blobs_scanned=0, shallow=None)
    report['limitations'] = [
        'Local HEAD history only; other refs, reflogs, dangling objects and remote content are not assessed.',
        'Each unique regular-file blob is inspected once; evidence shows one encountered commit/path, not every occurrence.',
        'Built-in candidate rules only. No credential validity, public exposure or billing verification.',
        'Symlinks and submodules are not followed. No checkout, hooks, textconv or content filters are run.',
    ]
    def skip(reason, path):
        report['skipped'][reason] = report['skipped'].get(reason, 0)+1
        if len(report['skipped_details']) < MAX_SKIP_DETAILS:
            report['skipped_details'].append(dict(reason=reason, path=path))
        else:
            report['skipped_details_omitted'] += 1
    def read(*args, max_bytes=4096):
        if cancel.is_set():
            raise HistoryCancelled
        if time.monotonic()-started > 120:
            raise HistoryLimit('History time limit reached.')
        return git_read(root, list(args), cancel, max_bytes)
    try:
        # Require an actual repository root; do not silently audit an ancestor.
        top = read('rev-parse', '--show-toplevel').decode('utf-8').strip()
        if Path(top).resolve() != root:
            raise HistoryError('Select the Git working-tree root, not a subfolder.')
        if read('rev-parse', '--is-bare-repository').strip() != b'false':
            raise HistoryError('Bare repositories are not supported yet.')
        shallow = read('rev-parse', '--is-shallow-repository').strip() == b'true'
        report['history']['shallow'] = shallow
        if shallow:
            report['limitations'].append('Shallow repository: earlier history is unavailable; no fetch was attempted.')
        head = read('rev-parse', '--verify', 'HEAD^{commit}').decode().strip()
        if not OID.fullmatch(head):
            raise HistoryError('Invalid HEAD object identifier.')
        report['history']['head'] = head
        commits = read('rev-list', '--max-count='+str(MAX_COMMITS+1), head,
                       max_bytes=(MAX_COMMITS+1)*66).decode().splitlines()
        truncated = len(commits) > MAX_COMMITS
        seen = set()
        for commit in commits[:MAX_COMMITS]:
            if not OID.fullmatch(commit):
                raise HistoryError('Invalid commit identifier.')
            report['history']['commits_considered'] += 1
            tree = read('ls-tree', '-rz', '--full-tree', commit, max_bytes=MAX_TREE_BYTES)
            for record in tree.split(b'\0'):
                if not record:
                    continue
                metadata, path_bytes = record.split(b'\t', 1)
                mode, kind, blob = metadata.decode('ascii').split()
                path = path_bytes.decode('utf-8', errors='replace')
                report['considered'] += 1
                if mode not in ('100644','100755') or kind != 'blob':
                    skip('git_symlink_or_submodule', path)
                    continue
                if not OID.fullmatch(blob):
                    raise HistoryError('Invalid blob identifier.')
                if blob in seen:
                    continue
                if len(seen) >= MAX_BLOBS:
                    raise HistoryLimit('Unique Git blob limit reached.')
                seen.add(blob)
                size = int(read('cat-file', '-s', blob).strip())
                if size > MAX_BYTES:
                    skip('size_limit', path)
                    continue
                raw = read('cat-file', 'blob', blob, max_bytes=MAX_BYTES)
                if b'\0' in raw:
                    skip('binary', path)
                    continue
                try:
                    text = raw.decode('utf-8')
                except UnicodeError:
                    skip('encoding', path)
                    continue
                found = detect(text, key, path)
                for finding in found:
                    finding.update(commit=commit, blob=blob, exposure='local_history_only')
                remaining = MAX_FINDINGS-len(report['findings'])
                report['findings'].extend(found[:remaining])
                report['scanned'] += 1
                report['history']['unique_blobs_scanned'] += 1
                if len(found) >= 1000 or len(report['findings']) >= MAX_FINDINGS:
                    raise HistoryLimit('Finding limit reached; history incomplete.')
            report['history']['commits_completed'] += 1
            save(report)
        if truncated:
            report['limitations'].append('Commit limit reached: only the newest '+str(MAX_COMMITS)+' reachable commits were inspected.')
        report['status'] = 'partial' if shallow or truncated or report['skipped'] else 'completed'
    except HistoryCancelled:
        report['status'] = 'cancelled'
    except HistoryLimit as error:
        report['status'] = 'partial'
        report['limitations'].append(str(error))
    except (HistoryError, OSError, ValueError):
        report['status'] = 'failed'
        report['limitations'].append('Cannot complete Git history scan: confirm Git is installed, select a working-tree root with commits, and ensure required objects exist locally.')
