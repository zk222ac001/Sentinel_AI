# Sentinel AI — local security audit MVP

A local security-audit prototype: read-only folder and local Git HEAD history
auditing, redacted candidate findings,
SQLite scan history, cancellation, CLI, local Streamlit UI, and HTML/JSON exports.
**AI analysis is not implemented yet.** This is an early prototype, not a production security product.

## Run on macOS

Install Python 3.11 or 3.12, then clone the repository and open its folder:

```bash
git clone https://github.com/zk222ac001/Sentinel_AI.git
cd Sentinel_AI
```

Create the environment and start the dashboard:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m streamlit run app.py --server.address=127.0.0.1
```

Open http://127.0.0.1:8501. Leave **Use synthetic demo data** selected,
confirm authorization, and click **Start scan**. The fixture contains two
obviously synthetic assignments, never usable credentials.

To scan your files, turn demo mode off and enter one project folder's path.
Start small. Do not grant Full Disk Access just to use this prototype.
Run directly on your Mac: a remote server would scan its own filesystem.

For a CLI-only demo, no third-party Python packages are required:

```bash
python3 -m sentinel demo --output demo-report
```

For an authorized folder:

```bash
python3 -m sentinel "$HOME/Projects/my-project" --output project-report
```

Ctrl+C requests cancellation. Reports are written after cancellation too.
Existing export files are never silently overwritten. Exit code 2 denotes
failed, partial, or cancelled coverage; 0 denotes completed selected scope,
not a security verdict. CLI reports are created owner-only (0600) from the
first write, even with a permissive umask. Browser download permissions are
controlled by your browser and OS. Review filenames and scope paths before sharing reports.

## Scan local Git history

Install Git and verify `git --version`. Choose **Local Git HEAD history** in the
sidebar, disable synthetic demo mode, and select the repository's working-tree
root. File mode remains the default; history scanning is an explicit choice.

```bash
python3 -m sentinel "$HOME/Projects/my-project" --mode git_history --output history-report
```

This scans regular-file blobs reachable from the HEAD commit captured at scan
start. It can find credentials in deleted files or older versions. Each unique
blob is scanned once, with one observed commit/path attached to its findings.
It does not determine when a secret was first introduced or publicly exposed.
Uncommitted files, other branches, reflogs and dangling objects are excluded.
Run file mode separately to inspect current uncommitted content.

Limits: 100 commits, 1,000 distinct blobs, 1 MiB/blob, 2 MiB tree-command output,
10 seconds per Git command, 120 seconds overall, and the existing finding caps.
Shallow history, skipped content and reached limits are marked **partial**.
Empty repositories, subfolders and missing local objects fail visibly.

History mode inspects committed UTF-8 regular-file content regardless of file
extension; the file-mode directory exclusions do not apply to committed blobs.
Symlinks and submodules are not followed. No fetch, checkout, hooks, filters or
textconv run. Git transports are disabled and lazy fetching is disabled. This
is an audit of locally available evidence, not a GitHub public-exposure check.
Git metadata may reference local object stores outside the working tree (for
example linked worktrees or alternates); audit only repositories you authorize.
Gitleaks integration currently applies only to file mode.

## Optional Gitleaks

Install Gitleaks 8.x manually from https://github.com/gitleaks/gitleaks and check
`gitleaks version`. Select its checkbox or add `--gitleaks` to the CLI.
The adapter uses stdin and fully redacted JSON, never raw disk reports.
Missing/incompatible tools cause an explicit failed scan. This adapter was
unit-tested with mocked responses; a real Gitleaks integration test is still
required. Built-in detection remains explicitly limited when used alone.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

See VALIDATION.md for what actually ran. requirements-resolved.txt records the
Linux validation environment; use requirements.txt on Mac and validate the
resolved platform dependencies. This is not a signed or notarized Mac app.

## Scope and limitations

- Targets macOS/POSIX filesystem semantics; tested on Linux, not a real Mac.
- Native Windows unsupported. WSL scans Linux-visible folders and cannot audit
  Windows security settings. Windows support needs a dedicated implementation.
- File mode reads selected UTF-8 text extensions and .env files; skips .git, Library,
  .ssh, .aws, .gnupg, dependency folders, binaries, archives and all symlinks.
- File mode: max 1 MiB/file, 10,000 scanned files, 50,000 entries, depth 40, 120 seconds.
  Time limit is checked between entries; a filesystem read or scanner call
  may delay cancellation. Do not use untrusted network filesystems.
- Any skipped items produce partial status. Counts are grouped by reason;
  up to 500 relative paths and reasons are shown in the dashboard and exports,
  with a count of additional omitted entries. Directories skipped as a whole
  count as one entry; their contents are not enumerated. Finding limits also
  produce partial status, including limits reached inside nested directories.
- Candidate rules are deliberately small and do not establish validity,
  public exposure, account ownership or paid subscription status.
- Repeated credentials can yield multiple findings; HMAC fingerprints support
  future grouping. Overlapping built-in and Gitleaks detections are not merged.
- No remote GitHub audit, system permissions inventory, PDF, cloud calls,
  AI models, scheduling, automated remediation, or relationship graph yet.
- Dashboard cancellation affects the one shared local worker. Intended for
  one trusted local user, not multi-user deployment.

## Architecture and trust boundaries

Browser → loopback Streamlit UI → shared background worker → approved folder.
History mode reads local objects through bounded Git subprocess pipes.
The worker emits redacted dictionaries → SQLite → escaped HTML/JSON exports.
The CLI calls the same engine. No scan data is sent to the network.
Dependency installation itself uses the network. Streamlit usage statistics
are disabled in the bundled configuration; launch from this project folder.

Filesystem reads use directory-relative descriptors and no-follow opens on
POSIX. Symlinks are never traversed. Files are treated as data; no contents or
project scripts execute. HTML export escapes all serialized data. There is
no LLM or prompt execution pathway.

Threat model: accidental credential exposure and hostile file contents within
an approved tree. Not a boundary against a malicious local administrator or
another process running as the same user. Hard links may refer to data also
reachable elsewhere. Concurrent mount/rename attacks require further hardening.

## Storage and privacy

Default state directory: ~/.sentinel-ai (0700). Database and fingerprint key
are created with owner-only permissions. **SQLite is not encrypted.** The MVP
fingerprint key is a local 0600 file, not OS Keychain; keyring integration is a
release-hardening task. Raw detected values are not intentionally persisted;
Python memory cannot guarantee zeroization. Filenames and scope paths remain
visible and can themselves contain personal information. The state directory
and its descendants cannot be selected as a scan root. For isolated dashboard
state, set `SENTINEL_DATA_DIR` before launching Streamlit; CLI users should
use `--data`. Never expose the dashboard publicly.

State survives restarts. Interrupted scans become partial on startup. Only one
application process should use a state directory. Stop the app, then manually
remove the state directory to clear records and fingerprint key. Delete any
exports separately. Physical secure erasure on SSDs is not guaranteed.

## Next development stages

1. Real macOS and Gitleaks compatibility tests; process-level job locking,
   authenticated local sessions, encrypted storage/keyring, bounded subprocess
   pipes and live filesystem threat hardening.
2. Broader Git ref selection, authorized GitHub evidence, system checks and guided
   permissions review.
3. Opt-in AI explanations using redacted structured findings, PDF reports,
   evidence-based relationship graph.
4. Packaging, signed releases, vulnerability review, broader platforms.

## Automated checks

GitHub Actions runs the core tests and synthetic Streamlit workflow on Linux
and macOS with Python 3.11 and 3.12 for pushes and pull requests. Actions are
pinned to commits and receive read-only repository permissions. The dashboard
test skips itself if Streamlit is not installed locally. Dependabot is configured
for weekly Python and Actions dependency update pull requests. This is not a
complete vulnerability assessment; inspect CI results before merging changes.

Implementation intentionally uses Python's standard library for the initial
engine, CLI and SQLite layer rather than adding Typer/SQLAlchemy/Pydantic
before their complexity is needed. No claim is made that every item in the
original product specification is finished.
