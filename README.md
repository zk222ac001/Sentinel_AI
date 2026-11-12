# Sentinel AI — local security audit MVP

A local security-audit prototype: read-only folder, local Git HEAD history and opt-in GitHub snapshot
auditing, redacted candidate findings,
SQLite scan history, cancellation, CLI, local Streamlit UI, and HTML/JSON exports.
**Optional local AI can select reviewed guidance for findings.** This is an early prototype, not a production security product.

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

## Audit one GitHub repository (explicit network opt-in)

In the dashboard choose **GitHub repository snapshot**, disable demo mode,
enter `owner/repository`, and confirm both your authority to audit that repository
and permission for API reads. Local modes still make no network requests.

```bash
python3 -m sentinel owner/repository --mode github --allow-network --output github-report
```

GitHub mode reads the selected repository's default branch at one pinned commit.
It does not scan earlier commits, other refs, forks, Actions logs or issues. Use
local Git history mode on an authorized clone for history inspection. GitHub
Enterprise hosts and bulk account discovery are not implemented.

Public repositories can be read without a token, subject to GitHub rate limits.
For private repositories, supply an intentionally created fine-grained token
restricted to selected repositories with Contents read access (and the associated
Metadata read permission). Set `SENTINEL_GITHUB_TOKEN` in the launching process's
environment using your secret manager or a non-echoing shell prompt. Do not put a
token in a command argument, repository file, screenshot or chat. The app reads
it only for GitHub mode, does not persist it, and never uses discovered credentials
as connector tokens. Environment-based credentials are an interim mechanism;
OS keyring integration is still planned.

Only HTTPS GET requests to `api.github.com` are made. Redirects are refused and
environment proxies are disabled to avoid forwarding the connector credential.
No files are uploaded, credentials validated, accounts modified or scripts run.
Blob values are processed in memory and findings are redacted before storage.
The local fingerprint key stays local. Repository names, paths, commit IDs and
observed visibility appear in reports, including for private repositories.

Limits: 100 distinct blobs, 1 MiB/blob, 4 MiB/API response, 104 requests, 10-second
socket timeout, 120-second scan budget, and existing finding limits. Cancellation
can wait for an in-flight socket read. Rate limits stop the scan without retries;
results already scanned are retained as partial. A truncated recursive tree is
explicitly partial, not an exhaustive inventory. Recursive trees are not paginated;
this version does not fetch omitted subtrees. No claim is made that any detected
credential is active, billable, or publicly exposed for a particular duration.

Public/private exposure labels reflect repository metadata observed at the start
of retrieval. Findings link to content at the captured commit, not the moving
branch tip. Each distinct blob gets one representative path. Supported regular
UTF-8 blobs are inspected regardless of extension; binaries, symlinks and submodules
are skipped. Missing access, empty repositories and malformed responses fail visibly.

API references: [Git trees](https://docs.github.com/en/rest/git/trees) and
[Git blobs](https://docs.github.com/en/rest/git/blobs).

## Optional local AI guidance

Scanning and reviewed guidance work without a model. After a scan finishes, open
**Explanations and optional local AI**. The default is reviewed guidance with no
model request. The AI feature is currently dashboard-only.

Install [Ollama](https://ollama.com/) yourself and download a suitable local model
for your hardware. Sentinel does not install software or download model weights.
List models with `ollama list`. Copy an installed local model name into the UI.

**Disable Ollama cloud features in the Ollama server before using this mode.**
For a manually launched server, stop any existing Ollama server and start it with:

```bash
OLLAMA_NO_CLOUD=1 ollama serve
```

For an existing desktop app or service, configure its environment or merge
`"disable_ollama_cloud": true` into `~/.ollama/server.json`, then restart Ollama.
Do not overwrite other settings. Confirm the server log reports cloud disabled.
See the [official FAQ](https://docs.ollama.com/faq). Setting an environment variable
only in the Sentinel process does not configure an already-running Ollama server.

In Sentinel, review the payload preview, confirm cloud features are disabled,
and explicitly allow the request. The app uses only `127.0.0.1:11434`, refuses
redirects, disables environment proxies, rejects cloud-named models and remote
model metadata, and requires local model metadata before requesting inference.
A loopback endpoint cannot independently guarantee the behavior of another
process: use your own trusted, correctly configured Ollama server.

Only enum-validated rule, severity and exposure fields, temporary IDs F1–F10,
fixed unknown validity/billing labels and a fixed guidance catalog are sent.
Paths, repository names, original IDs, snippets, fingerprints, tokens and actual
credential values are excluded. F1 maps to the first finding in the displayed
scan, F2 to the second, and so on. At most ten findings are included.

The model selects **guidance codes** from a reviewed catalog. It cannot contribute
arbitrary prose, invent findings, change severity or evidence, execute commands,
or call tools. Invalid IDs, extra fields, unsupported codes, tool calls and
unsupported exposure suggestions are rejected. All displayed advice comes from
the fixed catalog and is conditional; this is constrained AI assistance, not an
autonomous investigation or full free-form analysis.

Requests run in a per-browser-session background job with cancellation, a
60-second budget, 10-second socket timeout, 256 KiB response cap and 1,024-token
generation setting. Slow cold starts may fall back to reviewed guidance; preload
the model separately if needed. Cancellation can wait for the socket timeout.
Ollama may continue work briefly after the client stops waiting.

Guidance is labeled by source and stays in the browser session. It can be
exported separately as JSON. Original scan records and exports remain unchanged.
A refresh/session loss may discard the guidance. No cloud AI provider is
integrated; control the local server's own logging and retention separately.

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
- No system permissions inventory, PDF, AI-provider calls,
  cloud AI providers, scheduling, automated remediation, or relationship graph yet.
- Dashboard cancellation affects the one shared local worker. Intended for
  one trusted local user, not multi-user deployment.

## Architecture and trust boundaries

Browser → loopback Streamlit UI → shared background worker → approved folder.
History mode reads local objects through bounded Git subprocess pipes.
The worker emits redacted dictionaries → SQLite → escaped HTML/JSON exports.
The CLI calls the same engine. Local modes do not send scan data to the network.
GitHub mode sends authorized GET requests (repository/object identifiers plus
an optional connector token) and processes downloaded content locally.
Dependency installation itself uses the network. Streamlit usage statistics
are disabled in the bundled configuration; launch from this project folder.

Filesystem reads use directory-relative descriptors and no-follow opens on
POSIX. Symlinks are never traversed. Files are treated as data; no contents or
project scripts execute. HTML export escapes all serialized data. There is
no scanned file content is supplied to a model. Optional guidance uses only
allowlisted metadata and a fixed catalog; model responses cannot execute actions.

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
2. Broader Git ref selection, GitHub history coverage, system checks and guided
   permissions review.
3. Evaluate local model compatibility and guidance quality; PDF reports and
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
