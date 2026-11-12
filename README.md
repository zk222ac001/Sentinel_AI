# Sentinel AI — local security audit MVP

A working Phase 1 starter: read-only folder auditing, redacted candidate findings,
SQLite scan history, cancellation, CLI, local Streamlit UI, and HTML/JSON exports.
**AI analysis is not implemented yet.** This is an early prototype, not a production security product.

## Run on macOS

Install Python 3.11 or 3.12, then open Terminal in this extracted folder:

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
not a security verdict. Review filenames and scope paths before sharing reports.

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
- Reads selected UTF-8 text extensions and .env files; skips .git, Library,
  .ssh, .aws, .gnupg, dependency folders, binaries, archives and all symlinks.
- Max 1 MiB/file, 10,000 scanned files, 50,000 entries, depth 40, 120 seconds.
  Time limit is checked between entries; a filesystem read or scanner call
  may delay cancellation. Do not use untrusted network filesystems.
- Any skipped items produce partial status. Skip counts are grouped by reason;
  per-file skip inventory is not yet implemented.
- Candidate rules are deliberately small and do not establish validity,
  public exposure, account ownership or paid subscription status.
- Repeated credentials can yield multiple findings; HMAC fingerprints support
  future grouping. Overlapping built-in and Gitleaks detections are not merged.
- No Git history, GitHub, system permissions inventory, PDF, cloud calls,
  AI models, scheduling, automated remediation, or relationship graph yet.
- Dashboard cancellation affects the one shared local worker. Intended for
  one trusted local user, not multi-user deployment.

## Architecture and trust boundaries

Browser → loopback Streamlit UI → shared background worker → approved folder.
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
visible and can themselves contain personal information.

State survives restarts. Interrupted scans become partial on startup. Only one
application process should use a state directory. Stop the app, then manually
remove the state directory to clear records and fingerprint key. Delete any
exports separately. Physical secure erasure on SSDs is not guaranteed.

## Next development stages

1. Real macOS and Gitleaks compatibility tests; process-level job locking,
   authenticated local sessions, encrypted storage/keyring, bounded subprocess
   pipes, live filesystem threat hardening and detailed per-file coverage.
2. Local Git history, authorized GitHub evidence, system checks and guided
   permissions review.
3. Opt-in AI explanations using redacted structured findings, PDF reports,
   evidence-based relationship graph.
4. Packaging, signed releases, vulnerability review, CI, broader platforms.

Implementation intentionally uses Python's standard library for the initial
engine, CLI and SQLite layer rather than adding Typer/SQLAlchemy/Pydantic
before their complexity is needed. No claim is made that every item in the
original product specification is finished.
