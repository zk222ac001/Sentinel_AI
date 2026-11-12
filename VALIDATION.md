# Validation results

## Cross-platform filesystem and Git pipe support

- Linux/Python 3.12: 70 tests discovered, 65 passed and 5 native Win32 tests
  skipped as intended. Existing scans, Git fixtures and dashboard workflows pass.
- Windows-specific tests cover paths with spaces/Unicode, junction exclusion,
  handle scope enforcement, directory replacement blocking, and direct reparse
  point rejection. These require the Windows CI runners, not mocked Linux calls.
- CI expanded to nine jobs: Windows/macOS/Linux and Python 3.11/3.12/3.13.
  Consult PR checks for actual platform results; local Linux success alone does
  not prove Windows compatibility.
- Replaced Unix-only pipe selectors with a bounded reader queue for Git commands.
  SQLite connections now close explicitly to release Windows file locks.
- POSIX private-mode checks remain; Windows ACL inheritance is documented rather
  than falsely equated with chmod 0600. Custom Windows ACL enforcement, hostile
  concurrent mutation, network shares and cloud hydration remain out of scope.
- Real Gitleaks and Ollama inference remain unverified on all platforms.

## Optional local AI guidance

- Linux/Python 3.12: 65 tests passed, including 20 new guidance/transport/UI tests.
- Verified payload minimization, injection-like metadata exclusion, consent gates,
  cloud/remote-model refusal, response validation, unknown IDs/actions, arbitrary
  prose and tool-call rejection, fallback, cancellation, response bounds,
  loopback-only transport, no repeated inference on rerenders, and unchanged scans.
- The dashboard test uses mocked model responses, not real inference. Ollama model
  compatibility, latency, hardware requirements and actual selection quality have
  not been measured. No local model was downloaded or run in this workspace.
- CI runs Linux/macOS with Python 3.11/3.12; see PR checks for runner results.

## GitHub snapshot auditing

- Linux/Python 3.12: 45 tests passed, including 16 new offline GitHub API and UI
  contract tests. No real GitHub credential or live remote audit was used.
- Tests cover explicit network authorization, repository input validation,
  public/private evidence, token/value redaction from persistence, tree truncation,
  rate-limit partial results, blob integrity, symlink exclusion, response/blob
  caps, identity mismatch, redirect refusal, cancellation, fixed-host GETs, and
  the dashboard network gate followed by a mocked snapshot scan.
- GitHub CI runs the same suite on Linux/macOS with Python 3.11/3.12.
- Real private-repository access, organizational token policies and live API
  compatibility remain to be validated by an authorized user.

## Local Git history scanning

- Python 3.12 / Linux with Git 2.52.0: 29 tests passed including 11 new
  real-Git fixture tests; no external service was contacted.
- Verified deleted-secret recovery with commit evidence, persistence redaction,
  duplicate blob suppression, HEAD-only scope, shallow clone reporting,
  commit/blob/output limits, cancellation, empty/subfolder failures,
  symlink exclusion, and non-execution of configured textconv/smudge/fsmonitor.
- File-mode Streamlit demo continues to pass. History mode uses the same worker
  and exports; interactive visual testing on a personal Mac remains needed.
- CI results for this PR determine Linux/macOS Python 3.11/3.12 validation.

## Previous scan coverage hardening

- Python 3.12 / Linux: 18 tests passed, including a real Streamlit 1.50 AppTest.
- Regression tests exercise nested traversal limits, per-file/global finding
  limits, bounded skip details, symlink loops, excluded application-state roots,
  private CLI exports under a permissive umask, and no-overwrite behavior.
- Existing redaction, persistence, cancellation and recovery checks still pass.
- Dashboard demo uses isolated temporary state and yields two synthetic findings.
- GitHub Actions now defines Linux/macOS jobs for Python 3.11 and 3.12.
  Check the PR Actions results for runner validation; local testing alone does
  not establish real Mac compatibility.
- Real installed Gitleaks, macOS privacy permissions, visual browser review,
  native Windows, dependency vulnerability audit and signing are not validated.
- Non-failing warnings from Streamlit's test context and its NumPy timedelta
  conversion occurred during local tests. The deprecated dataframe width
  argument was replaced.

requirements-resolved.txt records the original Linux environment. It is not
an independently verified, portable dependency lockfile. CI resolves from
requirements.txt on each platform.
