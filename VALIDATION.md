# Validation results

## Scan coverage hardening

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
