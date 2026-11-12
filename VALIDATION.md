# Validation results

- Python 3.12 / Linux validation environment.
- `python -m compileall -q sentinel-ai`: passed.
- `python -m unittest discover -s tests -v`: 10 tests passed.
- CLI demo: completed, one file read, two synthetic candidate findings.
- Streamlit 1.50 AppTest: initial render, authorization checkbox, scan action,
  resulting metrics and report controls passed without application exceptions.
- Streamlit emitted a non-failing deprecation warning for use_container_width.
- No visual browser screenshot review performed.
- Real macOS, Windows, installed Gitleaks, and vulnerability review NOT tested.
- Dependency versions captured in requirements-resolved.txt; not a portable
  hash-verified lockfile. Mac dependency resolution still needs validation.

Tests cover persisted/report redaction, symlink escape prevention, binary and
size exclusions, HTML escaping, missing Gitleaks failure, Gitleaks evidence
field filtering, placeholders, interruption recovery, cancellation and HMAC.
