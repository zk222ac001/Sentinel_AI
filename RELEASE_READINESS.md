# Release readiness — local desktop product

Target: one trusted user auditing files on their own Windows desktop, with macOS
and Linux compatibility retained. This is a pre-release engineering milestone,
not a production-ready certification or an enterprise/multi-tenant service.

## Milestone 1: runtime and storage reliability (v0.4.0)

Implemented:
- Dashboard and CLI acquire an OS-held lock before key initialization, database
  migrations, or interrupted-scan recovery. A second process is refused before
  it can touch scan records. Multiple tabs in one dashboard share one runtime.
- Locks are released when the owning process exits, including abnormal exit.
  Lock files remain on disk deliberately. Never delete one to bypass ownership.
- Legacy version-0 databases migrate additively to schema version 1 in a SQLite
  transaction. Scans and review decisions remain intact. Newer schema versions,
  incompatible table layouts and failed integrity checks stop startup.
- Interrupted running scans become partial, once. Recovery rolls back if it
  encounters a malformed record. The app does not delete damaged records.
- Invalid or missing fingerprint keys in existing storage cause an actionable
  error instead of silently generating an unrelated replacement key.
- UI/CLI present actionable startup errors without database exception traces.

Validation includes actual subprocess contention and abrupt-exit recovery,
transaction rollback, legacy preservation, incompatible/corrupt data refusal,
and the existing scanner/UI regression suite. The GitHub CI matrix covers
Windows/macOS/Linux on Python 3.11–3.13.

Scope boundaries: locks coordinate v0.4+ application entry points on a local
filesystem, not hostile programs, older versions, network shares or a malicious
same-account user. Internal Engine construction is for tests/embedding; embedders
must use runtime.open_engine to participate in ownership. Do not run older
Sentinel versions against a v0.4 data folder. A restored database must be paired
with its matching fingerprint key.

## Upgrade and recovery runbook

1. Stop all Sentinel dashboards and CLI scans, including old copies on other ports.
2. Copy the entire data directory to a private backup location while the app is
   stopped. Default Windows location: `%USERPROFILE%\.sentinel-ai`;
   macOS/Linux: `~/.sentinel-ai`. Include the database and fingerprint key.
   Backups are sensitive and are not encrypted by Sentinel.
3. Pull the reviewed release and install its requirements in the native virtual
   environment. Restart one dashboard on localhost.
4. Verify the version in Settings, existing history/reviews, and a synthetic demo.
5. If migration/startup fails, preserve the failed directory for diagnosis. Do not
   delete the key, edit user_version, or delete instance.lock to force startup.
6. To roll back, stop the app and restore the complete pre-upgrade backup to a
   separate private data directory. Launch the matching older app with that
   directory configured. Never point an older app at a newer database.

A stale instance.lock file alone is normal. If ownership is reported in use,
close the other Python process normally. If no process is present, preserve the
folder and investigate permissions/local-filesystem support; do not bypass it.

## Gates before a private beta

- [ ] Native Windows desktop test: chooser, file/history scans, cancellation,
  browser reload, app restart, upgrade with existing data, backup/restore.
- [ ] Real Gitleaks integration test on each supported OS, including redaction,
  version mismatch, malformed output, timeout and cancellation.
- [ ] Signed Windows packaging and reproducible release build; clean-machine
  installation/uninstall and upgrade/rollback tests. Signing needs publisher
  credentials and a signing service/certificate, not secrets committed to Git.
- [ ] Privacy review: retention/deletion, backup handling, Windows ACLs, OS keyring
  integration and a decision on encryption at rest.
- [ ] Local access threat review: localhost request protections, authentication
  model, hostile local processes, symlink/reparse/hardlink races and subprocesses.
- [ ] Dependency vulnerability triage and release inventory/SBOM.
- [ ] Measured false-positive/false-negative performance on a maintained synthetic
  and legally usable fixture corpus. No accuracy percentage without evidence.
- [ ] Keyboard/screen-reader, scaling and narrow-layout usability checks.

## Gates before a public production release

- [ ] Independent security review with blocking findings resolved.
- [ ] Published supported versions, limitations, privacy policy, security reporting
  channel, release notes and an update/support policy.
- [ ] Verified update authenticity, rollback process and release provenance.
- [ ] Real-world private-beta feedback incorporated and regression tested.

Billing discovery, app permission auditing, cloud team management and automated
remediation are separate future capabilities, not implied by this milestone.
