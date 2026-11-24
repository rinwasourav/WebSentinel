# Changelog

## 0.1.0 - 2026-11-24

- Initial passive assessment framework with scope enforcement, baseline checks, reporting, and SQLite persistence.
- Active assessment, bounded inventory, and ephemeral runtime reserved as disabled modules.

## Unreleased

- Added opt-in bounded same-origin page inventory with request reuse, connection pinning, redirect-origin enforcement, and page/check coverage.
- Added inventory and coverage to JSON, HTML, and PDF assessments, plus a published JSON Schema.
- Expanded passive observations for cross-origin policies, HSTS lifetime, cookie prefixes/session persistence, and near-expiry verified TLS certificates.
- Added scan configuration and duration to assessment reports.
- Added SQLite schema migration for page records, consistent database backup, and assessment deletion.
- Added finding detection timestamps and explicit observation classification.
- Added architecture and safety documentation, contributor PR template, multi-platform CI, Dependabot, and non-root Docker packaging.
- Authenticated assessment, active testing, ephemeral runtime, and public package/release publication remain outside this milestone.
