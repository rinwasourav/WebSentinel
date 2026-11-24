# Release checklist

- [ ] Review scope, connection pinning, redirect and local-lab safety tests.
- [ ] Run test, lint, format, typing, Bandit, pip-audit and build gates on supported platforms.
- [ ] Verify `uv build` wheel and sdist, then install each in a clean environment.
- [ ] Review version, changelog, license and package metadata.
- [ ] Inspect JSON, HTML and optional PDF reports for redaction, escaping and coverage accuracy.
- [ ] Verify migration from the previous database schema and take a backup before upgrades.
- [ ] Review dependency and workflow updates.
- [ ] Confirm documentation describes unsupported authenticated/active/runtime capabilities.
- [ ] Publish release artifacts only after maintainer approval.
