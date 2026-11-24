# Contributing

## Development setup

Use Python 3.12+ and `uv sync --locked --all-extras`. The project targets macOS ARM64 and Linux x86_64/ARM64. Run the full commands in [testing guide](docs/testing.md) before opening a pull request.

## Adding a passive check

Add deterministic logic to `src/websentinel/checks/` that accepts `SafeResponse` and returns normalized `Finding` values. A check must not create a network client. Keep evidence minimal and redact secrets. State applicability and confidence; do not turn missing optional policies into high severity findings without application context. Add positive, negative, malformed-input, redaction and safety tests. Cite the relevant OWASP 2021 guidance when adding a mapping.

## Pull requests

Use the PR template. Include rationale, tests, documentation updates and any OWASP/CWE mapping sources. Keep commits focused and use conventional commit messages. Never use public targets in tests; use synthetic responses or the explicitly started loopback lab.
