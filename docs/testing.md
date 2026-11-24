# Testing and quality checks

Use only synthetic responses or the explicitly started loopback lab. The tests include unit coverage, mocked HTTP integration, scope safety regressions, and a loopback end-to-end test. No public target is used by the suite.

```sh
uv sync --locked --all-extras
uv run pytest --cov=websentinel --cov-fail-under=80
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run bandit -r src/websentinel
uv run pip-audit --skip-editable
uv build
```

The suite binds loopback sockets for local E2E verification. It does not start Docker or a heavy virtual machine. Network-related policy tests mock DNS and HTTP responses.
