# WebSentinel

WebSentinel is a lightweight, open-source framework for **authorized passive web security assessments**. Version 0.1 implements one bounded HTTP GET, safe header/cookie/TLS observations, exact host scope checks, redacted evidence, SQLite assessment history, a severity-confidence risk score, and escaped JSON/HTML/optional PDF reporting. It does not attempt exploitation, authentication, form submission, brute force, port scanning, or unrestricted crawling.

## Safety model

Every network assessment requires `--authorized`, an exact repeated `--scope` hostname allowlist, and an HTTP(S) URL. Wildcards, URL credentials, off-scope redirects, and non-global resolved addresses are denied by default. Loopback requires `--local-lab`. Each hostname is resolved and validated once per hop; the HTTP transport connects to a pinned approved IP and verifies the socket peer before sending the request, while retaining the original hostname for TLS SNI and certificate checks. Redirects are resolved and validated again. Requests use TLS verification, short timeouts, one request per second by default, and a hard request cap. Local process/container isolation does not prevent impact on a remote target server. Use a dedicated test environment and account for any authorized active work.

## Install and run

Requires Python 3.12+ and uv:

```sh
uv sync --all-extras
uv run websentinel assess --target https://your-authorized-host.example --scope your-authorized-host.example --authorized
```

Only assess systems for which you have explicit permission. Reports are written under `reports/` (ignored by Git); pass `--pdf` to also create a PDF when the `pdf` extra is installed. Use `websentinel history` to list saved assessments. Example local lab:

```sh
cd lab && docker compose up -d
cd .. && uv run websentinel assess --target http://127.0.0.1:3000 --scope 127.0.0.1 --authorized --local-lab
cd lab && docker compose down
```

The lab is optional and only starts during explicit commands. No Docker target was started as part of repository setup.

## Development checks

```sh
uv run pytest --cov=websentinel --cov-fail-under=80
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run bandit -r src/websentinel
uv run pip-audit --skip-editable
uv build
```

## Architecture

`scope/` is the authorization and URL gate; `http/` owns all requests; `checks/` contains deterministic passive checks; `findings/` normalizes and redacts evidence; `storage/` provides transactional, versioned SQLite persistence; `reporting/` escapes untrusted HTML. `active/`, `inventory/`, and `runtime/` are reserved, disabled extension points. Future page inventory must remain same-origin, bounded, rate limited, and avoid state-changing paths. Future active/runtime workflows require distinct opt-in authorization and must disclose that isolation does not prevent target-server impact.

OWASP references are contextual pointers, not proof that a finding maps to an entire category. Scanner observations can be false positives and are not a substitute for expert review. The implementation currently covers a baseline subset of HTTP security headers, cookie flags, a negotiated TLS protocol observation, and Server metadata. Certificate chain and hostname validation are enforced by the HTTP TLS stack; detailed certificate-expiry diagnostics remain follow-on work. PDF output is available through the optional ReportLab extra.
