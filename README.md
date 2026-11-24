# WebSentinel

WebSentinel is a lightweight, open-source framework for **authorized passive web security assessments**. It implements bounded HTTP GET assessment, a same-origin page inventory, passive header/cookie/TLS observations, exact host scope checks, redacted evidence, SQLite history and migrations, risk scoring, and escaped JSON/HTML/optional PDF reports. It does not attempt exploitation, authentication, form submission, brute force, port scanning, or unrestricted crawling.

## Safety model

Every network assessment requires `--authorized`, an exact repeated `--scope` hostname allowlist, and an HTTP(S) URL. Wildcards, URL credentials, off-scope redirects, and non-global resolved addresses are denied by default. `--local-lab` allows only IPv4/IPv6 loopback by default. Additional lab destinations require one or more explicit RFC1918/IPv6 ULA `--lab-cidr` values; link-local, metadata, reserved, and public destinations remain denied in local-lab mode. CIDRs never replace the exact host allowlist. Each hostname is resolved and validated once per hop; the HTTP transport connects to a pinned approved IP and verifies the socket peer before sending the request, while retaining the original hostname for TLS SNI and certificate checks. Redirects are resolved and validated against the same CIDR policy. Requests use TLS verification, short timeouts, one request per second by default, and a hard request cap. Local process/container isolation does not prevent impact on a remote target server. Use a dedicated test environment and account for any authorized active work.

## Install and run

Requires Python 3.12+ and uv:

```sh
uv sync --all-extras
uv run websentinel assess --target https://your-authorized-host.example --scope your-authorized-host.example --authorized
```

Only assess systems for which you have explicit permission. Reports are written under `reports/` (ignored by Git); pass `--pdf` to also create a PDF when the `pdf` extra is installed. Use `websentinel history` to list saved assessments and `websentinel checks list` to list registered passive checks.

Add `--crawl` to enable bounded same-origin inventory; defaults are 50 pages, depth 3, 1 MiB per HTML body, 250 links per page, sequential requests, and the same request rate and total request cap as the assessment. Limits can be changed with `--max-pages` and `--max-depth`. Every redirect still goes through scope validation, DNS pinning, and peer verification. Crawling is opt-in.

Example local lab:

```sh
cd lab && docker compose up -d
cd .. && uv run websentinel assess --target http://127.0.0.1:3000 --scope 127.0.0.1 --authorized --local-lab
cd lab && docker compose down
```

The lab is optional and only starts during explicit commands. No Docker target was started as part of repository setup.

The optional scanner image is separate from the Juice Shop lab. Build it with `docker build -t websentinel .`. Mount writable report and data directories, then run as your host user with a read-only container root, for example:

```sh
mkdir -p reports data
docker run --rm --read-only --tmpfs /tmp --cap-drop=ALL --security-opt=no-new-privileges \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/reports:/reports" -v "$PWD/data:/data" websentinel \
  assess --target https://your-authorized-host.example --scope your-authorized-host.example \
  --authorized --output /reports --database /data/assessments.sqlite3
```

For an intentionally isolated lab host on a private subnet, pass its narrowly scoped network explicitly, for example `--local-lab --lab-cidr 192.168.56.0/24`. Do not use broad home or office LAN ranges as lab CIDRs.

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

`scope/` is the authorization and URL gate; `http/` owns all requests; `checks/` contains deterministic passive checks; `findings/` normalizes and redacts evidence; `storage/` provides transactional, versioned SQLite persistence; `inventory/` performs bounded same-origin link discovery using the policy HTTP client; `reporting/` escapes untrusted HTML. `active/` and `runtime/` remain extension points. Future authenticated or active/runtime workflows require distinct opt-in authorization and must disclose that isolation does not prevent target-server impact.

OWASP references use the versioned OWASP Top 10 2021 mapping and are contextual pointers, not proof that a finding maps to an entire category. Scanner observations can be false positives and are not a substitute for expert review. The passive checks cover baseline browser headers, cookie flags/prefixes, HSTS lifetime, negotiated TLS protocol, near-expiry verified certificates, and Server metadata. Certificate chain and hostname validation are enforced by the HTTP TLS stack; this is not a full certificate-chain audit. PDF output is available through the optional ReportLab extra. Reports include page and check coverage; inaccessible, partial, and skipped pages are not treated as passing results.

See [the check catalogue](docs/checks.md), [assessment limitations and risk scoring](docs/limitations.md), [scope and crawler policy](docs/architecture/scope-security.md), and [data flow](docs/architecture/data-flow.md) for operational details.
