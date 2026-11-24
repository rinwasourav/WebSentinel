# Scope, crawler, and connection security

## Default policy

Every assessment requires explicit authorization and exact hostname allowlisting. Targets must use HTTP or HTTPS. Public assessments reject non-global destinations. Local-lab mode allows loopback by default; private lab networks require explicit RFC1918 or IPv6 ULA CIDRs. Link-local, reserved and cloud metadata destinations remain blocked. CIDR approval does not replace hostname authorization.

For every request hop, WebSentinel resolves and validates addresses, pins the connection to an approved IP, and verifies the connected peer. Redirects repeat that process. The crawler adds a same-origin rule even if the assessment allowlist contains other hosts. IPv4-mapped IPv6 addresses follow the embedded IPv4 policy.

## Crawler boundaries

Crawler defaults are 50 pages, depth 3, 1 MiB per HTML response, 250 links per page, one request at a time, and the assessment's configured rate, timeout, redirect and total-request limits. URLs are normalized, fragments removed, duplicates skipped, tracking parameters removed, and sensitive query parameters excluded. Links suggesting logout or state-changing actions are excluded. Only anchor and area `href` values are parsed; JavaScript and forms are not executed.

The crawler is opt-in with `assess --crawl`. A page outside the crawl origin after redirects is skipped. An oversized body or truncated link inventory is marked partial. Inaccessible and skipped pages reduce coverage; they do not count as passing checks.

## Limitations

These safeguards reduce scanner-side scope and resource risks. They do not establish authorization, isolate the target server, or make remote assessment impact-free. Operators remain responsible for authorization and agreed rate limits.
