# Architecture and data flow

1. The CLI parses explicit target, hostname scope, authorization acknowledgement, lab policy, request limits and output paths.
2. `ScopePolicy` rejects unauthorized targets and `resolve_target` validates every DNS result.
3. `PinnedHTTPTransport` connects to an approved address and checks the connected peer while preserving the hostname for TLS SNI and certificate validation.
4. `PolicyHTTPClient` performs sequential bounded GET requests. Redirects are resolved, policy-checked and pinned again. HTML body reads are opt-in and capped.
5. The optional inventory crawler parses anchor links only. It does not execute scripts, submit forms or follow external origins; unsafe action paths and credential-bearing query parameters are excluded.
6. Passive checks create normalized findings. Evidence and report data pass through redaction before persistence and export.
7. SQLite writes an assessment and its findings/pages in transactions, using schema migrations. JSON, HTML and optional PDF reports include coverage and limitations.

All network access belongs in the policy-enforced HTTP layer. Check implementations receive `SafeResponse`; they must not create their own network clients.

## Extension boundaries

Authenticated checks, active assessment, browser automation and ephemeral target runtimes are not implemented in the standard assessment flow. Any future runtime isolation cannot guarantee that a target server is unaffected. Such work requires dedicated explicit authorization, lab-only controls, and a separate review.
