## Summary

<!-- Describe the change and its user-visible effect. -->

## Safety and scope

- [ ] Network access remains in `PolicyHTTPClient`.
- [ ] Redirect, scope, DNS pinning, response-size, and rate limits remain enforced.
- [ ] Evidence and reports do not expose credentials or cookie values.

## Verification

- [ ] Tests added or updated.
- [ ] `ruff`, `mypy`, `bandit`, tests, and build checks pass.
- [ ] Documentation and limitations updated.
