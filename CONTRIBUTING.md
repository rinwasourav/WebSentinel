# Contributing

Use Python 3.12+, `uv sync --all-extras`, and the checks in README. Keep public APIs typed, network calls centralized through the policy-enforced client, checks deterministic, and evidence minimal and redacted. New checks need tests for positive, negative, error, and safety behavior. Never use public targets in tests; use synthetic responses or the explicitly started local lab. Keep third-party checks disabled unless a user explicitly enables them. Submit focused pull requests with rationale, tests, and any mapping source. Use conventional commit messages.
