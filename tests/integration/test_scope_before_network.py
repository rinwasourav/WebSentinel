import pytest

from websentinel.scope.guard import ScopeError, ScopePolicy, validate_url


def test_scope_rejected_before_request_can_be_created() -> None:
    p = ScopePolicy(frozenset({"allowed.test"}), authorized=True)
    with pytest.raises(ScopeError):
        validate_url("https://outside.test", p, resolve=False)
