"""Validated registry for built-in passive checks."""

from collections.abc import Callable
from dataclasses import dataclass

from websentinel.http.client import SafeResponse
from websentinel.models import Finding


@dataclass(frozen=True, slots=True)
class CheckSpec:
    id: str
    name: str
    capability: str
    run: Callable[[SafeResponse], list[Finding]]


def builtins() -> tuple[CheckSpec, ...]:
    from websentinel.checks.baseline import inspect_response

    return (CheckSpec("passive-baseline", "Passive HTTP baseline", "passive", inspect_response),)
