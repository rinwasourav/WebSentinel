"""Assessment mode and explicit authorization policy."""

from dataclasses import dataclass
from enum import StrEnum


class Mode(StrEnum):
    PASSIVE = "passive"
    ACTIVE = "active"
    INVENTORY = "inventory"


@dataclass(frozen=True, slots=True)
class Authorization:
    authorized: bool
    allowed_hosts: frozenset[str]
    permitted_modes: frozenset[Mode] = frozenset({Mode.PASSIVE})

    def require(self, mode: Mode, host: str) -> None:
        if not self.authorized:
            raise PermissionError("Explicit authorization is required")
        if mode not in self.permitted_modes:
            raise PermissionError(f"Assessment mode {mode} is not enabled")
        if host.lower().rstrip(".") not in {h.lower().rstrip(".") for h in self.allowed_hosts}:
            raise PermissionError("Host is outside the exact allowlist")
