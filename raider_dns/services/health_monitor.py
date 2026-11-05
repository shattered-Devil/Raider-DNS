"""Small, testable state machine for automatic DNS health monitoring."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class HealthTransition:
    previous: str
    current: str
    changed: bool
    failures: int
    successes: int


class DNSHealthStateTracker:
    """Require consecutive checks before reporting unhealthy or recovered."""

    def __init__(self) -> None:
        self.state = "unknown"
        self.consecutive_failures = 0
        self.consecutive_successes = 0

    def record(
        self,
        success: bool,
        failure_threshold: int = 3,
        recovery_threshold: int = 2,
    ) -> HealthTransition:
        failure_threshold = max(1, min(10, int(failure_threshold)))
        recovery_threshold = max(1, min(10, int(recovery_threshold)))
        previous = self.state
        if success:
            self.consecutive_successes += 1
            self.consecutive_failures = 0
            needed = 1 if self.state == "unknown" else recovery_threshold
            if self.consecutive_successes >= needed:
                self.state = "healthy"
        else:
            self.consecutive_failures += 1
            self.consecutive_successes = 0
            if self.consecutive_failures >= failure_threshold:
                self.state = "unhealthy"
        return HealthTransition(
            previous=previous,
            current=self.state,
            changed=previous != self.state,
            failures=self.consecutive_failures,
            successes=self.consecutive_successes,
        )

    def reset(self) -> None:
        self.state = "unknown"
        self.consecutive_failures = 0
        self.consecutive_successes = 0
