"""Small, deterministic state tracker for Raider DNS managed engines.

The supervisor observes process/controller state; it never kills, restarts, or
reconfigures an engine. Recovery remains an explicit operation in the relevant
controller so a missing process is never treated as permission to alter routes.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from threading import RLock
from typing import Any


_ALLOWED_STATES = {
    "not_configured", "stopped", "starting", "running", "healthy",
    "degraded", "failed", "recovery_required", "unknown",
}


@dataclass(frozen=True, slots=True)
class EngineStatus:
    engine_id: str
    display_name: str
    state: str
    detail: str
    checked_at: str
    transition_count: int = 0


class EngineSupervisor:
    """Track bounded engine observations and state transitions."""

    MAX_EVENTS = 50

    def __init__(self) -> None:
        self._lock = RLock()
        self._statuses: dict[str, EngineStatus] = {}
        self._events: list[dict[str, str]] = []
        self._expected_stops: set[str] = set()

    @staticmethod
    def derive_state(
        *, configured: bool, running: bool | None,
        ready: bool | None = None, recovery_required: bool = False,
    ) -> str:
        if recovery_required:
            return "recovery_required"
        if not configured:
            return "not_configured"
        if running is None:
            return "unknown"
        if not running:
            return "stopped"
        if ready is False:
            return "degraded"
        if ready is True:
            return "healthy"
        return "running"

    def mark_expected_stop(self, engine_id: str) -> None:
        """Mark the next running-to-stopped transition as an intentional stop."""
        key = str(engine_id).strip().casefold()
        if not key:
            raise ValueError("engine_id is required")
        with self._lock:
            self._expected_stops.add(key)

    def clear_expected_stop(self, engine_id: str) -> None:
        key = str(engine_id).strip().casefold()
        with self._lock:
            self._expected_stops.discard(key)

    def observe(
        self,
        engine_id: str,
        display_name: str,
        *,
        configured: bool,
        running: bool | None,
        ready: bool | None = None,
        recovery_required: bool = False,
        detail: str = "",
    ) -> EngineStatus:
        key = str(engine_id).strip().casefold()
        if not key:
            raise ValueError("engine_id is required")
        state = self.derive_state(
            configured=bool(configured), running=running,
            ready=ready, recovery_required=bool(recovery_required),
        )
        if state not in _ALLOWED_STATES:
            state = "unknown"
        checked_at = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
        with self._lock:
            previous = self._statuses.get(key)
            if previous and previous.state in {"running", "healthy", "degraded"} and state == "stopped":
                if key in self._expected_stops:
                    self._expected_stops.discard(key)
                else:
                    state = "failed"
                    detail = (str(detail).rstrip() + " Process exited unexpectedly since the previous check.").strip()
            elif state in {"running", "healthy", "degraded", "not_configured"}:
                self._expected_stops.discard(key)
            transitions = previous.transition_count if previous else 0
            if previous is None or previous.state != state:
                transitions += 1
                self._events.append({
                    "engine_id": key,
                    "display_name": str(display_name)[:80],
                    "from": previous.state if previous else "unobserved",
                    "to": state,
                    "at": checked_at,
                })
                self._events = self._events[-self.MAX_EVENTS:]
            status = EngineStatus(
                engine_id=key,
                display_name=str(display_name)[:80],
                state=state,
                detail=str(detail)[:500],
                checked_at=checked_at,
                transition_count=transitions,
            )
            self._statuses[key] = status
            return status

    def get(self, engine_id: str) -> EngineStatus | None:
        with self._lock:
            return self._statuses.get(str(engine_id).casefold())

    def snapshot(self) -> dict[str, EngineStatus]:
        with self._lock:
            return dict(self._statuses)

    def events(self) -> list[dict[str, str]]:
        with self._lock:
            return [dict(item) for item in self._events]
