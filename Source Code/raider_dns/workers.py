"""Qt thread-pool worker with explicit result/error signals."""
from __future__ import annotations

import traceback
from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QObject, QRunnable, Signal, Slot


class WorkerSignals(QObject):
    result = Signal(object)
    error = Signal(str)
    finished = Signal()


class Worker(QRunnable):
    def __init__(self, task: Callable[[], Any]) -> None:
        super().__init__()
        self.task = task
        self.signals = WorkerSignals()
        self.setAutoDelete(True)

    @Slot()
    def run(self) -> None:
        try:
            self.signals.result.emit(self.task())
        except Exception as exc:  # fail into UI instead of silently killing a worker
            self.signals.error.emit(f"{exc}\n{traceback.format_exc(limit=5)}")
        finally:
            self.signals.finished.emit()


class UiDispatcher(QObject):
    """Marshal callbacks from worker threads onto the QObject's owning thread.

    Signal emissions are safe across threads; the decorated receiver runs on the
    dispatcher object's thread, which is the GUI thread when created by MainWindow.
    """
    invoke = Signal(object, object)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.invoke.connect(self._dispatch)

    @Slot(object, object)
    def _dispatch(self, callback: Callable[[Any], None], payload: Any) -> None:
        callback(payload)
