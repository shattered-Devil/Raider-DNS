"""Single-instance coordination for the Raider DNS desktop application.

A per-user QLockFile prevents duplicate windows and duplicate tray icons across
normal launches and UAC elevation handoffs. A local Qt socket lets a second
normal launch ask the existing instance to restore its window from the tray.
"""
from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Callable

from PySide6.QtCore import QLockFile
from PySide6.QtNetwork import QLocalServer, QLocalSocket


class SingleInstanceGuard:
    """Own the application lock and local activation endpoint."""

    def __init__(self, lock_path: Path) -> None:
        self.lock_path = Path(lock_path)
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = QLockFile(str(self.lock_path))
        # QLockFile also checks whether a recorded PID still exists. The default
        # stale-lock interval is retained so live owners are never displaced.
        digest = hashlib.sha256(str(self.lock_path.resolve()).casefold().encode("utf-8")).hexdigest()[:20]
        self.server_name = f"RaiderDNS-{digest}"
        self._server: QLocalServer | None = None
        self._on_activate: Callable[[], None] | None = None
        self._acquired = False

    @property
    def acquired(self) -> bool:
        return self._acquired

    def acquire(self, timeout_seconds: float = 0.0, poll_interval: float = 0.1) -> bool:
        """Acquire immediately or wait for the previous instance to finish.

        The wait is used only by the hidden ``--admin-handoff`` child. A normal
        second launch returns immediately and asks the existing UI to activate.
        """
        timeout = max(0.0, float(timeout_seconds))
        interval = max(0.025, min(0.5, float(poll_interval)))
        deadline = time.monotonic() + timeout
        while True:
            if self._lock.tryLock(0):
                self._acquired = True
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(interval)

    def start_activation_server(self, callback: Callable[[], None]) -> bool:
        """Listen for activation requests from a second normal launch."""
        if not self._acquired:
            return False
        self._on_activate = callback
        server = QLocalServer()
        # The process lock proves no live Raider DNS owner exists, so removing
        # an orphaned local-server endpoint here cannot disconnect a live app.
        QLocalServer.removeServer(self.server_name)
        if not server.listen(self.server_name):
            server.deleteLater()
            return False
        server.newConnection.connect(self._accept_connections)
        self._server = server
        return True

    def _accept_connections(self) -> None:
        server = self._server
        if server is None:
            return
        while server.hasPendingConnections():
            client = server.nextPendingConnection()
            if client is None:
                continue
            client.readyRead.connect(lambda socket=client: self._read_client(socket))
            client.disconnected.connect(client.deleteLater)
            # The activation message may already be buffered by the time the
            # connection is accepted; read it immediately as well.
            if client.bytesAvailable():
                self._read_client(client)

    def _read_client(self, client: QLocalSocket) -> None:
        try:
            command = bytes(client.readAll()).decode("utf-8", errors="ignore").strip().casefold()
        except (AttributeError, RuntimeError):
            command = ""
        if command == "activate" and self._on_activate is not None:
            self._on_activate()
        if client.state() != QLocalSocket.LocalSocketState.UnconnectedState:
            client.disconnectFromServer()

    def request_activation(self, attempts: int = 4) -> bool:
        """Ask the current instance to restore/raise its existing main window."""
        retries = max(1, min(8, int(attempts)))
        for attempt in range(retries):
            socket = QLocalSocket()
            socket.connectToServer(self.server_name)
            if socket.waitForConnected(350):
                socket.write(b"activate\n")
                written = socket.waitForBytesWritten(500)
                socket.disconnectFromServer()
                socket.deleteLater()
                if written:
                    return True
            socket.abort()
            socket.deleteLater()
            if attempt + 1 < retries:
                time.sleep(0.1)
        return False

    def release(self) -> None:
        """Close the IPC endpoint and release the process lock exactly once."""
        if self._server is not None:
            self._server.close()
            self._server.deleteLater()
            self._server = None
            QLocalServer.removeServer(self.server_name)
        if self._acquired:
            self._lock.unlock()
            self._acquired = False
