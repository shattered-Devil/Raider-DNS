"""External sing-box TUN integration for full device/application IP traffic.

The app does not contain a proxy server or secret credentials. A user provides
an official sing-box executable and a JSON configuration with a TUN inbound and
an explicit proxy outbound as the default route. This is separate from DNS-only
transport encryption.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from raider_dns.storage import app_data_dir


@dataclass(slots=True)
class TunnelResult:
    success: bool
    message: str
    details: str = ""


def validate_singbox_config(path: Path) -> TunnelResult:
    if not path.is_file():
        return TunnelResult(False, "sing-box JSON config not found", str(path))
    try:
        config: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return TunnelResult(False, "Invalid sing-box JSON configuration", str(exc))
    if not isinstance(config, dict):
        return TunnelResult(False, "Invalid sing-box configuration", "The root must be a JSON object.")
    inbounds = config.get("inbounds", [])
    if not isinstance(inbounds, list):
        return TunnelResult(False, "Invalid sing-box configuration", "inbounds must be a list.")
    tun_inbounds = [item for item in inbounds if isinstance(item, dict) and item.get("type") == "tun"]
    if not tun_inbounds:
        return TunnelResult(False, "TUN inbound is required", "Add a sing-box inbound with type=tun to capture device traffic.")
    if not any(item.get("auto_route") is True and item.get("strict_route") is True for item in tun_inbounds):
        return TunnelResult(False, "Secure automatic routing is not enabled", "At least one TUN inbound must set auto_route=true and strict_route=true to reduce route conflicts and bypass/leak risk on Windows.")
    outbounds = config.get("outbounds", [])
    if not isinstance(outbounds, list) or not outbounds:
        return TunnelResult(False, "Proxy outbound required", "Add a working proxy outbound to your sing-box configuration.")
    outbound_by_tag = {item.get("tag"): item for item in outbounds if isinstance(item, dict) and isinstance(item.get("tag"), str)}
    route = config.get("route", {})
    final_tag = route.get("final") if isinstance(route, dict) else None
    if not isinstance(final_tag, str) or final_tag not in outbound_by_tag:
        return TunnelResult(False, "Explicit default route required", "Set route.final to the tag of the outbound that should carry general traffic.")
    route = route if isinstance(route, dict) else {}
    anti_loop = route.get("auto_detect_interface") is True or bool(route.get("default_interface")) or bool(outbound_by_tag[final_tag].get("bind_interface"))
    if not anti_loop:
        return TunnelResult(False, "Proxy routing loop protection required", "Set route.auto_detect_interface=true, route.default_interface, or bind_interface on the final outbound so the proxy connection does not loop into the TUN.")
    final = outbound_by_tag[final_tag]
    final_type = str(final.get("type", "")).casefold()
    if final_type in {"direct", "block", "dns"}:
        return TunnelResult(False, "Default route is not a proxy", f"route.final points to '{final_type}'. Select a proxy outbound so traffic is actually tunneled.")
    # Selectors/urltest groups are allowed when they include at least one real
    # remote proxy; plain direct/block fallbacks are never counted as the proxy.
    if final_type in {"selector", "urltest"}:
        tags = final.get("outbounds", [])
        if not isinstance(tags, list) or not tags:
            return TunnelResult(False, "Proxy group has no members", "The default selector/urltest outbound must reference one or more remote proxy outbounds.")
        candidates = [outbound_by_tag.get(tag) for tag in tags if isinstance(tag, str)]
        if len(candidates) != len(tags) or any(not isinstance(item, dict) for item in candidates):
            return TunnelResult(False, "Proxy group contains an unknown outbound", "Every selector/urltest member must reference an existing outbound.")
        forbidden = [str(item.get("type", "")).casefold() for item in candidates if str(item.get("type", "")).casefold() in {"direct", "block", "dns", "selector", "urltest"}]
        if forbidden:
            return TunnelResult(False, "Proxy group can bypass the tunnel", "The default selector/urltest group must not include direct, block, DNS-only, or nested group choices. Use only real remote proxy outbounds so the selected default cannot silently bypass the tunnel.")
        if any(not isinstance(item.get("server"), str) or not item.get("server") for item in candidates):
            return TunnelResult(False, "Proxy group has an incomplete remote endpoint", "Every default selector/urltest member must define its remote server. The official sing-box validator checks remaining protocol-specific fields.")
    else:
        if not isinstance(final.get("server"), str) or not final.get("server"):
            return TunnelResult(False, "Proxy endpoint needs checking", "The default outbound has no server field. This app's safety check requires an explicit remote endpoint.")
    # Explicit rules can override route.final. Rather than claiming that the
    # whole device is tunneled, surface this when a user-defined rule sends traffic direct.
    route_rules = route.get("rules", [])
    direct_rule_warning = False
    if isinstance(route_rules, list):
        for rule in route_rules:
            if not isinstance(rule, dict):
                continue
            outbound_tag = rule.get("outbound")
            if isinstance(outbound_tag, str) and outbound_tag in outbound_by_tag:
                if str(outbound_by_tag[outbound_tag].get("type", "")).casefold() == "direct":
                    direct_rule_warning = True
                    break
    details = "TUN uses strict automatic routes and anti-loop routing. The official sing-box executable must still validate it, and live routing/leak tests are required."
    if direct_rule_warning:
        details += " Warning: at least one explicit routing rule selects a direct outbound; matching traffic will bypass the tunnel."
    details += " Ensure DNS queries are also routed through the intended resolver/tunnel in the sing-box config; TUN setup alone does not prove DNS leak protection."
    return TunnelResult(True, "TUN configuration passed Raider DNS checks", details)


class SingBoxTunnelController:
    """Own the sing-box TUN process and make Windows shutdown recoverable.

    Windows-specific lifecycle rules:
    * Start the console process with a hidden window, not CREATE_NO_WINDOW. The
      hidden console is required for taskkill without /F to deliver the close
      event that lets sing-box release WinTun and its routes cleanly.
    * Never fall back to TerminateProcess/process.kill for a live TUN engine.
      If graceful stop cannot be confirmed, keep the session record and keep
      the UI open so the user can retry instead of leaving a half-cleaned driver.
    * Persist the exact PID, executable and config path. On the next launch we
      only inspect/stop that exact recorded process; never kill by image name.
    """

    SESSION_SCHEMA = 1

    def __init__(self) -> None:
        self.process: subprocess.Popen[bytes] | None = None
        self.binary_path: Path | None = None
        self.config_path: Path | None = None
        self.external_pid: int | None = None
        self._lock = threading.RLock()
        self.log_path = (
            Path.home() / ".config" / "raider-dns" / "sing-box.log"
            if os.name != "nt"
            else app_data_dir() / "sing-box.log"
        )
        self.session_path = app_data_dir() / "singbox-session.json"

    @property
    def is_running(self) -> bool:
        process = self.process
        if process is not None and process.poll() is None:
            return True
        return self.external_pid is not None

    @property
    def has_recovery_record(self) -> bool:
        return self.session_path.is_file()

    @staticmethod
    def _hidden_console_startupinfo() -> subprocess.STARTUPINFO | None:
        """Return hidden-window startup settings while preserving a console.

        Do not replace this with CREATE_NO_WINDOW: sing-box needs the hidden
        console window's close lifecycle so Windows can ask it to clean up TUN.
        """
        if os.name != "nt":
            return None
        startup_info = subprocess.STARTUPINFO()
        startup_info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startup_info.wShowWindow = subprocess.SW_HIDE
        return startup_info

    @staticmethod
    def _ps_quote(value: str) -> str:
        return "'" + value.replace("'", "''") + "'"

    def _persist_session(self, pid: int, binary: Path, config: Path) -> None:
        self.session_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": self.SESSION_SCHEMA,
            "pid": int(pid),
            "binary_path": str(binary.resolve()),
            "config_path": str(config.resolve()),
            "started_at_utc": datetime.now(timezone.utc).isoformat(),
        }
        fd, temporary_name = tempfile.mkstemp(
            prefix=".singbox-session-", suffix=".tmp", dir=str(self.session_path.parent)
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(payload, handle, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.chmod(temporary, 0o600)
            except OSError:
                pass
            os.replace(temporary, self.session_path)
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    def _read_session(self) -> dict[str, Any] | None:
        try:
            raw = json.loads(self.session_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(raw, dict) or raw.get("schema_version") != self.SESSION_SCHEMA:
            return {}
        try:
            pid = int(raw.get("pid", 0))
            binary = Path(str(raw.get("binary_path", ""))).resolve()
            config = Path(str(raw.get("config_path", ""))).resolve()
        except (TypeError, ValueError, OSError, RuntimeError):
            return {}
        if pid <= 0 or not str(binary) or not str(config):
            return {}
        return {"pid": pid, "binary_path": binary, "config_path": config}

    def _clear_session(self) -> None:
        try:
            self.session_path.unlink(missing_ok=True)
        except OSError:
            # Keep the record if Windows cannot remove it. Startup recovery can
            # verify the PID again and safely retry rather than losing ownership.
            pass

    def _matching_process_state(self, pid: int, binary: Path, config: Path) -> bool | None:
        """True=exact process, False=absent/different PID owner, None=unknown."""
        if os.name != "nt":
            return False
        script = (
            f"$targetPid = {int(pid)}; "
            f"$expectedExe = {self._ps_quote(str(binary.resolve()))}; "
            f"$expectedConfig = {self._ps_quote(str(config.resolve()))}; "
            "$p = Get-CimInstance Win32_Process -Filter \"ProcessId = $targetPid\" -ErrorAction SilentlyContinue; "
            "if (-not $p) { [Console]::Out.Write('ABSENT'); exit 0 }; "
            "$exeMatch = $p.ExecutablePath -and [String]::Equals($p.ExecutablePath, $expectedExe, [StringComparison]::OrdinalIgnoreCase); "
            "$configMatch = $p.CommandLine -and $p.CommandLine.IndexOf($expectedConfig, [StringComparison]::OrdinalIgnoreCase) -ge 0; "
            "if ($exeMatch -and $configMatch) { [Console]::Out.Write('MATCH') } else { [Console]::Out.Write('OTHER') }"
        )
        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        try:
            result = subprocess.run(
                ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                capture_output=True,
                text=True,
                timeout=6.0,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if result.returncode != 0:
            return None
        state = result.stdout.strip().upper()
        if state == "MATCH":
            return True
        if state in {"ABSENT", "OTHER"}:
            return False
        return None

    def validate(self, binary: Path, config: Path, timeout: float = 12.0) -> TunnelResult:
        if not binary.is_file():
            return TunnelResult(False, "sing-box executable not found", str(binary))
        structural = validate_singbox_config(config)
        if not structural.success:
            return structural
        try:
            result = subprocess.run(
                [str(binary), "check", "-c", str(config)],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return TunnelResult(False, "Could not validate sing-box configuration", str(exc))
        if result.returncode:
            return TunnelResult(False, "sing-box rejected the configuration", (result.stderr or result.stdout).strip())
        return TunnelResult(True, "sing-box configuration validated", (result.stdout or structural.details).strip())

    def start(self, binary: Path, config: Path) -> TunnelResult:
        with self._lock:
            if self.is_running:
                return TunnelResult(True, "Full traffic tunnel is already running.")

            # A process from a previous crashed app session must be recovered
            # before another TUN instance is allowed to start.
            if self.has_recovery_record:
                recovered = self.recover_previous_session(timeout=8.0)
                if not recovered.success:
                    return TunnelResult(
                        False,
                        "Previous sing-box session needs recovery before a new tunnel can start",
                        recovered.message + ("\n" + recovered.details if recovered.details else ""),
                    )
                if "no adapter, route, or driver was removed" in recovered.details.casefold():
                    return TunnelResult(
                        False,
                        "Previous tunnel process exited; verify Windows networking before restarting",
                        recovered.details + " After Diagnostics confirms that the physical adapter and default route are healthy, retry the tunnel start.",
                    )

            if os.name != "nt":
                return TunnelResult(False, "Windows-only operation", "The TUN controller currently targets Windows.")
            validation = self.validate(binary, config)
            if not validation.success:
                return validation
            if not self.is_admin():
                return TunnelResult(False, "Administrator permission required", "TUN routing changes require elevation. Restart Raider DNS as administrator and retry.")

            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                startup_info = self._hidden_console_startupinfo()
                with self.log_path.open("ab") as log_handle:
                    self.process = subprocess.Popen(
                        [str(binary), "run", "-c", str(config)],
                        cwd=str(binary.parent),
                        stdout=log_handle,
                        stderr=log_handle,
                        startupinfo=startup_info,
                        close_fds=True,
                    )
                self.binary_path = binary.resolve()
                self.config_path = config.resolve()
                self._persist_session(self.process.pid, self.binary_path, self.config_path)
            except (OSError, ValueError) as exc:
                if self.process is not None and self.process.poll() is None:
                    cleanup = self.stop(timeout=8.0)
                    return TunnelResult(
                        False,
                        "Could not persist the tunnel recovery record",
                        f"{exc}. A graceful cleanup was requested: {cleanup.message}. {cleanup.details}",
                    )
                self.process = None
                return TunnelResult(False, "Could not start or record the full traffic tunnel", str(exc))

            time.sleep(0.55)
            if self.process.poll() is not None:
                exit_code = self.process.returncode
                tail = self.log_path.read_text(encoding="utf-8", errors="replace")[-2000:] if self.log_path.exists() else ""
                self.process = None
                self.external_pid = None
                # Keep the journal: an engine that exited during TUN startup may
                # have changed routes/interfaces before it failed. Do not assume
                # those resources were restored just because the process is gone.
                return TunnelResult(
                    False,
                    "sing-box exited during startup; network state needs checking",
                    f"Exit code: {exit_code}. Recovery record retained at {self.session_path}. {tail or 'See sing-box.log for details.'} Check Diagnostics before retrying.",
                )
            return TunnelResult(
                True,
                "sing-box TUN process started",
                "The process is recorded for crash recovery and launched with a hidden console so Windows can deliver a clean close event. This confirms startup only; verify live routing and DNS before relying on the tunnel.",
            )

    @staticmethod
    def is_admin() -> bool:
        if os.name != "nt":
            return False
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False

    def check_for_unexpected_exit(self) -> TunnelResult | None:
        """Report an active-session process exit without guessing at route cleanup.

        The durable session marker is deliberately retained. If sing-box exits
        unexpectedly, Windows may have completed normal TUN cleanup, or it may
        have left route/interface state behind. A later explicit recovery check
        can verify the exact process identity; Raider DNS never removes arbitrary
        VPN adapters or default routes based only on a missing process.
        """
        with self._lock:
            process = self.process
            if process is None:
                return None
            try:
                exit_code = process.poll()
            except OSError as exc:
                return TunnelResult(
                    False,
                    "Could not inspect the active sing-box process",
                    f"{exc}. The process reference and recovery record were retained. Review the TUN adapter and default route in Diagnostics; no automatic adapter or route changes were made.",
                )
            if exit_code is None:
                return None
            self.process = None
            self.external_pid = None
            return TunnelResult(
                False,
                "sing-box exited unexpectedly while the tunnel was active",
                f"sing-box exit code: {exit_code}. The recovery record was retained at {self.session_path}. Check the physical adapter and default route in Diagnostics before starting another tunnel. No adapter, route, or driver was removed automatically.",
            )

    def recover_previous_session(self, timeout: float = 8.0) -> TunnelResult:
        """Recover only a previously recorded, exact Raider DNS sing-box process."""
        with self._lock:
            session = self._read_session()
            if session is None:
                return TunnelResult(True, "No previous sing-box session requires recovery.")
            if not session:
                # A malformed marker is not permission to search/kill processes.
                return TunnelResult(
                    False,
                    "Previous sing-box recovery record is invalid",
                    f"The record at {self.session_path} could not be validated. No processes or adapters were changed; inspect the network before starting another TUN session.",
                )
            pid = int(session["pid"])
            binary = Path(session["binary_path"])
            config = Path(session["config_path"])
            process_state = self._matching_process_state(pid, binary, config)
            if process_state is None:
                return TunnelResult(
                    False,
                    "Could not verify the previous sing-box process",
                    "Windows process inspection failed. The recovery record was preserved and no process was stopped. Run Raider DNS as administrator and retry recovery.",
                )
            if not process_state:
                self._clear_session()
                return TunnelResult(
                    True,
                    "Previous sing-box process is no longer running",
                    "The stale process record was removed. No adapter, route, or driver was removed automatically because it could belong to another VPN or network tool. If Windows still has no connectivity, run Diagnostics and inspect the TUN adapter before applying repairs.",
                )
            self.external_pid = pid
            self.binary_path = binary
            self.config_path = config
            return self.stop(timeout=timeout)

    def stop(self, timeout: float = 8.0) -> TunnelResult:
        """Request normal sing-box shutdown; never force-kill a live TUN engine."""
        with self._lock:
            process = self.process
            if process is not None and process.poll() is not None:
                self.process = None
                self.external_pid = None
                self._clear_session()
                return TunnelResult(
                    True,
                    "sing-box had already exited",
                    "The process is gone and no termination request was sent to its PID. If the network still appears disconnected, check the TUN adapter and default route in Diagnostics; unknown network devices are not removed automatically.",
                )
            pid = process.pid if process is not None else self.external_pid
            if pid is None:
                return TunnelResult(True, "Full traffic tunnel is not running.")

            binary = self.binary_path
            config = self.config_path
            if process is None:
                if binary is None or config is None:
                    session = self._read_session()
                    if not session:
                        self.external_pid = None
                        return TunnelResult(False, "Tunnel process ownership could not be verified", "No valid session record is available. No process was stopped.")
                    binary = Path(session["binary_path"])
                    config = Path(session["config_path"])
                process_state = self._matching_process_state(pid, binary, config)
                if process_state is None:
                    return TunnelResult(False, "Could not verify sing-box process identity", "The recovery record is preserved; no process was stopped.")
                if not process_state:
                    self.external_pid = None
                    self._clear_session()
                    return TunnelResult(True, "Previous sing-box process is already stopped", "The process is gone. No broad adapter/driver cleanup was attempted.")

            try:
                # This is intentionally taskkill without /F or /T. With sing-box
                # started using SW_HIDE rather than CREATE_NO_WINDOW, Windows
                # closes its hidden console and allows sing-box/WinTun cleanup.
                result = subprocess.run(
                    ["taskkill.exe", "/PID", str(pid)],
                    capture_output=True,
                    text=True,
                    timeout=max(3.0, float(timeout)),
                    check=False,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except (OSError, subprocess.SubprocessError) as exc:
                still_alive = process is not None and process.poll() is None
                if still_alive or process is None:
                    return TunnelResult(
                        False,
                        "Could not request graceful sing-box shutdown",
                        f"{exc}. The process/session reference was retained; Raider DNS will not force-kill the TUN engine.",
                    )
                result = None

            if process is not None:
                try:
                    process.wait(timeout=max(3.0, float(timeout)))
                except subprocess.TimeoutExpired:
                    return TunnelResult(
                        False,
                        "sing-box did not finish its graceful shutdown",
                        "The process may still own WinTun resources or routes. The session record remains. Keep Raider DNS open and retry Stop tunnel; force-kill is disabled to avoid an unclean driver teardown.",
                    )
                except OSError as exc:
                    return TunnelResult(False, "Could not confirm sing-box shutdown", str(exc))
                if process.poll() is None:
                    return TunnelResult(False, "sing-box is still running", "No forced termination was attempted; the session record remains for recovery.")
            else:
                deadline = time.monotonic() + max(3.0, float(timeout))
                while time.monotonic() < deadline:
                    state = self._matching_process_state(pid, binary, config)
                    if state is False:
                        break
                    if state is None:
                        return TunnelResult(False, "Could not confirm the previous sing-box process stopped", "The recovery marker is preserved and no force-kill was attempted.")
                    time.sleep(0.2)
                else:
                    return TunnelResult(
                        False,
                        "Previous sing-box process did not finish its graceful shutdown",
                        "The recovery record remains. No force-kill was attempted; retry recovery from an elevated Raider DNS session.",
                    )

            if result is not None and result.returncode != 0:
                # taskkill can race with a process that exits on its own. The
                # process handle/identity check above is authoritative.
                if process is None and self._matching_process_state(pid, binary, config) is not False:
                    return TunnelResult(False, "Windows did not confirm graceful sing-box shutdown", (result.stderr or result.stdout).strip())
                if process is not None and process.poll() is None:
                    return TunnelResult(False, "Windows did not confirm graceful sing-box shutdown", (result.stderr or result.stdout).strip())

            self.process = None
            self.external_pid = None
            self._clear_session()
            return TunnelResult(
                True,
                "Full traffic tunnel stopped gracefully",
                "Windows confirmed the sing-box process exited through the non-forced shutdown path. Allow a moment for the TUN adapter and routes to settle, then verify connectivity in Diagnostics. No unrelated adapters or routes were modified.",
            )

