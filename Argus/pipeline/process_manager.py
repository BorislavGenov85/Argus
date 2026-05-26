"""
ProcessManager — centralized external process lifecycle.

Replaces the scattered PID fields on the model. Handles:
- Starting subprocesses in their own process group
- Tracking active processes by label
- Graceful stop (SIGTERM -> wait -> SIGKILL)
- Cleanup on scan end
- Timeout handling
"""

from __future__ import annotations

import os
import signal
import subprocess
import threading
from typing import Optional


class ProcessManager:
    """
    One instance per scan session. Thread-safe.

    Usage:
        pm = ProcessManager()
        proc = pm.start('nmap', ['nmap', '-T4', '10.10.10.1'])
        # ... read proc.stdout ...
        pm.cleanup()  # kills everything still running
    """

    def __init__(self):
        self._processes: dict[str, subprocess.Popen] = {}
        self._lock = threading.Lock()

    def start(
        self,
        label: str,
        cmd: list[str],
        timeout: int | None = None,
    ) -> subprocess.Popen:
        """
        Start a subprocess in its own process group.

        Args:
            label: identifier for this process (e.g. 'nmap', 'gobuster_80')
            cmd: command + args
            timeout: optional max seconds (not enforced here — caller reads output)
        """
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
            preexec_fn=os.setsid,
        )

        with self._lock:
            # If there's already a process with this label, kill it first
            if label in self._processes:
                self._kill_one(label)
            self._processes[label] = proc

        return proc

    def stop(self, label: str) -> None:
        """Gracefully stop a single process by label."""
        with self._lock:
            self._kill_one(label)

    def stop_all(self) -> None:
        """Stop all tracked processes."""
        with self._lock:
            for label in list(self._processes.keys()):
                self._kill_one(label)

    def cleanup(self) -> None:
        """Final cleanup — kill everything, wait for exit."""
        self.stop_all()

    def is_running(self, label: str) -> bool:
        with self._lock:
            proc = self._processes.get(label)
            if proc is None:
                return False
            return proc.poll() is None

    def remove(self, label: str) -> None:
        """Remove a finished process from tracking."""
        with self._lock:
            self._processes.pop(label, None)

    # ----- internal -----

    def _kill_one(self, label: str) -> None:
        """Must be called with lock held."""
        proc = self._processes.pop(label, None)
        if proc is None:
            return

        if proc.poll() is not None:
            return  # already dead

        try:
            pgid = os.getpgid(proc.pid)
            os.killpg(pgid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass

        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                pgid = os.getpgid(proc.pid)
                os.killpg(pgid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
