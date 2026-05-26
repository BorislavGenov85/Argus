"""
ReconContext — shared mutable state that all modules read from and write to.

This is the single source of truth during a scan. Every module receives the
same context instance. No module owns the context; they all contribute to it.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any


@dataclass
class HttpService:
    """An HTTP(S) service discovered on a port."""
    port: int
    protocol: str = 'tcp'
    is_https: bool = False
    product: str = ''
    version: str = ''

    @property
    def scheme(self) -> str:
        return 'https' if self.is_https else 'http'

    @property
    def base_url(self) -> str:
        return f'{self.scheme}://{{host}}:{self.port}'


@dataclass
class DiscoveredDomain:
    """A domain extracted during recon, tagged with its source."""
    domain: str
    source: str  # 'tls_san', 'tls_cn', 'http_redirect', 'html_body', 'gobuster_redirect', 'manual'

    def __hash__(self):
        return hash(self.domain)

    def __eq__(self, other):
        if isinstance(other, DiscoveredDomain):
            return self.domain == other.domain
        return NotImplemented


class ReconContext:
    """
    Thread-safe shared state for a single scan session.

    Modules populate this during execution. The orchestrator reads it
    to decide which modules to run next.
    """

    def __init__(
        self,
        session_id: int,
        target: str,
        options: dict[str, Any] | None = None,
        stop_checker: 'Callable[[], bool] | None' = None,
    ):
        self.session_id = session_id
        self.target = target
        self.options = options or {}

        self._lock = threading.Lock()

        # External stop checker — called by should_stop to check DB status
        # without monkey-patching. Injected by the Celery task.
        self._stop_checker = stop_checker

        # ----- populated by modules -----
        self.open_ports: set[int] = set()
        self.port_details: dict[int, dict] = {}  # port -> full nmap result dict
        self.http_services: list[HttpService] = []

        self.discovered_domains: dict[str, DiscoveredDomain] = {}  # domain -> DiscoveredDomain
        self.confirmed_domains: list[str] = []  # set by user confirmation

        self.technologies: set[str] = set()

        # Findings are the final output
        from pipeline.finding import Finding
        self.findings: list[Finding] = []

        # Track module execution
        self.completed_modules: set[str] = set()
        self.failed_modules: set[str] = set()

        # Stop flag
        self._stop_requested = False

    # ----- thread-safe mutations -----

    def add_port(self, port: int, details: dict) -> None:
        with self._lock:
            self.open_ports.add(port)
            self.port_details[port] = details

    def add_http_service(self, service: HttpService) -> None:
        with self._lock:
            # Avoid duplicates by port
            if not any(s.port == service.port for s in self.http_services):
                self.http_services.append(service)

    def add_discovered_domain(self, domain: str, source: str) -> None:
        with self._lock:
            domain = domain.lower().strip('.')
            if domain and domain not in self.discovered_domains:
                self.discovered_domains[domain] = DiscoveredDomain(
                    domain=domain,
                    source=source,
                )

    def add_finding(self, finding: 'Finding') -> None:
        with self._lock:
            self.findings.append(finding)

    def mark_completed(self, module_name: str) -> None:
        with self._lock:
            self.completed_modules.add(module_name)

    def mark_failed(self, module_name: str) -> None:
        with self._lock:
            self.failed_modules.add(module_name)

    # ----- stop control -----

    def request_stop(self) -> None:
        self._stop_requested = True

    @property
    def should_stop(self) -> bool:
        if self._stop_requested:
            return True
        if self._stop_checker and self._stop_checker():
            self._stop_requested = True  # cache it
            return True
        return False

    # ----- convenience -----

    @property
    def has_http(self) -> bool:
        return len(self.http_services) > 0

    @property
    def has_confirmed_domains(self) -> bool:
        return len(self.confirmed_domains) > 0

    @property
    def unique_discovered_domains(self) -> list[str]:
        return sorted(self.discovered_domains.keys())

    def __repr__(self):
        return (
            f'<ReconContext target={self.target!r} '
            f'ports={len(self.open_ports)} '
            f'http={len(self.http_services)} '
            f'domains={len(self.discovered_domains)} '
            f'findings={len(self.findings)}>'
        )
