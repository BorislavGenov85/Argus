"""
NmapModule — port scanning with live output parsing and domain extraction.

Phase: discovery (always runs first)
Produces: open_ports, http_services, discovered_domains
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from pipeline.base_module import ReconModule
from pipeline.context import HttpService
from pipeline.domain_extractor import DomainExtractor
from pipeline.finding import Finding, FindingType, Severity
from pipeline.events import EventType

if TYPE_CHECKING:
    from pipeline.context import ReconContext
    from pipeline.events import EventBus


# Known HTTP service names
HTTP_SERVICES = {'http', 'http-alt', 'https', 'ssl/http', 'http-proxy', 'https-alt'}
HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8008, 8888, 3000, 5000}

PORT_REGEX = re.compile(r'^(\d+)\/(tcp|udp)\s+open\s+(\S+)\s*(.*)$')


class NmapModule(ReconModule):
    name = 'nmap'
    phase = 'discovery'
    requires = []

    def should_run(self, context: ReconContext) -> bool:
        return True  # Always runs — it's the entry point

    def skip_reason(self, context: ReconContext) -> str:
        return 'nmap: no reason to skip.'

    def run(self, context: ReconContext, bus: EventBus) -> None:
        from pipeline.process_manager import ProcessManager

        flags = context.options.get('nmap_flags', '-T4 --open')
        if not flags.strip():
            flags = '-T4 -sV -Pn --top-ports 1000'

        cmd = [
            'stdbuf', '-oL', '-eL',
            'nmap',
            *flags.split(),
            '--stats-every', '2s',
            context.target,
        ]

        # Get the shared process manager from context options
        pm: ProcessManager = context.options['process_manager']
        proc = pm.start('nmap', cmd)

        if not proc.stdout:
            raise RuntimeError('No stdout from nmap process')

        try:
            for raw_line in iter(proc.stdout.readline, ''):
                if context.should_stop:
                    pm.stop('nmap')
                    return

                line = raw_line.strip()
                if not line:
                    continue

                # Log every line
                bus.log(self.name, line)

                # Extract domains from every line
                for ed in DomainExtractor.from_nmap_line(line):
                    context.add_discovered_domain(ed.domain, ed.source)

                # Parse port lines
                match = PORT_REGEX.search(line)
                if not match:
                    continue

                port = int(match.group(1))
                protocol = match.group(2)
                service = match.group(3)
                version_str = (match.group(4) or '').strip()

                is_http = (
                    service.lower() in HTTP_SERVICES
                    or port in HTTP_PORTS
                    or 'http' in version_str.lower()
                )

                port_data = {
                    'port': port,
                    'protocol': protocol,
                    'state': 'open',
                    'service': service,
                    'product': version_str,
                    'version': '',
                    'extra_info': '',
                    'is_http': is_http,
                }

                context.add_port(port, port_data)

                if is_http:
                    context.add_http_service(HttpService(
                        port=port,
                        protocol=protocol,
                        is_https=(port in {443, 8443} or service in {'https', 'ssl/http'}),
                        product=version_str,
                    ))

                # Finding
                context.add_finding(Finding(
                    type=FindingType.PORT,
                    source=self.name,
                    severity=Severity.INFO,
                    data=port_data,
                    description=f'{port}/{protocol} open — {service} {version_str}'.strip(),
                ))

                # WS event
                bus.emit(
                    EventType.PORT_FOUND,
                    module=self.name,
                    data=port_data,
                )
        finally:
            proc.wait()
            pm.remove('nmap')

        if proc.returncode == -15:
            return  # killed by stop

        if proc.returncode not in (0, None):
            raise RuntimeError(f'nmap exited with code {proc.returncode}')
