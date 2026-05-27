"""
GobusterModule — directory/file enumeration on HTTP services.

Phase: discovery
Requires: nmap (needs http_services populated)
Produces: directory findings, discovered_domains from redirect URLs
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from pipeline.base_module import ReconModule
from pipeline.domain_extractor import DomainExtractor
from pipeline.finding import Finding, FindingType, Severity
from pipeline.events import EventType

if TYPE_CHECKING:
    from pipeline.context import ReconContext
    from pipeline.events import EventBus


GOBUSTER_LINE_RE = re.compile(
    r'^(/\S*)'           # path
    r'\s+\(Status:\s*(\d+)\)'  # status code
    r'(?:\s+\[Size:\s*(\d+)\])?'   # size — optional
    r'(?:\s+\[-->\s*([^\]]+)\])?'  # redirect target — optional
)


class GobusterModule(ReconModule):
    name = 'gobuster'
    phase = 'discovery'
    requires = ['nmap']

    def should_run(self, context: ReconContext) -> bool:
        wordlist = context.options.get('dir_wordlist', '')
        return context.has_http and bool(wordlist)

    def skip_reason(self, context: ReconContext) -> str:
        if not context.has_http:
            return 'gobuster: no HTTP services found.'
        if not context.options.get('dir_wordlist'):
            return 'gobuster: no wordlist configured.'
        return 'gobuster: preconditions not met.'

    def run(self, context: ReconContext, bus: EventBus) -> None:
        from pipeline.process_manager import ProcessManager

        pm: ProcessManager = context.options['process_manager']
        wordlist = context.options['dir_wordlist']

        for svc in context.http_services:
            if context.should_stop:
                return

            base_url = f'{svc.scheme}://{context.target}:{svc.port}'
            label = f'gobuster_{svc.port}'

            bus.log(self.name, f'Scanning {base_url} ...')

            cmd = [
                'gobuster', 'dir',
                '-u', base_url,
                '-w', wordlist,
                '-t', '50',
                '-q',
                '--no-error',
                '--follow-redirect',
            ]

            proc = pm.start(label, cmd)

            try:
                if not proc.stdout:
                    continue

                for raw_line in iter(proc.stdout.readline, ''):
                    if context.should_stop:
                        pm.stop(label)
                        return

                    line = raw_line.strip()
                    if not line:
                        continue

                    parsed = self._parse_line(line, base_url, svc.port)
                    if not parsed:
                        continue

                    # Extract domains from redirect URLs
                    for ed in DomainExtractor.from_gobuster_url(parsed['url']):
                        context.add_discovered_domain(ed.domain, ed.source)

                    # Finding
                    context.add_finding(Finding(
                        type=FindingType.DIRECTORY,
                        source=self.name,
                        severity=Severity.INFO,
                        data=parsed,
                        description=f'[{parsed["status_code"]}] {parsed["url"]}',
                    ))

                    # WS event
                    bus.emit(
                        EventType.DIRECTORY_FOUND,
                        module=self.name,
                        data=parsed,
                    )
            finally:
                proc.wait()
                pm.remove(label)

    @staticmethod
    def _parse_line(line: str, base_url: str, port: int) -> dict | None:
        match = GOBUSTER_LINE_RE.match(line)
        if not match:
            return None

        size_str = match.group(3)
        redirect = match.group(4)

        return {
            'url': f'{base_url}{match.group(1)}',
            'status_code': int(match.group(2)),
            'size': int(size_str) if size_str else 0,
            'port': port,
            'redirect': redirect.strip() if redirect else None,
        }
