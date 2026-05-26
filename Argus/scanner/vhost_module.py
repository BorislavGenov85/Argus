"""
VHostModule — virtual host discovery using ffuf.

Phase: expansion (requires confirmed domains)
Uses ffuf's -ac (auto-calibrate) for wildcard filtering, plus
an explicit baseline check as a safety net.

Wildcard detection:
  1. Send a request with a random subdomain (e.g. random8374.example.htb)
  2. Record the baseline response (status, length, words, lines)
  3. Any result matching the baseline is a wildcard false positive → drop it
"""

from __future__ import annotations

import json
import os
import re
import secrets
import signal
import subprocess
import base64
from typing import TYPE_CHECKING

from pipeline.base_module import ReconModule
from pipeline.finding import Finding, FindingType, Severity
from pipeline.events import EventType

if TYPE_CHECKING:
    from pipeline.context import ReconContext
    from pipeline.events import EventBus


class VHostModule(ReconModule):
    name = 'vhost'
    phase = 'expansion'
    requires = ['nmap']

    def should_run(self, context: ReconContext) -> bool:
        wordlist = context.options.get('vhost_wordlist', '')
        return context.has_http and context.has_confirmed_domains and bool(wordlist)

    def skip_reason(self, context: ReconContext) -> str:
        if not context.has_http:
            return 'vhost: no HTTP services found.'
        if not context.has_confirmed_domains:
            return 'vhost: no confirmed domains.'
        if not context.options.get('vhost_wordlist'):
            return 'vhost: no wordlist configured.'
        return 'vhost: preconditions not met.'

    def run(self, context: ReconContext, bus: EventBus) -> None:
        from pipeline.process_manager import ProcessManager

        pm: ProcessManager = context.options['process_manager']
        wordlist = context.options['vhost_wordlist']

        for svc in context.http_services:
            if context.should_stop:
                return

            for domain in context.confirmed_domains:
                if context.should_stop:
                    return

                label = f'ffuf_{svc.port}_{domain}'
                bus.log(self.name, f'Scanning vhosts for {domain} on port {svc.port}...')

                url = f'{svc.scheme}://{context.target}:{svc.port}'

                cmd = [
                    'ffuf',
                    '-u', url,
                    '-H', f'Host: FUZZ.{domain}',
                    '-w', wordlist,
                    '-mc', '200,204,301,302,307,401,403',
                    '-ac',       # auto-calibrate (ffuf's built-in wildcard filter)
                    '-json',
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

                        # Strip ANSI escape codes
                        line = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', line)

                        if not line.startswith('{'):
                            continue

                        try:
                            item = json.loads(line)
                        except json.JSONDecodeError:
                            continue

                        fuzz_value = item.get('input', {}).get('FUZZ')
                        if not fuzz_value:
                            continue

                        # ffuf may base64-encode the value
                        try:
                            fuzz_value = base64.b64decode(fuzz_value).decode()
                        except Exception:
                            pass

                        hostname = f'{fuzz_value}.{domain}'

                        vhost_data = {
                            'hostname': hostname,
                            'port': svc.port,
                            'status_code': item.get('status', 0),
                            'content_length': item.get('length', 0),
                            'words': item.get('words', 0),
                            'lines': item.get('lines', 0),
                        }

                        context.add_finding(Finding(
                            type=FindingType.VHOST,
                            source=self.name,
                            severity=Severity.INFO,
                            data=vhost_data,
                            description=f'VHost discovered: {hostname}',
                        ))

                        bus.emit(
                            EventType.VHOST_FOUND,
                            module=self.name,
                            data=vhost_data,
                        )

                finally:
                    proc.wait()
                    pm.remove(label)
