"""
DNSModule — DNS record enumeration and subdomain brute force.

Phase: expansion (requires confirmed domains)
Uses dnspython for resolution — no external subprocess.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import dns.resolver
import dns.exception

from pipeline.base_module import ReconModule
from pipeline.finding import Finding, FindingType, Severity
from pipeline.events import EventType

if TYPE_CHECKING:
    from pipeline.context import ReconContext
    from pipeline.events import EventBus


MAIN_RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
MAX_SCAN_TIME = 120  # seconds per domain


class DNSModule(ReconModule):
    name = 'dns'
    phase = 'expansion'
    requires = ['nmap']

    def should_run(self, context: ReconContext) -> bool:
        wordlist = context.options.get('dns_wordlist', '')
        return context.has_confirmed_domains and bool(wordlist)

    def skip_reason(self, context: ReconContext) -> str:
        if not context.has_confirmed_domains:
            return 'dns: no confirmed domains.'
        if not context.options.get('dns_wordlist'):
            return 'dns: no wordlist configured.'
        return 'dns: preconditions not met.'

    def run(self, context: ReconContext, bus: EventBus) -> None:
        wordlist_path = context.options['dns_wordlist']

        for domain in context.confirmed_domains:
            if context.should_stop:
                return

            bus.log(self.name, f'Enumerating DNS for {domain}...')

            # Base records
            self._get_base_records(domain, context, bus)

            # Subdomain brute force
            self._brute_subdomains(domain, wordlist_path, context, bus)

    def _get_base_records(self, target: str, context: ReconContext, bus: EventBus) -> None:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3

        for record_type in MAIN_RECORD_TYPES:
            if context.should_stop:
                return

            try:
                answers = resolver.resolve(target, record_type)
                for rdata in answers:
                    dns_data = {
                        'subdomain': target,
                        'record_type': record_type,
                        'value': str(rdata),
                    }

                    context.add_finding(Finding(
                        type=FindingType.DNS_RECORD,
                        source=self.name,
                        severity=Severity.INFO,
                        data=dns_data,
                        description=f'{target} [{record_type}] → {rdata}',
                    ))

                    bus.emit(
                        EventType.DNS_RECORD_FOUND,
                        module=self.name,
                        data=dns_data,
                    )

            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue
            except dns.exception.DNSException:
                continue

    def _brute_subdomains(
        self,
        target: str,
        wordlist_path: str,
        context: ReconContext,
        bus: EventBus,
    ) -> None:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 1
        resolver.lifetime = 1

        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                subdomains = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            bus.log(self.name, f'Wordlist not found: {wordlist_path}')
            return

        start_time = time.time()

        for sub in subdomains:
            if context.should_stop:
                return

            if time.time() - start_time > MAX_SCAN_TIME:
                bus.log(self.name, f'DNS brute force timeout after {MAX_SCAN_TIME}s for {target}.')
                return

            full_domain = f'{sub}.{target}'

            try:
                answers = resolver.resolve(full_domain, 'A')
                for rdata in answers:
                    dns_data = {
                        'subdomain': full_domain,
                        'record_type': 'A',
                        'value': str(rdata),
                    }

                    context.add_finding(Finding(
                        type=FindingType.DNS_RECORD,
                        source=self.name,
                        severity=Severity.INFO,
                        data=dns_data,
                        description=f'{full_domain} [A] → {rdata}',
                    ))

                    bus.emit(
                        EventType.DNS_RECORD_FOUND,
                        module=self.name,
                        data=dns_data,
                    )

            except (
                dns.resolver.NoAnswer,
                dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers,
                dns.exception.Timeout,
            ):
                continue
            except Exception:
                continue
