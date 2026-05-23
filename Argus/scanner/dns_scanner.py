import dns.resolver
import dns.exception
import dns.resolver
import dns.exception

from core.models import ScanSession
from typing import Generator


MAIN_RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']


def should_stop(session_id):
    try:
        session = ScanSession.objects.get(id=session_id)
        print(
            f"[STOP CHECK] session={session_id} status={session.status}"
        )
        print("CHECK STATUS:", session.status)
        return session.status == "stopping"
    except ScanSession.DoesNotExist:
        return True


def run_dns_enumeration(
        session_id: int,
        target: str,
        wordlist: str
) -> Generator[dict, None, None]:

    yield from _get_base_records(target)

    yield from _brute_force_subdomains(
        session_id,
        target,
        wordlist
    )

    yield {'type': 'done'}


def _get_base_records(target: str) -> Generator[dict, None, None]:
    """Взима стандартните DNS записи за домейна."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    for record_type in MAIN_RECORD_TYPES:
        try:
            answers = resolver.resolve(target, record_type)

            for rdata in answers:
                yield {
                    'type': 'dns',
                    'data': {
                        'subdomain': target,
                        'record_type': record_type,
                        'value': str(rdata),
                    }
                }

        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        except dns.exception.DNSException:
            continue


def _brute_force_subdomains(
        session_id: int,
        target: str,
        wordlist_path: str
) -> Generator[dict, None, None]:

    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2

    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            subdomains = [line.strip() for line in f if line.strip()]

    except FileNotFoundError:
        yield {
            'type': 'error',
            'message': f'Wordlist не е намерен: {wordlist_path}'
        }
        return

    for sub in subdomains:
        full_domain = f'{sub}.{target}'

        try:
            answers = resolver.resolve(full_domain, 'A')

            for rdata in answers:
                yield {
                    'type': 'dns',
                    'data': {
                        'subdomain': full_domain,
                        'record_type': 'A',
                        'value': str(rdata),
                    }
                }

        except (
                dns.resolver.NoAnswer,
                dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers
        ):
            continue

        except dns.exception.Timeout:
            continue

        except Exception:
            continue
