import dns.resolver
import dns.exception
from typing import Generator


# DNS записи, които търсим за основния домейн
MAIN_RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']


def run_dns_enumeration(target: str, wordlist: str) -> Generator[dict, None, None]:
    """
    DNS енумерация в два етапа:
    1. Основни DNS записи за домейна
    2. Brute force на субдомейни от wordlist

    Yields dict с:
        type: 'dns' | 'error' | 'done'
        data: DNS записа
    """
    # Етап 1: Основни записи
    yield from _get_base_records(target)

    # Етап 2: Субдомейни от wordlist
    yield from _brute_force_subdomains(target, wordlist)

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


def _brute_force_subdomains(target: str, wordlist_path: str) -> Generator[dict, None, None]:
    """Brute force на субдомейни от wordlist файл."""
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

        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            continue
        except dns.exception.Timeout:
            continue
        except Exception:
            continue
