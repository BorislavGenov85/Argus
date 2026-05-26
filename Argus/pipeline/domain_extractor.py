"""
DomainExtractor — dedicated layer for pulling domains from various sources.

Each extraction method tags its output with the source. Includes
normalisation (strip subdomains to root) and deduplication.
"""

from __future__ import annotations

import re
from typing import NamedTuple


class ExtractedDomain(NamedTuple):
    domain: str
    source: str  # 'tls_cn', 'tls_san', 'http_redirect', 'html_body', 'gobuster_redirect', 'nmap_htb'


# ---- Patterns ----

_TLS_CN = re.compile(r'commonName=([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})', re.IGNORECASE)
_TLS_SAN = re.compile(r'DNS:([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})', re.IGNORECASE)
_HTTP_REDIRECT = re.compile(r'Location:\s*https?://([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})', re.IGNORECASE)
_NMAP_REDIRECT = re.compile(r'redirect\s+to\s+https?://([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})', re.IGNORECASE)
_HTB_DOMAIN = re.compile(r'\b([a-zA-Z0-9._-]+\.(?:htb|thm|local|internal|corp|lan))\b', re.IGNORECASE)
_URL_DOMAIN = re.compile(r'https?://([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})', re.IGNORECASE)
_HTML_HREF = re.compile(r'(?:href|src|action)=["\']https?://([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})', re.IGNORECASE)

# Domains to ignore — common false positives
_IGNORE = {
    'nmap.org', 'localhost', 'example.com', 'openssl.org',
    'w3.org', 'www.w3.org', 'schema.org', 'xmlns.com',
    'jquery.com', 'google.com', 'googleapis.com',
}


class DomainExtractor:
    """
    Stateless extractor. Call individual methods or use extract_all_from_nmap_line()
    for convenience.
    """

    @staticmethod
    def from_tls_cn(text: str) -> list[ExtractedDomain]:
        return [
            ExtractedDomain(_normalise(m.group(1)), 'tls_cn')
            for m in _TLS_CN.finditer(text)
            if _valid(_normalise(m.group(1)))
        ]

    @staticmethod
    def from_tls_san(text: str) -> list[ExtractedDomain]:
        return [
            ExtractedDomain(_normalise(m.group(1)), 'tls_san')
            for m in _TLS_SAN.finditer(text)
            if _valid(_normalise(m.group(1)))
        ]

    @staticmethod
    def from_http_redirect(text: str) -> list[ExtractedDomain]:
        results = []
        for m in _HTTP_REDIRECT.finditer(text):
            d = _normalise(m.group(1))
            if _valid(d):
                results.append(ExtractedDomain(d, 'http_redirect'))
        for m in _NMAP_REDIRECT.finditer(text):
            d = _normalise(m.group(1))
            if _valid(d):
                results.append(ExtractedDomain(d, 'http_redirect'))
        return results

    @staticmethod
    def from_html(text: str) -> list[ExtractedDomain]:
        return [
            ExtractedDomain(_normalise(m.group(1)), 'html_body')
            for m in _HTML_HREF.finditer(text)
            if _valid(_normalise(m.group(1)))
        ]

    @staticmethod
    def from_gobuster_url(url: str) -> list[ExtractedDomain]:
        return [
            ExtractedDomain(_normalise(m.group(1)), 'gobuster_redirect')
            for m in _URL_DOMAIN.finditer(url)
            if _valid(_normalise(m.group(1)))
        ]

    @staticmethod
    def from_nmap_line(line: str) -> list[ExtractedDomain]:
        """
        Run all nmap-relevant extractors on a single line.
        Returns deduplicated results, preferring higher-signal sources.
        """
        seen: dict[str, ExtractedDomain] = {}

        # Priority order: tls_san > tls_cn > http_redirect > htb pattern
        for extractor in [
            DomainExtractor.from_tls_san,
            DomainExtractor.from_tls_cn,
            DomainExtractor.from_http_redirect,
        ]:
            for ed in extractor(line):
                if ed.domain not in seen:
                    seen[ed.domain] = ed

        # HTB/THM catch-all (lower priority)
        for m in _HTB_DOMAIN.finditer(line):
            d = _normalise(m.group(1))
            if _valid(d) and d not in seen:
                seen[d] = ExtractedDomain(d, 'nmap_htb')

        return list(seen.values())

    @staticmethod
    def normalise_to_root(domain: str) -> str:
        """
        example.htb          -> example.htb
        dev.example.htb      -> example.htb
        api.dev.example.htb  -> example.htb

        Only works reliably for known TLDs like .htb, .thm, .local etc.
        For real TLDs you'd need a public suffix list.
        """
        parts = domain.lower().strip('.').split('.')
        if len(parts) <= 2:
            return '.'.join(parts)

        # For CTF domains (.htb, .thm, .local) the root is always last 2 parts
        known_ctf_tlds = {'htb', 'thm', 'local', 'internal', 'corp', 'lan'}
        if parts[-1] in known_ctf_tlds:
            return '.'.join(parts[-2:])

        # For real domains, return last 2 parts (naive but good enough)
        return '.'.join(parts[-2:])


# ---- helpers ----

def _normalise(domain: str) -> str:
    return domain.lower().strip('.')


def _valid(domain: str) -> bool:
    if domain in _IGNORE:
        return False
    if '.' not in domain:
        return False
    parts = domain.split('.')
    if all(p.isdigit() for p in parts):
        return False  # IP address
    if len(domain) < 4:
        return False
    return True
