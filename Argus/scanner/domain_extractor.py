import re

# Regex patterns за домейни в nmap output
NMAP_PATTERNS = [
    # SSL cert: commonName=example.htb
    re.compile(r'commonName=([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})', re.IGNORECASE),
    # Subject Alternative Names: DNS:example.htb
    re.compile(r'DNS:([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})', re.IGNORECASE),
    # HTTP redirect: Location: http://example.htb
    re.compile(r'Location:\s*https?://([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})', re.IGNORECASE),
    # http-title или друг hint: "Did not follow redirect to http://example.htb"
    re.compile(r'redirect\s+to\s+https?://([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})', re.IGNORECASE),
    # Всяко .htb или .thm (TryHackMe) в output-а
    re.compile(r'\b([a-zA-Z0-9._-]+\.(?:htb|thm|local|internal|corp|lan))\b', re.IGNORECASE),
]

# Regex за gobuster резултати — Location header в redirect
GOBUSTER_PATTERNS = [
    re.compile(r'https?://([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})', re.IGNORECASE),
]

# Домейни които да игнорираме — false positives
IGNORE_DOMAINS = {
    'nmap.org',
    'localhost',
    'example.com',
    'openssl.org',
}


def extract_domains_from_nmap_line(line: str) -> set[str]:
    """Извлича домейни от един ред nmap output."""
    found = set()

    for pattern in NMAP_PATTERNS:
        for match in pattern.finditer(line):
            domain = match.group(1).lower().strip('.')
            if _is_valid_domain(domain):
                found.add(domain)

    return found


def extract_domains_from_gobuster_url(url: str) -> set[str]:
    """Извлича домейни от gobuster URL резултат."""
    found = set()

    for pattern in GOBUSTER_PATTERNS:
        for match in pattern.finditer(url):
            domain = match.group(1).lower().strip('.')
            if _is_valid_domain(domain):
                found.add(domain)

    return found


def _is_valid_domain(domain: str) -> bool:
    """Филтрира false positives."""
    if domain in IGNORE_DOMAINS:
        return False

    # Трябва да има поне една точка
    if '.' not in domain:
        return False

    # Не трябва да е само IP
    parts = domain.split('.')
    if all(p.isdigit() for p in parts):
        return False

    # Минимална дължина
    if len(domain) < 4:
        return False

    return True