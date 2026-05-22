import re
import os
import subprocess
import signal

from typing import Generator
from core.models import ScanSession

HTTP_SERVICES = {'http', 'http-alt', 'https', 'ssl/http', 'http-proxy', 'https-alt'}

HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8008, 8888, 3000, 5000}

# Fallback: normal output port line
PORT_REGEX = re.compile(
    r'^(\d+)\/(tcp|udp)\s+open\s+([^\s]+)\s*(.*)$'
)


def run_nmap_scan(session_id: int, target: str, flags: str = '-T4 --open') -> Generator[dict, None, None]:
    print("===== NEW NMAP CODE LOADED =====")
    if not flags.strip():
        flags = '-T4 -sV -Pn --top-ports 1000'

    cmd = [
        'stdbuf', '-oL', '-eL',
        'nmap',
        *flags.split(),
        '--stats-every', '2s',
        target
    ]

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
            preexec_fn=os.setsid
        )
        ScanSession.objects.filter(id=session_id).update(
            nmap_pid=process.pid
        )

    except Exception as e:
        yield {
            'type': 'error',
            'message': str(e)
        }
        return

    if not process.stdout:
        yield {
            'type': 'error',
            'message': 'No stdout from nmap process'
        }
        return

    for raw_line in iter(process.stdout.readline, ''):

        line = raw_line.strip()

        print(f"[RAW] {raw_line!r}")

        if not line:
            continue

        yield {
            'type': 'log',
            'message': line
        }

        match = PORT_REGEX.search(line)

        print(f"[MATCH] {match}")

        if not match:
            continue

        port = int(match.group(1))
        protocol = match.group(2)
        service = match.group(3)
        version = (match.group(4) or '').strip()

        is_http = (
                service.lower() in HTTP_SERVICES
                or port in HTTP_PORTS
                or 'http' in version.lower()
        )

        print(f"[FOUND PORT] {port}")

        yield {
            'type': 'port',
            'data': {
                'port': port,
                'protocol': protocol,
                'state': 'open',
                'service': service,
                'product': version,
                'version': '',
                'extra_info': '',
                'is_http': is_http,
            }
        }

    process.wait()
    print(f"[NMAP EXIT CODE] {process.returncode}")

    if process.returncode == -15:
        yield {
            'type': 'stopped',
            'message': '🛑 Scan stopped by user.'
        }
        return

    if process.returncode != 0:
        yield {
            'type': 'error',
            'message': f'nmap exited with code {process.returncode}'
        }
        return

    yield {
        'type': 'done'
    }


def get_http_ports_from_results(port_results) -> list[dict]:
    return [
        {'port': p.port, 'protocol': p.protocol}
        for p in port_results
        if p.is_http
    ]


def read_stderr(stderr_pipe):
    for line in iter(stderr_pipe.readline, ''):
        yield {
            'type': 'log',
            'message': line.strip()
        }
