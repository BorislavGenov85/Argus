import json
import os
import signal
import subprocess
import base64
import re

from typing import Generator
from core.models import ScanSession


def run_vhost_scan(
        session_id: int,
        target: str,
        port: int,
        wordlist: str,
        use_https: bool = False
) -> Generator[dict, None, None]:

    protocol = 'https' if use_https else 'http'

    url = f'{protocol}://{target}:{port}'

    cmd = [
        'ffuf',
        '-u', url,
        '-H', f'Host: FUZZ.{target}',
        '-w', wordlist,
        '-mc', '200,204,301,302,307,401,403',
        '-ac',
        '-json',
    ]

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        universal_newlines=True,
        preexec_fn=os.setsid
    )

    # SAVE PID
    session = ScanSession.objects.get(id=session_id)
    session.vhost_pid = process.pid
    session.save(update_fields=['vhost_pid'])

    try:
        if not process.stdout:
            return

        for line in process.stdout:

            # STOP CHECK
            try:
                session.refresh_from_db()

                if session.status in ['stopping', 'stopped']:

                    print(f"[VHOST STOP] stopping session {session_id}")

                    try:
                        os.killpg(
                            os.getpgid(process.pid),
                            signal.SIGTERM
                        )
                    except ProcessLookupError:
                        pass

                    return

            except ScanSession.DoesNotExist:
                return

            line = line.strip()

            if not line:
                continue

            # REMOVE ANSI ESCAPE CODES
            line = re.sub(
                r'\x1b\[[0-9;]*[A-Za-z]',
                '',
                line
            )

            # ONLY JSON LINES
            if not line.startswith('{'):
                continue

            try:
                item = json.loads(line)

                fuzz_value = (
                    item
                    .get('input', {})
                    .get('FUZZ')
                )

                if not fuzz_value:
                    continue

                # FFUF RETURNS BASE64
                try:
                    fuzz_value = base64.b64decode(
                        fuzz_value
                    ).decode()

                except Exception:
                    continue

                hostname = f"{fuzz_value}.{target}"

                yield {
                    'type': 'vhost',
                    'data': {
                        'hostname': hostname,
                        'port': port,
                        'status_code': item.get('status', 0),
                        'content_length': item.get('length', 0),
                        'words': item.get('words', 0),
                        'lines': item.get('lines', 0),
                    }
                }

            except Exception:
                continue

        process.wait()

    except subprocess.TimeoutExpired:

        try:
            os.killpg(
                os.getpgid(process.pid),
                signal.SIGTERM
            )
        except ProcessLookupError:
            pass

        yield {
            'type': 'error',
            'message': 'VHOST scan timeout.'
        }

        return

    finally:

        try:
            session.refresh_from_db()
            session.vhost_pid = None
            session.save(update_fields=['vhost_pid'])
        except Exception:
            pass

    yield {
        'type': 'done'
    }