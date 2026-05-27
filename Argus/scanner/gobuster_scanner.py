import subprocess
import re
from typing import Generator


def run_gobuster_dir(
    target: str,
    port: int,
    wordlist: str,
    use_https: bool = False,
    extra_flags: str = ''
) -> Generator[dict, None, None]:
    """
    Пуска gobuster dir на конкретен HTTP порт.

    Yields dict с:
        type: 'directory' | 'error' | 'done'
        data: информацията за намерената директория
    """
    protocol = 'https' if use_https or port == 443 else 'http'
    base_url = f'{protocol}://{target}:{port}'

    cmd = [
        'gobuster', 'dir',
        '-u', base_url,
        '-w', wordlist,
        '-t', '50',           # 50 threads
        '-q',                 # quiet — само резултатите
        '--no-error',
        '--follow-redirect',
    ]

    # Добавяме допълнителни флагове ако има
    if extra_flags:
        cmd.extend(extra_flags.split())

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,          # line buffered — четем ред по ред
        )

        # Четем output в реално време
        for line in process.stdout:
            line = line.strip()
            if not line:
                continue

            parsed = _parse_gobuster_line(line, base_url, port)
            if parsed:
                yield {'type': 'directory', 'data': parsed}

        process.wait()

        if process.returncode not in (0, 1):
            stderr = process.stderr.read()
            if stderr:
                yield {'type': 'error', 'message': f'Gobuster error: {stderr[:200]}'}

    except FileNotFoundError:
        yield {
            'type': 'error',
            'message': 'gobuster не е намерен. Инсталирай го: apt install gobuster'
        }
    except Exception as e:
        yield {'type': 'error', 'message': str(e)}

    yield {'type': 'done', 'port': port}


def _parse_gobuster_line(line: str, base_url: str, port: int) -> dict or None:
    """
    Парсва ред от gobuster output.
    Формат: /path (Status: 200) [Size: 1234]
    """
    # Gobuster формат: /admin (Status: 200) [Size: 5678]
    match = re.match(r'^(/\S*)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)]', line)

    if match:
        path = match.group(1)
        status_code = int(match.group(2))
        size = int(match.group(3))

        return {
            'url': f'{base_url}{path}',
            'status_code': status_code,
            'size': size,
            'port': port,
        }

    return None
