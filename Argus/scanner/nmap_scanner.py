import nmap
from typing import Generator


# HTTP услуги — по тях решаваме дали да пускаме gobuster
HTTP_SERVICES = {'http', 'http-alt', 'https', 'ssl/http', 'http-proxy', 'https-alt'}
HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8008, 8888, 3000, 5000}


def run_nmap_scan(target: str, flags: str = '-sV -sC --open') -> Generator[dict, None, None]:
    """
    Сканира таргета с nmap и yield-ва резултати в реално време.

    Yields dict с:
        type: 'port' | 'error' | 'done'
        data: информацията за порта
    """
    nm = nmap.PortScanner()

    try:
        # -p- сканира всички портове, комбинирано с потребителските флагове
        full_flags = f'{flags} -p-'
        nm.scan(hosts=target, arguments=full_flags)

    except nmap.PortScannerError as e:
        yield {'type': 'error', 'message': str(e)}
        return
    except Exception as e:
        yield {'type': 'error', 'message': f'Unexpected error: {str(e)}'}
        return

    # Проверяваме дали таргетът е намерен
    if target not in nm.all_hosts():
        yield {'type': 'error', 'message': f'Host {target} not found or down.'}
        return

    host_data = nm[target]

    # Минаваме през всички протоколи (tcp/udp)
    for proto in host_data.all_protocols():
        ports = sorted(host_data[proto].keys())

        for port in ports:
            port_info = host_data[proto][port]

            if port_info['state'] != 'open':
                continue

            service_name = port_info.get('name', '')
            product = port_info.get('product', '')
            version = port_info.get('version', '')

            # Проверяваме дали е HTTP порт
            is_http = (
                service_name.lower() in HTTP_SERVICES
                or port in HTTP_PORTS
                or 'http' in product.lower()
            )

            # Script output — от -sC флага
            script_output = ''
            if 'script' in port_info:
                script_output = '\n'.join(
                    f'{k}: {v}' for k, v in port_info['script'].items()
                )

            yield {
                'type': 'port',
                'data': {
                    'port': port,
                    'protocol': proto,
                    'state': port_info['state'],
                    'service': service_name,
                    'product': product,
                    'version': version,
                    'extra_info': script_output,
                    'is_http': is_http,
                }
            }

    yield {'type': 'done'}


def get_http_ports_from_results(port_results) -> list[dict]:
    """
    Връща само HTTP портовете от вече записаните резултати.
    Използва се за вземане на решение кои портове да сканира gobuster.
    """
    return [
        {'port': p.port, 'protocol': p.protocol}
        for p in port_results
        if p.is_http
    ]
