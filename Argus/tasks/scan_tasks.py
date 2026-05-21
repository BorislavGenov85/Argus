from celery import shared_task
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from django.utils import timezone

from core.models import ScanSession, PortResult, DirectoryResult, DNSResult
from scanner.nmap_scanner import run_nmap_scan, get_http_ports_from_results
from scanner.gobuster_scanner import run_gobuster_dir
from scanner.dns_scanner import run_dns_enumeration


def send_ws_update(session_id: int, message: dict):
    """Send update to WebSocket client."""
    channel_layer = get_channel_layer()

    async_to_sync(channel_layer.group_send)(
        f'scan_{session_id}',
        {
            'type': 'scan_update',
            'message': message,
        }
    )


def should_stop(session_id):
    """
    Check whether the scan should stop.
    Returns True if:
    - session status == stopping
    - session no longer exists
    """
    try:
        session = ScanSession.objects.get(id=session_id)
        return session.status == "stopping"
    except ScanSession.DoesNotExist:
        return True


def stop_scan(session, stage="unknown"):
    """
    Gracefully stop scan execution.
    """
    session.status = "stopped"
    session.completed_at = timezone.now()
    session.save()

    send_ws_update(session.id, {
        "stage": stage,
        "status": "stopped",
        "message": "🛑 Scan stopped by user.",
    })


def fail_scan(session, stage, error_message):
    """
    Centralized error handling.
    """
    session.status = "failed"
    session.error_message = str(error_message)
    session.completed_at = timezone.now()
    session.save()

    send_ws_update(session.id, {
        "stage": stage,
        "status": "error",
        "message": str(error_message),
    })


@shared_task(bind=True)
def run_full_scan(self, session_id: int):
    """
    Main Celery task.

    Flow:
    1. nmap scan
    2. gobuster directory enumeration
    3. DNS enumeration
    """

    try:
        session = ScanSession.objects.get(id=session_id)
    except ScanSession.DoesNotExist:
        return

    session.status = 'running'
    session.task_id = self.request.id
    session.save()

    # ─────────────────────────────────────────────────────────────
    # NMAP
    # ─────────────────────────────────────────────────────────────

    send_ws_update(session_id, {
        'stage': 'nmap',
        'status': 'started',
        'message': f'🔍 Starting nmap scan for {session.target}...',
    })

    try:
        for result in run_nmap_scan(session.target, session.nmap_flags):

            if should_stop(session.id):
                stop_scan(session, "nmap")
                return

            if result['type'] == 'error':
                fail_scan(session, 'nmap', result['message'])
                return

            if result['type'] == 'port':
                port_data = result['data']

                PortResult.objects.create(
                    session=session,
                    **port_data
                )

                send_ws_update(session_id, {
                    'stage': 'nmap',
                    'status': 'result',
                    'port': port_data['port'],
                    'protocol': port_data['protocol'],
                    'service': port_data['service'],
                    'product': port_data['product'],
                    'version': port_data['version'],
                    'is_http': port_data['is_http'],
                })

    except Exception as e:
        fail_scan(session, 'nmap', e)
        return

    send_ws_update(session_id, {
        'stage': 'nmap',
        'status': 'done',
        'message': '✅ nmap scan completed.',
    })

    # ─────────────────────────────────────────────────────────────
    # GOBUSTER
    # ─────────────────────────────────────────────────────────────

    if should_stop(session.id):
        stop_scan(session, "nmap")
        return

    http_ports = get_http_ports_from_results(
        session.ports.filter(is_http=True)
    )

    if http_ports and session.dir_wordlist:

        send_ws_update(session_id, {
            'stage': 'gobuster',
            'status': 'started',
            'message': f'📂 Starting directory enumeration for {len(http_ports)} HTTP port(s)...',
        })

        try:
            for port_info in http_ports:

                if should_stop(session.id):
                    stop_scan(session, "gobuster")
                    return

                port_num = port_info['port']
                use_https = port_num in {443, 8443}

                for result in run_gobuster_dir(
                        target=session.target,
                        port=port_num,
                        wordlist=session.dir_wordlist,
                        use_https=use_https,
                ):

                    if should_stop(session.id):
                        stop_scan(session, "gobuster")
                        return

                    if result['type'] == 'directory':

                        dir_data = result['data']

                        DirectoryResult.objects.create(
                            session=session,
                            **dir_data
                        )

                        send_ws_update(session_id, {
                            'stage': 'gobuster',
                            'status': 'result',
                            **dir_data,
                        })

                    elif result['type'] == 'error':

                        send_ws_update(session_id, {
                            'stage': 'gobuster',
                            'status': 'error',
                            'message': result['message'],
                        })

        except Exception as e:
            fail_scan(session, 'gobuster', e)
            return

        send_ws_update(session_id, {
            'stage': 'gobuster',
            'status': 'done',
            'message': '✅ Directory enumeration completed.',
        })

    elif not session.dir_wordlist:

        send_ws_update(session_id, {
            'stage': 'gobuster',
            'status': 'skipped',
            'message': '⏭️ Directory enumeration skipped — no wordlist selected.',
        })

    else:

        send_ws_update(session_id, {
            'stage': 'gobuster',
            'status': 'skipped',
            'message': '⏭️ No HTTP ports found.',
        })

    # ─────────────────────────────────────────────────────────────
    # DNS ENUMERATION
    # ─────────────────────────────────────────────────────────────

    if should_stop(session.id):
        stop_scan(session, "gobuster")
        return

    if session.dns_wordlist:

        send_ws_update(session_id, {
            'stage': 'dns',
            'status': 'started',
            'message': f'🌐 Starting DNS enumeration for {session.target}...',
        })

        try:
            for result in run_dns_enumeration(
                    session.target,
                    session.dns_wordlist
            ):

                if should_stop(session.id):
                    stop_scan(session, "dns")
                    return

                if result['type'] == 'dns':

                    dns_data = result['data']

                    DNSResult.objects.create(
                        session=session,
                        **dns_data
                    )

                    send_ws_update(session_id, {
                        'stage': 'dns',
                        'status': 'result',
                        **dns_data,
                    })

                elif result['type'] == 'error':

                    send_ws_update(session_id, {
                        'stage': 'dns',
                        'status': 'error',
                        'message': result['message'],
                    })

        except Exception as e:
            fail_scan(session, 'dns', e)
            return

        send_ws_update(session_id, {
            'stage': 'dns',
            'status': 'done',
            'message': '✅ DNS enumeration completed.',
        })

    else:

        send_ws_update(session_id, {
            'stage': 'dns',
            'status': 'skipped',
            'message': '⏭️ DNS enumeration skipped — no wordlist selected.',
        })

    # ─────────────────────────────────────────────────────────────
    # FINALIZATION
    # ─────────────────────────────────────────────────────────────

    session.status = 'completed'
    session.completed_at = timezone.now()
    session.save()

    send_ws_update(session_id, {
        'stage': 'all',
        'status': 'completed',
        'message': '🎯 Scanning is complete!',
    })
