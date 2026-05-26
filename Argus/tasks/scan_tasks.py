"""
Celery tasks — two-phase scan architecture.

Phase 1: run_discovery
  Runs nmap + gobuster. If domains are discovered, pauses the scan
  (status=awaiting_domains) and sends a WS event. Celery worker is freed.

Phase 2: run_expansion
  Triggered by POST /scan/{id}/continue/ after user confirms domains.
  Runs vhost + dns on the confirmed domains.

No Redis polling. No blocked workers. Clean handoff via HTTP endpoint.
"""

from __future__ import annotations

from celery import shared_task
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from django.utils import timezone

from core.models import (
    ScanSession, PortResult, DirectoryResult, VHostResult, DNSResult,
)
from pipeline.context import ReconContext, HttpService
from pipeline.events import EventBus, EventType, ScanEvent
from pipeline.process_manager import ProcessManager
from pipeline.orchestrator import Orchestrator
from pipeline.finding import FindingType
from scanner import ALL_MODULES


def _make_dispatcher(session_id: int):
    """Create a WS dispatch function bound to a session."""
    channel_layer = get_channel_layer()

    def dispatch(event: ScanEvent) -> None:
        async_to_sync(channel_layer.group_send)(
            f'scan_{session_id}',
            {
                'type': 'scan_update',
                'message': event.to_dict(),
            },
        )

    return dispatch


def _check_stop(session_id: int) -> bool:
    """Check if the session has been stopped externally."""
    try:
        session = ScanSession.objects.get(id=session_id)
        return session.status == 'stopping'
    except ScanSession.DoesNotExist:
        return True


def _build_context(session: ScanSession, pm: ProcessManager) -> ReconContext:
    """Build a ReconContext from a ScanSession model."""
    return ReconContext(
        session_id=session.id,
        target=session.target,
        options={
            'nmap_flags': session.nmap_flags,
            'dir_wordlist': session.dir_wordlist,
            'vhost_wordlist': session.vhost_wordlist,
            'dns_wordlist': session.dns_wordlist,
            'process_manager': pm,
        },
        stop_checker=lambda: _check_stop(session.id),
    )


def _persist_findings(session: ScanSession, context: ReconContext) -> None:
    """Write pipeline findings to Django models for persistence."""
    for finding in context.findings:
        d = finding.data

        if finding.type == FindingType.PORT:
            PortResult.objects.get_or_create(
                session=session,
                port=d['port'],
                protocol=d.get('protocol', 'tcp'),
                defaults={
                    'state': d.get('state', 'open'),
                    'service': d.get('service', ''),
                    'product': d.get('product', ''),
                    'version': d.get('version', ''),
                    'extra_info': d.get('extra_info', ''),
                    'is_http': d.get('is_http', False),
                },
            )

        elif finding.type == FindingType.DIRECTORY:
            DirectoryResult.objects.get_or_create(
                session=session,
                url=d['url'],
                defaults={
                    'status_code': d.get('status_code', 0),
                    'size': d.get('size', 0),
                    'port': d.get('port', 80),
                },
            )

        elif finding.type == FindingType.VHOST:
            VHostResult.objects.get_or_create(
                session=session,
                hostname=d['hostname'],
                port=d.get('port', 80),
                defaults={
                    'status_code': d.get('status_code', 0),
                    'content_length': d.get('content_length', 0),
                    'words': d.get('words', 0),
                    'lines': d.get('lines', 0),
                },
            )

        elif finding.type == FindingType.DNS_RECORD:
            DNSResult.objects.get_or_create(
                session=session,
                subdomain=d['subdomain'],
                record_type=d['record_type'],
                value=d['value'],
            )


def _finalize(session, status, pm, bus, message=''):
    """Set final session state and emit closing event."""
    session.refresh_from_db()
    session.status = status
    session.completed_at = timezone.now()
    session.save()
    pm.cleanup()

    event_map = {
        'completed': EventType.SCAN_COMPLETED,
        'stopped': EventType.SCAN_STOPPED,
        'failed': EventType.SCAN_FAILED,
    }
    bus.emit(event_map.get(status, EventType.SCAN_FAILED), message=message or f'Scan {status}.')


@shared_task(bind=True)
def run_discovery(self, session_id: int):
    """
    Phase 1: nmap + gobuster.

    After completion:
    - If domains discovered → status=awaiting_domains, WS event, RETURN
    - If no domains and no expansion needed → status=completed
    """
    try:
        session = ScanSession.objects.get(id=session_id)
    except ScanSession.DoesNotExist:
        return

    session.status = 'running'
    session.task_id = self.request.id
    session.save()

    pm = ProcessManager()
    context = _build_context(session, pm)
    bus = EventBus(_make_dispatcher(session_id))

    bus.emit(EventType.SCAN_STARTED, message=f'Starting recon for {session.target}')

    orchestrator = Orchestrator(ALL_MODULES, context, bus, pm)

    try:
        completed = orchestrator.run_phase('discovery')
        _persist_findings(session, context)

        if not completed:
            _finalize(session, 'stopped', pm, bus)
            return

        # Check if expansion is needed
        needs_expansion = session.vhost_wordlist or session.dns_wordlist
        discovered = context.unique_discovered_domains

        if needs_expansion and context.has_http:
            # Pause — send domains to frontend, free the Celery worker
            session.refresh_from_db()
            session.discovered_domains = discovered
            session.status = 'awaiting_domains'
            session.save()

            bus.emit(
                EventType.DOMAINS_AWAITING,
                message='Domains detected — confirm to continue.' if discovered
                        else 'No domains detected. Add manually or skip.',
                data={'domains': discovered},
            )
            pm.cleanup()
            return

        # No expansion needed — done
        _finalize(session, 'completed', pm, bus, 'Scan completed.')

    except Exception as e:
        session.refresh_from_db()
        session.error_message = str(e)
        session.save()
        _finalize(session, 'failed', pm, bus, str(e))


@shared_task(bind=True)
def run_expansion(self, session_id: int):
    """
    Phase 2: vhost + dns on confirmed domains.

    Triggered by POST /scan/{id}/continue/.
    """
    try:
        session = ScanSession.objects.get(id=session_id)
    except ScanSession.DoesNotExist:
        return

    if not session.confirmed_domains:
        session.status = 'completed'
        session.completed_at = timezone.now()
        session.save()
        return

    session.status = 'running'
    session.task_id = self.request.id
    session.save()

    pm = ProcessManager()
    context = _build_context(session, pm)

    # Restore state from discovery phase
    context.confirmed_domains = list(session.confirmed_domains)

    for port_result in session.ports.filter(is_http=True):
        context.add_http_service(HttpService(
            port=port_result.port,
            protocol=port_result.protocol,
            is_https=(port_result.port in {443, 8443}),
            product=port_result.product,
        ))
        context.open_ports.add(port_result.port)

    # Mark discovery as done so expansion modules don't block on requires
    context.completed_modules.add('nmap')
    context.completed_modules.add('gobuster')

    bus = EventBus(_make_dispatcher(session_id))
    bus.emit(
        EventType.DOMAINS_CONFIRMED,
        message=f'Continuing with {len(context.confirmed_domains)} domain(s).',
        data={'domains': context.confirmed_domains},
    )

    orchestrator = Orchestrator(ALL_MODULES, context, bus, pm)

    try:
        completed = orchestrator.run_phase('expansion')
        _persist_findings(session, context)

        status = 'completed' if completed else 'stopped'
        _finalize(session, status, pm, bus, f'Scan {status}.')

    except Exception as e:
        session.refresh_from_db()
        session.error_message = str(e)
        session.save()
        _finalize(session, 'failed', pm, bus, str(e))
