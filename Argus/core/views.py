import json
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from django.views.decorators.http import require_POST, require_GET
from django.views.decorators.csrf import ensure_csrf_cookie
from django.conf import settings

from core.models import ScanSession, ModuleRun, ScanTimelineEvent
from tasks.scan_tasks import run_discovery, run_expansion


@ensure_csrf_cookie
def index(request):
    """Main page — scan form + live dashboard."""
    sessions = ScanSession.objects.prefetch_related(
        'ports', 'directories', 'dns_records', 'vhosts',
    )[:10]

    return render(request, 'core/index.html', {
        'sessions': sessions,
        'default_dir_wordlist': settings.DEFAULT_DIR_WORDLIST,
        'default_dns_wordlist': settings.DEFAULT_DNS_WORDLIST,
    })


def scan_history(request):
    """Scan History page — list of all sessions."""
    sessions = ScanSession.objects.prefetch_related(
        'ports', 'directories', 'dns_records', 'vhosts', 'module_runs',
    )
    return render(request, 'core/scan_history.html', {'sessions': sessions})


@require_POST
def start_scan(request):
    target = request.POST.get('target', '').strip()
    if not target:
        return JsonResponse({'error': 'Target is required.'}, status=400)

    session = ScanSession.objects.create(
        target=target,
        nmap_flags=request.POST.get('nmap_flags', '-T4 --open').strip(),
        dir_wordlist=request.POST.get('dir_wordlist', '').strip(),
        vhost_wordlist=request.POST.get('vhost_wordlist', '').strip(),
        dns_wordlist=request.POST.get('dns_wordlist', '').strip(),
    )

    run_discovery.apply_async(args=[session.id], countdown=2)
    return JsonResponse({'session_id': session.id, 'status': 'started'})


@require_POST
def continue_scan(request, session_id):
    session = get_object_or_404(ScanSession, id=session_id)

    if session.status != 'awaiting_domains':
        return JsonResponse(
            {'error': f'Session is not awaiting domains (status={session.status}).'},
            status=400,
        )

    try:
        body = json.loads(request.body)
        domains = body.get('domains', [])
    except (json.JSONDecodeError, AttributeError):
        domains = []

    session.confirmed_domains = domains
    session.status = 'running'
    session.save()

    if domains:
        run_expansion.apply_async(args=[session.id], countdown=1)
    else:
        from django.utils import timezone
        session.status = 'completed'
        session.completed_at = timezone.now()
        session.save()

    return JsonResponse({
        'session_id': session.id,
        'confirmed_domains': domains,
        'status': 'expansion_started' if domains else 'completed',
    })


def session_detail(request, session_id):
    """Scan Detail page — full analyst view."""
    session = get_object_or_404(ScanSession, id=session_id)
    module_runs = session.module_runs.all()
    timeline = session.timeline_events.all()

    return render(request, 'core/session_detail.html', {
        'session': session,
        'ports': session.ports.all(),
        'directories': session.directories.all(),
        'vhosts': session.vhosts.all(),
        'dns_records': session.dns_records.all(),
        'module_runs': module_runs,
        'timeline': timeline,
    })


def session_status(request, session_id):
    session = get_object_or_404(ScanSession, id=session_id)
    return JsonResponse({
        'status': session.status,
        'ports_count': session.ports.count(),
        'directories_count': session.directories.count(),
        'vhosts_count': session.vhosts.count(),
        'dns_count': session.dns_records.count(),
    })


# ── API endpoints for the analyst UI ────────────────────────────────────────

def api_session_detail(request, session_id):
    """JSON: full session data for the detail page."""
    session = get_object_or_404(ScanSession, id=session_id)

    ports = list(session.ports.values(
        'port', 'protocol', 'state', 'service', 'product', 'version', 'is_http'
    ))
    directories = list(session.directories.values('url', 'status_code', 'size', 'port'))
    vhosts = list(session.vhosts.values('hostname', 'port', 'status_code', 'content_length', 'words', 'lines'))
    dns_records = list(session.dns_records.values('subdomain', 'record_type', 'value'))

    # Module runs (without full stdout for this endpoint)
    module_runs = []
    for mr in session.module_runs.all():
        module_runs.append({
            'module_name': mr.module_name,
            'status': mr.status,
            'started_at': mr.started_at.isoformat() if mr.started_at else None,
            'completed_at': mr.completed_at.isoformat() if mr.completed_at else None,
            'duration_seconds': mr.duration_seconds,
            'exit_code': mr.exit_code,
        })

    # Timeline
    timeline = []
    for ev in session.timeline_events.all():
        timeline.append({
            'timestamp': ev.timestamp.isoformat(),
            'event_type': ev.event_type,
            'module': ev.module,
            'message': ev.message,
            'data': ev.data,
        })

    duration = session.duration_seconds

    return JsonResponse({
        'id': session.id,
        'target': session.target,
        'status': session.status,
        'created_at': session.created_at.isoformat(),
        'completed_at': session.completed_at.isoformat() if session.completed_at else None,
        'duration_seconds': duration,
        'nmap_flags': session.nmap_flags,
        'discovered_domains': session.discovered_domains,
        'confirmed_domains': session.confirmed_domains,
        'error_message': session.error_message,
        'ports': ports,
        'directories': directories,
        'vhosts': vhosts,
        'dns_records': dns_records,
        'module_runs': module_runs,
        'timeline': timeline,
        'findings_count': session.findings_count,
    })


def api_module_raw(request, session_id, module_name):
    """JSON: raw stdout/stderr for a specific module run."""
    session = get_object_or_404(ScanSession, id=session_id)
    try:
        run = session.module_runs.filter(module_name=module_name).latest('started_at')
    except ModuleRun.DoesNotExist:
        return JsonResponse({'stdout': '', 'stderr': '', 'status': 'not_found'})

    return JsonResponse({
        'module_name': run.module_name,
        'status': run.status,
        'stdout': run.stdout,
        'stderr': run.stderr,
        'exit_code': run.exit_code,
        'duration_seconds': run.duration_seconds,
    })


def api_scan_list(request):
    """JSON: list of all sessions for the history page."""
    sessions = ScanSession.objects.prefetch_related('ports', 'directories', 'vhosts', 'dns_records', 'module_runs')
    result = []
    for s in sessions:
        result.append({
            'id': s.id,
            'target': s.target,
            'status': s.status,
            'created_at': s.created_at.isoformat(),
            'completed_at': s.completed_at.isoformat() if s.completed_at else None,
            'duration_seconds': s.duration_seconds,
            'findings_count': s.findings_count,
            'modules_executed': list(s.module_runs.values_list('module_name', flat=True)),
            'ports_count': s.ports.count(),
            'dirs_count': s.directories.count(),
            'vhosts_count': s.vhosts.count(),
            'dns_count': s.dns_records.count(),
        })
    return JsonResponse({'scans': result})


@require_POST
def stop_scan(request, session_id):
    session = get_object_or_404(ScanSession, id=session_id)
    session.status = 'stopping'
    session.save()
    return JsonResponse({'status': 'stopping'})


@require_POST
def delete_session(request, session_id):
    session = get_object_or_404(ScanSession, id=session_id)
    session.delete()
    return JsonResponse({'status': 'deleted'})


@require_POST
def clear_database(request):
    ScanSession.objects.all().delete()
    return JsonResponse({'status': 'cleared'})
