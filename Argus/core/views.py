from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import ensure_csrf_cookie
from django.conf import settings

from core.models import ScanSession
from tasks.scan_tasks import run_discovery, run_expansion


@ensure_csrf_cookie
def index(request):
    """Main page — scan form + history."""
    sessions = ScanSession.objects.prefetch_related(
        'ports', 'directories', 'dns_records',
    )[:10]

    return render(request, 'core/index.html', {
        'sessions': sessions,
        'default_dir_wordlist': settings.DEFAULT_DIR_WORDLIST,
        'default_dns_wordlist': settings.DEFAULT_DNS_WORDLIST,
    })


@require_POST
def start_scan(request):
    """Create a session and launch Phase 1 (discovery)."""
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

    # countdown=2 gives the browser time to open WebSocket before first event
    run_discovery.apply_async(args=[session.id], countdown=2)

    return JsonResponse({'session_id': session.id, 'status': 'started'})


@require_POST
def continue_scan(request, session_id):
    """
    Phase 2 trigger — user confirms domains, we launch expansion.

    No polling, no Redis key, no blocked worker.
    The frontend POSTs the confirmed domains here.
    """
    import json

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
        # User skipped — mark as completed
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
    """Detail page for a session."""
    session = get_object_or_404(ScanSession, id=session_id)
    return render(request, 'core/session_detail.html', {
        'session': session,
        'ports': session.ports.all(),
        'directories': session.directories.all(),
        'vhosts': session.vhosts.all(),
        'dns_records': session.dns_records.all(),
    })


def session_status(request, session_id):
    """API: session status (for polling fallback)."""
    session = get_object_or_404(ScanSession, id=session_id)
    return JsonResponse({
        'status': session.status,
        'ports_count': session.ports.count(),
        'directories_count': session.directories.count(),
        'vhosts_count': session.vhosts.count(),
        'dns_count': session.dns_records.count(),
    })


@require_POST
def stop_scan(request, session_id):
    """Stop a running scan. ProcessManager handles cleanup."""
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
