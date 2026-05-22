import signal
import os
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.conf import settings

from core.models import ScanSession, PortResult, DirectoryResult, DNSResult
from tasks.scan_tasks import run_full_scan
from django.views.decorators.csrf import ensure_csrf_cookie
from celery import current_app


@ensure_csrf_cookie
def index(request):
    """Главна страница — форма за нов скан + история."""
    sessions = ScanSession.objects.prefetch_related(
        'ports',
        'directories',
        'dns_records'
    )[:10]

    context = {
        'sessions': sessions,
        'default_dir_wordlist': settings.DEFAULT_DIR_WORDLIST,
        'default_dns_wordlist': settings.DEFAULT_DNS_WORDLIST,
    }

    return render(request, 'core/index.html', context)


@require_POST
def start_scan(request):
    """Създава нова сесия и пуска Celery task."""
    target = request.POST.get('target', '').strip()
    nmap_flags = request.POST.get('nmap_flags', '-T4 --open').strip()
    dir_wordlist = request.POST.get('dir_wordlist', '').strip()
    dns_wordlist = request.POST.get('dns_wordlist', '').strip()

    if not target:
        return JsonResponse({'error': 'Input target!'}, status=400)

    session = ScanSession.objects.create(
        target=target,
        nmap_flags=nmap_flags,
        dir_wordlist=dir_wordlist,
        dns_wordlist=dns_wordlist,
    )

    # Пускаме async Celery task
    # countdown=2 дава време на браузъра да отвори WebSocket преди task-ът
    # да изпрати първото съобщение — без това 'started' се губи в Redis
    run_full_scan.apply_async(args=[session.id], countdown=2)

    return JsonResponse({'session_id': session.id, 'status': 'started'})


def session_detail(request, session_id):
    """Детайлна страница за сесия с резултатите."""
    session = get_object_or_404(ScanSession, id=session_id)

    context = {
        'session': session,
        'ports': session.ports.all(),
        'directories': session.directories.all(),
        'dns_records': session.dns_records.all(),
    }
    return render(request, 'core/session_detail.html', context)


def session_status(request, session_id):
    """API endpoint за статуса на сесията (за polling ако е нужно)."""
    session = get_object_or_404(ScanSession, id=session_id)

    return JsonResponse({
        'status': session.status,
        'ports_count': session.ports.count(),
        'directories_count': session.directories.count(),
        'dns_count': session.dns_records.count(),
    })


@require_POST
def clear_database(request):
    """Изтрива всички сканирания от БД."""
    ScanSession.objects.all().delete()
    return JsonResponse({'status': 'cleared', 'message': 'Database cleared.'})


@require_POST
def delete_session(request, session_id):
    """Изтрива конкретна сесия."""
    session = get_object_or_404(ScanSession, id=session_id)
    session.delete()
    return JsonResponse({'status': 'deleted'})


@require_POST
def stop_scan(request, session_id):

    session = get_object_or_404(ScanSession, id=session_id)

    session.status = 'stopping'
    session.save()

    try:
        if session.nmap_pid:
            os.killpg(os.getpgid(session.nmap_pid), signal.SIGTERM)
    except ProcessLookupError:
        pass

    try:
        if session.gobuster_pid:
            os.killpg(os.getpgid(session.gobuster_pid), signal.SIGTERM)
    except ProcessLookupError:
        pass

    try:
        if session.dns_pid:
            os.killpg(os.getpgid(session.dns_pid), signal.SIGTERM)
    except ProcessLookupError:
        pass

    if session.task_id:
        current_app.control.revoke(
            session.task_id,
            terminate=True,
            signal='SIGTERM'
        )

    session.status = 'stopped'
    session.save()

    return JsonResponse({
        'status': 'stopped'
    })