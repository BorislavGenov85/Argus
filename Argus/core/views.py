from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.conf import settings

from core.models import ScanSession, PortResult, DirectoryResult, DNSResult
from tasks.scan_tasks import run_full_scan
from django.views.decorators.csrf import ensure_csrf_cookie
from celery.result import AsyncResult


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
    nmap_flags = request.POST.get('nmap_flags', '-sV -sC --open').strip()
    dir_wordlist = request.POST.get('dir_wordlist', '').strip()
    dns_wordlist = request.POST.get('dns_wordlist', '').strip()

    if not target:
        return JsonResponse({'error': 'Въведи таргет!'}, status=400)

    session = ScanSession.objects.create(
        target=target,
        nmap_flags=nmap_flags,
        dir_wordlist=dir_wordlist,
        dns_wordlist=dns_wordlist,
    )

    # Пускаме async Celery task
    run_full_scan.delay(session.id)

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
def stop_scan(request, session_id):
    try:
        session = ScanSession.objects.get(id=session_id)
    except ScanSession.DoesNotExist:
        return JsonResponse({'error': 'Session not found'}, status=404)

    session.status = 'stopping'
    session.save()

    if session.task_id:
        AsyncResult(session.task_id).revoke(terminate=True)

    return JsonResponse({
        'status': 'stopping',
        'message': 'Scan stop requested.'
    })


@require_POST
def clear_database(request):
    """Изтрива всички сканирания от БД."""
    ScanSession.objects.all().delete()
    return JsonResponse({'status': 'cleared', 'message': 'Базата данни е изчистена.'})


@require_POST
def delete_session(request, session_id):
    """Изтрива конкретна сесия."""
    session = get_object_or_404(ScanSession, id=session_id)
    session.delete()
    return JsonResponse({'status': 'deleted'})
