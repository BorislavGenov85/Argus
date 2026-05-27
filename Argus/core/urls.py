from django.urls import path
from core import views

urlpatterns = [
    # Pages
    path('', views.index, name='index'),
    path('scans/', views.scan_history, name='scan_history'),
    path('scan/<int:session_id>/', views.session_detail, name='session_detail'),

    # Scan control
    path('scan/start/', views.start_scan, name='start_scan'),
    path('scan/<int:session_id>/status/', views.session_status, name='session_status'),
    path('scan/<int:session_id>/continue/', views.continue_scan, name='continue_scan'),
    path('scan/<int:session_id>/stop/', views.stop_scan, name='stop_scan'),
    path('scan/<int:session_id>/delete/', views.delete_session, name='delete_session'),

    # API — analyst UI
    path('api/scans/', views.api_scan_list, name='api_scan_list'),
    path('api/scan/<int:session_id>/', views.api_session_detail, name='api_session_detail'),
    path('api/scan/<int:session_id>/raw/<str:module_name>/', views.api_module_raw, name='api_module_raw'),

    # DB ops
    path('db/clear/', views.clear_database, name='clear_database'),
]
