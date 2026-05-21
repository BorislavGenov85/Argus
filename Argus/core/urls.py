from django.urls import path
from core import views

urlpatterns = [
    path('', views.index, name='index'),
    path('scan/start/', views.start_scan, name='start_scan'),
    path('scan/<int:session_id>/', views.session_detail, name='session_detail'),
    path('scan/<int:session_id>/status/', views.session_status, name='session_status'),
    path('scan/<int:session_id>/delete/', views.delete_session, name='delete_session'),
    path('db/clear/', views.clear_database, name='clear_database'),
    path('scan/<int:session_id>/stop/', views.stop_scan, name='stop_scan'),
]
