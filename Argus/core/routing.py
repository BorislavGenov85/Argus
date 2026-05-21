from django.urls import re_path
from core import consumers

websocket_urlpatterns = [
    re_path(r'ws/scan/(?P<session_id>\d+)/$', consumers.ScanConsumer.as_asgi()),
]
