from django.contrib import admin
from core.models import ScanSession, PortResult, DirectoryResult, DNSResult

admin.site.register(ScanSession)
admin.site.register(PortResult)
admin.site.register(DirectoryResult)
admin.site.register(DNSResult)
