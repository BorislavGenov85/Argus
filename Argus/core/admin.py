from django.contrib import admin
from core.models import ScanSession, PortResult, DirectoryResult, VHostResult, DNSResult

admin.site.register(ScanSession)
admin.site.register(PortResult)
admin.site.register(DirectoryResult)
admin.site.register(VHostResult)
admin.site.register(DNSResult)
