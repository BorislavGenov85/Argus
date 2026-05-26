from django.db import models


class ScanSession(models.Model):
    """One scan session — one target."""

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('awaiting_domains', 'Awaiting domain confirmation'),
        ('stopping', 'Stopping'),
        ('stopped', 'Stopped'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]

    target = models.CharField(max_length=255)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    # Scan options
    nmap_flags = models.CharField(max_length=500, default='-T4 --open')
    dir_wordlist = models.CharField(max_length=500, blank=True)
    vhost_wordlist = models.CharField(
        max_length=500, blank=True,
        default='/opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt',
    )
    dns_wordlist = models.CharField(max_length=500, blank=True)

    # Domains
    discovered_domains = models.JSONField(default=list, blank=True)
    confirmed_domains = models.JSONField(default=list, blank=True)

    # Celery task tracking
    task_id = models.CharField(max_length=255, blank=True)

    # Error
    error_message = models.TextField(blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.target} — {self.status} ({self.created_at.strftime("%d.%m.%Y %H:%M")})'


class PortResult(models.Model):
    """An open port found by nmap."""

    session = models.ForeignKey(ScanSession, on_delete=models.CASCADE, related_name='ports')
    port = models.IntegerField()
    protocol = models.CharField(max_length=10, default='tcp')
    state = models.CharField(max_length=20)
    service = models.CharField(max_length=100, blank=True)
    product = models.CharField(max_length=200, blank=True)
    version = models.CharField(max_length=100, blank=True)
    extra_info = models.TextField(blank=True)
    is_http = models.BooleanField(default=False)

    class Meta:
        ordering = ['port']

    def __str__(self):
        return f'{self.port}/{self.protocol} — {self.service}'


class DirectoryResult(models.Model):
    """A directory/file found by gobuster."""

    session = models.ForeignKey(ScanSession, on_delete=models.CASCADE, related_name='directories')
    url = models.CharField(max_length=1000)
    status_code = models.IntegerField()
    size = models.IntegerField(default=0)
    port = models.IntegerField(default=80)

    class Meta:
        ordering = ['status_code', 'url']

    def __str__(self):
        return f'[{self.status_code}] {self.url}'


class VHostResult(models.Model):
    """A virtual host found by ffuf."""

    session = models.ForeignKey(ScanSession, on_delete=models.CASCADE, related_name='vhosts')
    hostname = models.CharField(max_length=500)
    port = models.IntegerField(default=80)
    status_code = models.IntegerField(default=0)
    content_length = models.IntegerField(default=0)
    words = models.IntegerField(default=0)
    lines = models.IntegerField(default=0)

    class Meta:
        ordering = ['hostname']

    def __str__(self):
        return f'{self.hostname}:{self.port}'


class DNSResult(models.Model):
    """A DNS record found by enumeration."""

    RECORD_TYPES = [
        ('A', 'A'), ('AAAA', 'AAAA'), ('CNAME', 'CNAME'),
        ('MX', 'MX'), ('TXT', 'TXT'), ('NS', 'NS'), ('SOA', 'SOA'),
    ]

    session = models.ForeignKey(ScanSession, on_delete=models.CASCADE, related_name='dns_records')
    subdomain = models.CharField(max_length=500)
    record_type = models.CharField(max_length=10, choices=RECORD_TYPES)
    value = models.CharField(max_length=500)

    class Meta:
        ordering = ['record_type', 'subdomain']

    def __str__(self):
        return f'{self.subdomain} [{self.record_type}] → {self.value}'
