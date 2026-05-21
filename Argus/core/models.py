from django.db import models


class ScanSession(models.Model):
    """Една сесия на сканиране — един таргет."""

    STATUS_CHOICES = [
        ('pending', 'pending'),
        ('running', 'running'),
        ('completed', 'completed'),
        ('failed', 'failed'),
    ]
    # status:
    # - pending
    # - running
    # - stopping
    # - stopped
    # - completed
    # - failed

    target = models.CharField(max_length=255)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    # Опции за сканиране
    nmap_flags = models.CharField(
        max_length=500,
        default='-sV -sC --open',
        help_text='Additional nmap flags'
    )
    dir_wordlist = models.CharField(max_length=500, blank=True)
    dns_wordlist = models.CharField(max_length=500, blank=True)

    # Celery task ID — за проследяване
    task_id = models.CharField(max_length=255, blank=True)

    # Обща бележка / грешка
    error_message = models.TextField(blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.target} — {self.status} ({self.created_at.strftime("%d.%m.%Y %H:%M")})'


class PortResult(models.Model):
    """Резултат от nmap — един отворен порт."""

    session = models.ForeignKey(ScanSession, on_delete=models.CASCADE, related_name='ports')
    port = models.IntegerField()
    protocol = models.CharField(max_length=10, default='tcp')  # tcp / udp
    state = models.CharField(max_length=20)                    # open / filtered
    service = models.CharField(max_length=100, blank=True)     # http, ssh, ftp...
    product = models.CharField(max_length=200, blank=True)     # Apache, OpenSSH...
    version = models.CharField(max_length=100, blank=True)     # 2.4.49, 8.2p1...
    extra_info = models.TextField(blank=True)                  # nmap script output

    # Дали е HTTP порт — за gobuster
    is_http = models.BooleanField(default=False)

    class Meta:
        ordering = ['port']

    def __str__(self):
        return f'{self.port}/{self.protocol} — {self.service}'


class DirectoryResult(models.Model):
    """Резултат от gobuster dir — намерена директория/файл."""

    session = models.ForeignKey(ScanSession, on_delete=models.CASCADE, related_name='directories')
    url = models.CharField(max_length=1000)
    status_code = models.IntegerField()
    size = models.IntegerField(default=0)         # Content-Length
    port = models.IntegerField(default=80)        # На кой порт е намерено

    class Meta:
        ordering = ['status_code', 'url']

    def __str__(self):
        return f'[{self.status_code}] {self.url}'


class DNSResult(models.Model):
    """Резултат от DNS енумерация — намерен субдомейн."""

    RECORD_TYPES = [
        ('A', 'A'),
        ('AAAA', 'AAAA'),
        ('CNAME', 'CNAME'),
        ('MX', 'MX'),
        ('TXT', 'TXT'),
        ('NS', 'NS'),
        ('SOA', 'SOA'),
    ]

    session = models.ForeignKey(ScanSession, on_delete=models.CASCADE, related_name='dns_records')
    subdomain = models.CharField(max_length=500)
    record_type = models.CharField(max_length=10, choices=RECORD_TYPES)
    value = models.CharField(max_length=500)       # IP адрес или hostname

    class Meta:
        ordering = ['record_type', 'subdomain']

    def __str__(self):
        return f'{self.subdomain} [{self.record_type}] → {self.value}'
