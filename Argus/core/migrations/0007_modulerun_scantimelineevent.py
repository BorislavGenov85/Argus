# Hand-written migration for ModuleRun and ScanTimelineEvent

import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0006_remove_scansession_dns_pid_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='ModuleRun',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('module_name', models.CharField(max_length=100)),
                ('started_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('completed_at', models.DateTimeField(blank=True, null=True)),
                ('exit_code', models.IntegerField(blank=True, null=True)),
                ('stdout', models.TextField(blank=True)),
                ('stderr', models.TextField(blank=True)),
                ('status', models.CharField(
                    choices=[('running','Running'),('completed','Completed'),('failed','Failed'),('skipped','Skipped')],
                    default='running',
                    max_length=20,
                )),
                ('session', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='module_runs',
                    to='core.scansession',
                )),
            ],
            options={'ordering': ['started_at']},
        ),
        migrations.CreateModel(
            name='ScanTimelineEvent',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('timestamp', models.DateTimeField(default=django.utils.timezone.now)),
                ('event_type', models.CharField(max_length=50)),
                ('module', models.CharField(blank=True, max_length=100)),
                ('message', models.CharField(max_length=500)),
                ('data', models.JSONField(blank=True, null=True)),
                ('session', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='timeline_events',
                    to='core.scansession',
                )),
            ],
            options={'ordering': ['timestamp']},
        ),
    ]
