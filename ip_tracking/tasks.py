from datetime import datetime, timedelta
from django.utils.timezone import now
from ip_tracking.celery import shared_task
from .models import RequestLog, SuspiciousIP

SENSITIVE_PATHS = ['/admin', '/login']


@shared_task
def detect_suspicious_ips():
    one_hour_ago = now() - timedelta(hours=1)
    recent_logs = RequestLog.objects.filter(timestamp__gte=one_hour_ago)

    # Count requests per IP
    ip_counts = {}
    ip_sensitive_hits = set()

    for log in recent_logs:
        ip = log.ip_address
        ip_counts[ip] = ip_counts.get(ip, 0) + 1
        if any(log.path.startswith(path) for path in SENSITIVE_PATHS):
            ip_sensitive_hits.add(ip)

    # Flag IPs
    for ip, count in ip_counts.items():
        if count > 100:
            SuspiciousIP.objects.get_or_create(
                ip_address=ip, reason='Too many requests in 1 hour')

    for ip in ip_sensitive_hits:
        SuspiciousIP.objects.get_or_create(
            ip_address=ip, reason='Accessed sensitive path')
