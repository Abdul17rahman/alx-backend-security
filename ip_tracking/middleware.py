import requests
from datetime import datetime
from django.core.cache import cache
from django.http import HttpResponseForbidden
from .models import RequestLog, BlockedIP


class RequestLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip_address = self.get_client_ip(request)

        # Block check
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            return HttpResponseForbidden("Your IP has been blocked.")

        # Check cache for geolocation
        cache_key = f"geo:{ip_address}"
        geo_data = cache.get(cache_key)

        if not geo_data:
            geo_data = self.get_geolocation(ip_address)
            cache.set(cache_key, geo_data, timeout=86400)  # 24 hours

        # Log request
        RequestLog.objects.create(
            ip_address=ip_address,
            timestamp=datetime.now(),
            path=request.path,
            country=geo_data.get('country', ''),
            city=geo_data.get('city', '')
        )

        return self.get_response(request)

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')

    def get_geolocation(self, ip):
        try:
            response = requests.get(f'https://ipapi.co/{ip}/json/')
            if response.status_code == 200:
                data = response.json()
                return {
                    'country': data.get('country_name', ''),
                    'city': data.get('city', '')
                }
        except Exception as e:
            pass
        return {'country': '', 'city': ''}
