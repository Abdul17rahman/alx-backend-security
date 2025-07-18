from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django_ratelimit.decorators import ratelimit
from django_ratelimit.core import get_usage


@csrf_exempt
# Check but don't block yet
@ratelimit(key='user_or_ip', rate='10/m', block=False)
def login_view(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=400)

    # Determine appropriate rate
    is_authenticated = request.user.is_authenticated
    ip = request.META.get('REMOTE_ADDR')
    rate = '10/m' if is_authenticated else '5/m'
    key = 'user_or_ip' if is_authenticated else 'ip'

    # Manually check the limit
    usage = get_usage(
        request=request,
        group=None,
        fn=None,
        key=key,
        rate=rate,
        method=['POST'],
        increment=True,
    )

    if usage['should_limit']:
        return JsonResponse(
            {'error': 'Rate limit exceeded. Try again later.'},
            status=429
        )

    # Example login logic
    return JsonResponse({'status': 'success', 'message': 'Login attempt received'})
