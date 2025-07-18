
from django.contrib import admin
from django.urls import path, include
from .views import login_view

urlpatterns = [
    path('admin/', admin.site.urls),
    path('login/', login_view, name='login'),
    path('ip_tracking/', include('ip_tracking.urls')),
]
