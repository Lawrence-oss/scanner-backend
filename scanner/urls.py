"""
URL configuration for scanner project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from api.views import ScanView, SimpleCaptchaView
from api.auth_views import register, login, profile, logout

urlpatterns = [
    # Scan endpoints
    path('api/scan/', ScanView.as_view(), name='scan_create'),
    path('api/scan/<str:scan_id>/', ScanView.as_view(), name='scan_detail'),
    
    # Captcha endpoint
    path('api/captcha/', SimpleCaptchaView.as_view(), name='captcha'),
    
    # Auth endpoints
    path('api/auth/register/', register, name='register'),
    path('api/auth/login/', login, name='login'),
    path('api/auth/logout/', logout, name='logout'),
    path('api/user/profile/', profile, name='profile'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
]