from django.contrib import admin
from django.urls import path, include
from accounts import views as account_views
from accounts.views import PasswordResetConfirmView 



urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('accounts.urls')),
    
    # Direct template URLs
    path('register/', account_views.register_page, name='register'),
    path('login/', account_views.login_page, name='login'),
    path('verify-otp/', account_views.otp_verification_page, name='verify_otp'),
    path('home/', account_views.home_page_template, name='home'),
    path('forgot-password/', account_views.forgot_password_page, name='forgot-password'),
    path('reset-password/<str:uid>/<str:token>/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
]

