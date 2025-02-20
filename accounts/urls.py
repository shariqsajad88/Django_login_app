from django.urls import path
from . import views 
from accounts.views import PasswordResetConfirmView


urlpatterns = [
    # API endpoints
    path('register/', views.RegisterView.as_view(), name='register_api'),
    path('login/', views.LoginView.as_view(), name='login_api'),
    path('logout/', views.LogoutView.as_view(), name='logout_api'),
    path('request-otp/', views.RequestOTPView.as_view(), name='request_otp_api'),
    path('verify-otp/', views.VerifyOTPView.as_view(), name='verify_otp_api'),
    path('toggle-2fa/', views.Toggle2FAView.as_view(), name='toggle_2fa_api'),
    path('disable-2fa/', views.Disable2FAView.as_view(), name='disable-2fa'),
    path('home/', views.home_page, name='home_api'),
    path('password-reset/', views.PasswordResetRequestView.as_view(), name='password-reset-request'),
    
    # Template URLs
    path('register-page/', views.register_page, name='register_page'),
    path('login-page/', views.login_page, name='login_page'),
    path('otp-verification-page/', views.otp_verification_page, name='otp_verification_page'),
    path('home-page/', views.home_page_template, name='home_page'),
    path('forgot-password/', views.forgot_password_page, name='forgot-password'),
    path('reset-password/<str:uid>/<str:token>/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),

]