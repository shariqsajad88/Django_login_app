import pyotp
import random
from django.core.mail import send_mail
from django.conf import settings
from datetime import datetime, timedelta
from django.utils.timezone import now

class OTPManager:
    @staticmethod
    def generate_otp():
        """Generate a 6-digit OTP"""
        return str(random.randint(100000, 999999))
    
    @staticmethod
    def send_otp_email(email, otp):
        """Send OTP to user's email"""
        subject = 'Your Authentication Code'
        message = f'Your verification code is: {otp}\nThis code will expire in 10 minutes.'
        from_email = settings.EMAIL_HOST_USER
        recipient_list = [email]

        try:
            send_mail(subject, message, from_email, recipient_list, fail_silently=False)
            print(f"✅ OTP sent to {email}")
        except Exception as e:
            print(f" Failed to send email: {e}")
    
    @staticmethod
    def verify_otp(stored_otp, user_otp, timestamp):
        if not stored_otp or not user_otp:
            return False
        expiry_time = timestamp + timedelta(minutes=10)
        if now() > expiry_time:
            return False
        return stored_otp == user_otp