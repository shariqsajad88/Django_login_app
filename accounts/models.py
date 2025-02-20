from django.db import models
from django.contrib.auth.models import User
from datetime import datetime, timedelta
from django.utils import timezone

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    bio = models.TextField(blank=True)
    phone_number = models.CharField(max_length=15, blank=True, null=True)

    # Two-factor authentication fields
    two_factor_enabled = models.BooleanField(default=False)

    # Failed login tracking
    failed_attempts = models.IntegerField(default=0)
    lockout_until = models.DateTimeField(null=True, blank=True)

    def is_locked(self):
        """Check if the user is locked out"""
        if self.lockout_until and timezone.now() < self.lockout_until:
            return True
        return False

    def reset_lockout(self):
        """Reset failed attempts after successful login"""
        self.failed_attempts = 0
        self.lockout_until = None
        self.save()

    def __str__(self):
        return self.user.username

class OTPRecord(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    is_used = models.BooleanField(default=False)

    def __str__(self):
        return f"OTP for {self.user.username}"
