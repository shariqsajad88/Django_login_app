from django.http import HttpResponse
from django.views import View
from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.decorators import api_view, permission_classes
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.shortcuts import render
from django.utils import timezone
from .serializers import (
    UserSerializer, 
    UserProfileSerializer, 
    OTPVerificationSerializer,
    RequestOTPSerializer
)
from django.contrib.auth import get_user_model
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from .models import UserProfile, OTPRecord
from .otp_utils import OTPManager
from datetime import  timedelta
from django.utils.timezone import now
from django.contrib.auth.tokens import default_token_generator
from rest_framework.permissions import IsAuthenticated
from django.core.mail import send_mail
from django.conf import settings
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes,  force_str

class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            UserProfile.objects.create(user=user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class RequestOTPView(APIView):
    def post(self, request):
        serializer = RequestOTPSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        username = serializer.validated_data['username']
        
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({"detail": "User not found"}, status=status.HTTP_404_NOT_FOUND)
            
        # Generate and store OTP
        otp = OTPManager.generate_otp()
        OTPRecord.objects.create(user=user, otp=otp)
        
        # Send OTP via email
        OTPManager.send_otp_email(user.email, otp)
        
        return Response({"detail": "OTP sent to your email"}, status=status.HTTP_200_OK)

class VerifyOTPView(APIView):
    def post(self, request):
        serializer = OTPVerificationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        username = serializer.validated_data['username']
        user_otp = serializer.validated_data['otp']
        
        try:
            user = User.objects.get(username=username)
            otp_record = OTPRecord.objects.filter(
                user=user, 
                is_used=False
            ).order_by('-created_at').first()
            
            if not otp_record:
                return Response({"detail": "No active OTP found"}, status=status.HTTP_400_BAD_REQUEST)
                
            # Verify OTP
            if OTPManager.verify_otp(otp_record.otp, user_otp, otp_record.created_at):
                # Mark OTP as used
                otp_record.is_used = True
                otp_record.save()
                
                # Log user in
                login(request, user)
                
                profile = UserProfile.objects.get(user=user)
                return Response({
                    'detail': 'OTP verified successfully',
                    'user_id': user.id,
                    'username': user.username,
                    'two_factor_enabled': profile.two_factor_enabled
                }, status=status.HTTP_200_OK)
            else:
                return Response({"detail": "Invalid or expired OTP"}, status=status.HTTP_400_BAD_REQUEST)
                
        except User.DoesNotExist:
            return Response({"detail": "User not found"}, status=status.HTTP_404_NOT_FOUND)
@method_decorator(csrf_exempt, name='dispatch')
class LoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({'detail': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

        # Get the user's profile
        profile, created = UserProfile.objects.get_or_create(user=user)

        # Check if the user is locked out
        if profile.is_locked():
            return Response({
                'detail': 'Too many failed attempts. Try again later.'
            }, status=status.HTTP_403_FORBIDDEN)

        user = authenticate(username=username, password=password)

        if user:
            # Reset failed attempts on successful login
            profile.reset_lockout()

            # Check if 2FA is enabled
            if profile.two_factor_enabled:
                otp = OTPManager.generate_otp()
                OTPRecord.objects.create(user=user, otp=otp)
                OTPManager.send_otp_email(user.email, otp)

                return Response({
                    'detail': 'Please verify with OTP sent to your email',
                    'requires_2fa': True,
                    'username': username
                }, status=status.HTTP_200_OK)
            else:
                login(request, user)
                return Response({
                    'detail': 'Successfully logged in',
                    'user_id': user.id,
                    'username': user.username,
                    'requires_2fa': False
                }, status=status.HTTP_200_OK)
        else:
            # Increment failed attempts
            profile.failed_attempts += 1
            if profile.failed_attempts >= 3:
                profile.lockout_until = now() + timedelta(hours=1)  # Lock for 1 hour
                profile.failed_attempts = 3  # Cap failed attempts at 3
            profile.save()

            return Response({
                'detail': 'Invalid credentials'
            }, status=status.HTTP_401_UNAUTHORIZED)
class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        logout(request)
        return Response({
            'detail': 'Successfully logged out'
        }, status=status.HTTP_200_OK)

class Toggle2FAView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        try:
            profile = UserProfile.objects.get(user=request.user)
            # Toggle 2FA status
            profile.two_factor_enabled = not profile.two_factor_enabled
            profile.save()
            
            return Response({
                'detail': f"Two-factor authentication {'enabled' if profile.two_factor_enabled else 'disabled'}",
                'two_factor_enabled': profile.two_factor_enabled
            }, status=status.HTTP_200_OK)
        except UserProfile.DoesNotExist:
            return Response({
                'detail': 'User profile not found'
            }, status=status.HTTP_404_NOT_FOUND)

@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def home_page(request):
    try:
        profile = UserProfile.objects.get(user=request.user)
        serializer = UserProfileSerializer(profile)
        return Response({
            'detail': 'Welcome to the home page!',
            'user': serializer.data
        })
    except UserProfile.DoesNotExist:
        return Response({
            'detail': 'Profile not found'
        }, status=status.HTTP_404_NOT_FOUND)
    

class Disable2FAView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        user.two_factor_enabled = False  
        user.save()
        return Response({'message': 'Two-factor authentication disabled successfully.'})
    
class PasswordResetRequestView(APIView):
    def post(self, request):
        email = request.data.get('email')
        try:
            user = User.objects.get(email=email)
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            reset_link = f"{settings.FRONTEND_URL}/reset-password/{uid}/{token}/"

            # Send email
            subject = "Password Reset Request"
            message = f"Click the link below to reset your password:\n{reset_link}"
            send_mail(subject, message, settings.EMAIL_HOST_USER, [email])

            return Response({"message": "Password reset link sent!"}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "User with this email does not exist."}, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetRequestView(APIView):
    def post(self, request):
        email = request.data.get("email")
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)
        
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        reset_link = f"{settings.FRONTEND_URL}/reset-password/{uid}/{token}/"
        
        send_mail(
            "Password Reset Request",
            f"Click the link below to reset your password:\n{reset_link}",
            settings.DEFAULT_FROM_EMAIL,
            [email],
            fail_silently=False,
        )
        
        return Response({"message": "Password reset link has been sent to your email."}, status=status.HTTP_200_OK)


User = get_user_model()

class PasswordResetConfirmView(View):
    def get(self, request, uid, token):
        """Render the password reset form"""
        return render(request, 'reset_password.html', {'uid': uid, 'token': token})

    @method_decorator(csrf_exempt)
    def post(self, request, uid, token):
        """Handle password reset form submission"""
        new_password = request.POST.get("new_password")
        confirm_password = request.POST.get("confirm_password")

        if new_password != confirm_password:
            return Response({"error": "Passwords do not match"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user_id = urlsafe_base64_decode(uid).decode()
            user = User.objects.get(pk=user_id)
        except (User.DoesNotExist, ValueError):
            return Response({"error": "Invalid user"}, status=status.HTTP_404_NOT_FOUND)

        if not default_token_generator.check_token(user, token):
            return Response({"error": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)

        # Set new password
        user.set_password(new_password)
        user.save()

        return Response({"message": "Password reset successful! Redirecting to login..."}, status=status.HTTP_200_OK)



# Template views
def register_page(request):
    return render(request, 'accounts/register.html')

def login_page(request):
    return render(request, 'accounts/login.html')

def otp_verification_page(request):
    return render(request, 'accounts/otp_verification.html')

def home_page_template(request):
    return render(request, 'accounts/home.html')
def forgot_password_page(request):
    return render(request, 'forgot_password.html')

