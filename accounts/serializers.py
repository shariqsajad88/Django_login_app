from rest_framework import serializers
from django.contrib.auth.models import User
from .models import UserProfile, OTPRecord

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'password')
    
    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        return user

class UserProfileSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True)
    email = serializers.CharField(source='user.email', read_only=True)
    two_factor_enabled = serializers.BooleanField(read_only=True)
    
    class Meta:
        model = UserProfile
        fields = ('id', 'username', 'email', 'bio', 'phone_number', 'two_factor_enabled')

class OTPVerificationSerializer(serializers.Serializer):
    username = serializers.CharField()
    otp = serializers.CharField(max_length=6, min_length=6)

class RequestOTPSerializer(serializers.Serializer):
    username = serializers.CharField()