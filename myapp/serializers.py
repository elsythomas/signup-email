from rest_framework import serializers
from .models import Student, Admin


class LoginSerializer(serializers.ModelSerializer):
    class Meta:
        model= Student
        fields = ["email","password"]

class LoginAdminSerializer(serializers.ModelSerializer):
    class Meta:
        model= Student
        fields = ["name","email", "Role"]
