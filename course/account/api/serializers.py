from tkinter import NUMERIC
from rest_framework import serializers
from django import forms
from django.contrib.auth.models import User
from django.utils import timezone
from django.contrib.auth import get_user_model, password_validation
from rest_framework.exceptions import ValidationError
from rest_framework.serializers import (CharField)
from django.contrib.auth.password_validation import validate_password
from django.core.validators import RegexValidator
import re
from django.utils.translation import gettext_lazy as _
from account.models import Child, Guardian

User = get_user_model()

class SignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True, required=True)
    
    class Meta:
        model = User
        fields = ('username','full_name', 'email', 'password', 'confirm_password','user_type')
   

    def validate_password(self, password):
        password_validation.validate_password(password)
        return password

            
    def validate_username(self, username):
        # alphanumeric = RegexValidator(r'^[0-9a-zA-Z]*$', 'Only alphanumeric characters are allowed.')
        # if 'username' not in alphanumeric:
        #    raise ValidationError('Please enter a valid username in alpha numeric values only.')
        if len(username) < 10:
            raise forms.ValidationError("username must contain 10 digits.")
        return username

    
    def validate(self, password, user=None):
        if not re.findall('[()[\]{}|\\`~!@#$%^&*_\-+=;:\'",<>./?]', str(password)):
            raise ValidationError(
                _("The password must contain at least 1 symbol: " +
                  "()[]{}|\`~!@#$%^&*_-+=;:'\",<>./?"),
                code='password_no_symbol',
            )
        return password

    def get_help_text(self):
        return _(
            "Your password must contain at least 1 symbol: " +
            "()[]{}|\`~!@#$%^&*_-+=;:'\",<>./?"
        )

    def validate(self, attrs):
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})

        return attrs


# class ConfirmPasswordSerializer(serializers.ModelSerializer):
#     password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
#     password2 = serializers.CharField(write_only=True, required=True)

#     class Meta:
#         model = User
#         fields = ('password', 'password2')

#     def validate(self, attrs):
#         if attrs['password'] != attrs['password2']:
#             raise serializers.ValidationError({"password": "Password fields didn't match."})

#         return attrs

    
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required = True)
    # phone = serializers.CharField(required = False)
    password = serializers.CharField(required = True)
    USER_TYPES = (
        ('CHILD', 'child'),
        ('GUARDIAN', 'guardian'),
    )
    user_type = serializers.ChoiceField(choices=USER_TYPES,required=True)

# class GuardianListSerializer(serializers.ModelSerializer):

#     class Meta:
#         model = User
#         fields = ['full_name', 'username', 'address', 'email', 'image', 'is_active', 'is_verified', 'user_type']



class ChildListSerializer(serializers.ModelSerializer):
    pin = serializers.IntegerField(required=True)
    confirm_pin = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = Child
        fields = ('full_name','username','pin', 'confirm_pin')

    def validate_pin(self, pin):
        pin = str(pin)
        if len(pin) == 4:   
            return pin
        raise serializers.ValidationError('PIN must be 4 digit numbers.')

    def validate(self, attrs):
        if attrs['pin'] != attrs['confirm_pin']:
            raise serializers.ValidationError({"pin": "PIN didn't match."})

        return attrs


