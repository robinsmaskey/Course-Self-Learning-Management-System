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

User = get_user_model()

class SignupSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = User
        # password2 = CharField(label='Confirm Password')
        fields = ('username','full_name', 'email', 'password','phone', 'user_type')

    # class CustomUserDetailsSerializer(serializers.Serializer):

    #     class Meta:
    #         model = User
    #         fields = ('confirm_password',)


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


class ConfirmPasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ('password', 'password2')

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})

        return attrs

    
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required = True)
    # phone = serializers.CharField(required = False)
    password = serializers.CharField(required = True)
    USER_TYPES = (
        ('CHILD', 'child'),
        ('GUARDIAN', 'guardian'),
    )
    user_type = serializers.ChoiceField(choices=USER_TYPES,required=True)
