from django.contrib.auth import get_user_model, password_validation
from rest_framework.generics import CreateAPIView, RetrieveAPIView, UpdateAPIView
from rest_framework.response import Response
from account.api.serializers import SignupSerializer, LoginSerializer, ConfirmPasswordSerializer
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated, IsAdminUser, IsAuthenticatedOrReadOnly
from django.contrib.auth.decorators import permission_required



User = get_user_model()

class SignupAPIView(CreateAPIView):
    serializer_class = SignupSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data) # ---> getting the data from serializers class
        if serializer.is_valid(raise_exception = True):
            # --- validating serializers.py data ---
            full_name = serializer.validated_data['full_name'] 
            username = serializer.validated_data['username']
            email = serializer.validated_data['email'] 
            password = serializer.validated_data['password']
            print(password)
            user_type = serializer.validated_data['user_type']
            user = User.objects.create(username=username, full_name=full_name, email=email, user_type=user_type)
            user.set_password(password)
            user.is_verified = True
            user.save()
            return Response(serializer.data)

class ConfirmPasswordAPIView(UpdateAPIView):
    serializer_class = ConfirmPasswordSerializer

    def get_object(self):
        return self.request.user


class LoginAPIView(CreateAPIView):
    serializer_class = LoginSerializer

    def create(self, request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data)

        if serializer.is_valid(raise_exception=True): 
            try:
                user = User.objects.get(username=serializer.validated_data['username'])
            except User.DoesNotExist:
                raise NotFound({"username": "User with the provided username does not exist."})  # exception message
            if not user.check_password(serializer.validated_data['password']):
                raise ValidationError({'password': "Incorrect password"})
            if not (user.is_active or user.is_verified):
                raise ValidationError({'email': "User not activated or is unverified"})
            user_type = serializer.validated_data['user_type']
            token = RefreshToken.for_user(user)  # method to generating access and refresh token for users
            print(dir(token))
            return Response({
                'refresh': str(token),
                'access': str(token.access_token)
            })



