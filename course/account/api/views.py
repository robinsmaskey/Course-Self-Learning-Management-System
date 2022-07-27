from django.contrib.auth import get_user_model, password_validation
from account.models import Guardian
from rest_framework.generics import CreateAPIView, RetrieveAPIView, UpdateAPIView, ListCreateAPIView, ListAPIView
from rest_framework.response import Response
from account.api.serializers import SignupSerializer, LoginSerializer, ChildListSerializer
from rest_framework.exceptions import NotFound, ValidationError,  PermissionDenied
# from course.account.models import PortalUser
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated, IsAdminUser, IsAuthenticatedOrReadOnly
from django.contrib.auth.decorators import permission_required
from account.models import Guardian, Child



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


class LoginAPIView(CreateAPIView):
    serializer_class = LoginSerializer

    def create(self, request, *args, **kwargs):
        try:
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
        except Exception as e:
             return Response({
                    'e:': str(e),
                })



class ChildCreateAPIView(ListCreateAPIView):
    serializer_class = ChildListSerializer
    permission_class = (IsAuthenticated,)

    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data) # ---> getting the data from serializers class
        if serializer.is_valid(raise_exception = True):
            # queryset = Child.objects.create(full_name=full_name, username=username, pin=pin, confirm_pin=confirm_pin)
            full_name = serializer.validated_data['full_name']
            # full_name2 = serializer.validated_data['full_name2'] 
            username = serializer.validated_data['username']
            # username2 = serializer.validated_data['username2']
            pin = serializer.validated_data['pin']
            # pin2 = serializer.validated_data['pin2']
            print(pin)
            # print(pin2)
            # child = Child.objects.create(username=username, full_name=full_name, pin=pin)
            # guardian = Child.objects.create(username=username,full_name=full_name, pin=pin)
            child = Child.objects.create(username=username,full_name=full_name, pin=pin)
            # child2 = Child.objects.create(username=username,full_name=full_name, pin=pin)
            # Guardian.child.add(child)
            # guardian.Child.add(Child)
            # guardian_id = kwargs.get('guardian_id')
            # guardian = Guardian.objects.get(guardian_id=guardian_id)
            child.save()
            return Response(serializer.data)

    def get_queryset(self):
        return Guardian.objects.all()


# class GuardianAPIView(ListAPIView):
#     serializer_class = GuardianSerializer
#     permission_classes = (IsAdminUser,)

#     def get_queryset(self):
#         return Guardian.objects.all()
    
#     def perform_create(self, serializer):
#         if self.request.user.user_type == 'guardian':
#             serializer.save(user=self.request.user, is_active=True)
#         else:
#             raise PermissionDenied('You do not have permission to create child profile.')

# class GuardianList(ListCreateAPIView):
#     queryset = User.objects.all()
#     serializer_class = ChildListSerializer
#     permission_classes = [IsAdminUser]

#     def list(self, request):
#         # Note the use of `get_queryset()` instead of `self.queryset`
#         queryset = self.get_queryset()
#         serializer = ChildListSerializer(queryset, many=True)
#         return Response(serializer.data)

# class GuardianList(ListAPIView):
#     queryset = Child.objects.all()
#     serializer_class = ChildListSerializer

#     # queryset = User.objects.all()
#     # serializer_class = GuardianListSerializer
#     def get_queryset(self):
#         child = self.request.user
#         # guardian_id = kwargs.get('guardian_id')
#         # Guardian = Guardian.objects.get(id=guardian_id)
#         return Guardian.objects.filter(guardian=child)

#     def __init__(self, **kwargs):
#         self.name = input("Name: ")
#         self.child = self.get_child()

#         for key, value in kwargs.guardian():
#             setattr(self, key, value)

# class ChildList(ListAPIView):
#     queryset = Child.objects.all()
#     serializer_class = ChildListSerializer
    
