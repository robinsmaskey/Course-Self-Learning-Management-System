from django.urls import path
from .views import *

app_name = 'account'

urlpatterns = [
    path('signup/',SignupAPIView.as_view(), name = 'signup'),
    path('login/',LoginAPIView.as_view(), name = 'login'),
    path('password/confirm/', ConfirmPasswordAPIView.as_view(), name='pwd_confirm'),


]