from django.urls import path
from .views import *

app_name = 'account'

urlpatterns = [
    path('signup/',SignupAPIView.as_view(), name = 'signup'),
    path('login/',LoginAPIView.as_view(), name = 'login'),
    path('child/create/',ChildCreateAPIView.as_view(),name='create_child'),
    # path('guardian/list/',GuardianList.as_view(), name='guardian_list'),
    # path('child/list/',ChildList.as_view(), name='child_list'),
    path('guardian/<int:guardian_id>/child/create/',ChildCreateAPIView.as_view(),name='create_child'),
    # path('guardian/<int:guardian_id>/',ListAPIView.as_view(),name='child_list'),
    # path('guardian/list/<int:guardian_id>',GuardianList.as_view(),name='guardian_list'),



]
