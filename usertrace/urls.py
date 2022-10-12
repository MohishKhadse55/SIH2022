from django.urls import path

from . import views
from django.urls import path

urlpatterns = [
    path('', views.home,),
    path('logout', views.sign_out),
    path('signin', views.signin),
    path('register', views.register),
    path('dash', views.dash),
    path('userdetails', views.user_details)
]
