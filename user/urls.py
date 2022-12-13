
from django.contrib import admin
from django.urls import path,include
from .views import *

urlpatterns = [
  path('search/<str:userName>', UserView.as_view())
]