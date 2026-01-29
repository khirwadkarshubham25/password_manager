from django.urls import path

from password_manager_users import views

urlpatterns = [
    path("register", views.RegisterUser.as_view(), name='register'),
    path("login", views.Login.as_view(), name='login')
]