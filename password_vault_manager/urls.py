from django.urls import path

from password_vault_manager import views

urlpatterns = [
    path("register/", views.RegisterUser.as_view(), name='register'),
    path("login/", views.Login.as_view(), name='login'),
    path("dashboard/", views.Dashboard.as_view(), name='dashboard'),
    path("manage_password", views.ManagePassword.as_view(), name='manage_password'),
    path("refresh_token", views.RefreshToken.as_view(), name='refresh_token'),
]