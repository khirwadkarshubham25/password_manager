from django.urls import path

from password_vault_manager import views

urlpatterns = [
    path("signup", views.SignUp.as_view(), name='signup'),
    path("create_master_password", views.CreateMasterPasswordView.as_view(), name='create_master_password'),
    path("login", views.Login.as_view(), name='login'),
    path("home", views.Home.as_view(), name='home')
]