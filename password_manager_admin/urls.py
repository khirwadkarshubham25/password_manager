from django.urls import path

from password_manager_admin import views

urlpatterns = [
    path("register", views.RegisterAdminUser.as_view(), name='register'),
    path("login", views.LoginAdminUser.as_view(), name='login'),
    path("refresh_token", views.RefreshToken.as_view(), name='refresh_token'),
]