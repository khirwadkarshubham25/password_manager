from django.urls import path

from vault import views

urlpatterns = [
    # --- User Passwords ---
    path('api/user_passwords', views.UserPasswordsView.as_view(), name='api-user-passwords'),
    # --- Generate Password ---
    path('api/generate_password', views.GeneratePasswordView.as_view(), name='api-generate-password'),

    path('dashboard', views.VaultDashboard.as_view(), name='vault-dashboard'),
]