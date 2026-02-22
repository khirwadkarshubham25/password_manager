from django.urls import path

from accounts import views

urlpatterns = [
    path('api/login', views.LoginView.as_view(), name='api-login'),
    path('api/register', views.RegisterView.as_view(), name='api-register'),

    path('login', views.Login.as_view(), name='login'),
    path('register', views.Register.as_view(), name='register'),

]