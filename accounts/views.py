import json

from django.http import JsonResponse
from django.shortcuts import render
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import ListView

from password_manager.services.view_services import ViewServices


@method_decorator(csrf_exempt, name='dispatch')
class LoginView(View):
    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)

        kwargs.update({
            'data': data
        })
        service_obj = ViewServices(service_name='login_user')
        status_code, data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(data, safe=False, status=status_code)


@method_decorator(csrf_exempt, name='dispatch')
class RegisterView(View):
    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)

        kwargs.update({
            'data': data
        })
        service_obj = ViewServices(service_name='register_user')
        status_code, data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(data, safe=False, status=status_code)


class Login(View):
    def get(self, request, *args, **kwargs):
        return render(request, 'login.html')

class Register(View):
    def get(self, request, *args, **kwargs):
        return render(request, 'register.html')
