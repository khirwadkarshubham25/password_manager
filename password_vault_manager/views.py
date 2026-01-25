import json

from django.http import JsonResponse
from django.shortcuts import render
from django.views import View
from rest_framework.views import APIView

from password_manager.commons.token_verifier import verify_token_required
from password_manager.services.view_services import ViewServices


class RegisterUser(View):
    def get(self, request, *args, **kwargs):
        return render(request=request, template_name='register.html')

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
        return render(request=request, template_name='login.html')

    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)

        kwargs.update({
            'data': data
        })
        service_obj = ViewServices(service_name='login_user')
        status_code, data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(data, safe=False, status=status_code)

class Dashboard(View):
    def get(self, request, *args, **kwargs):
        return render(request=request, template_name='dashboard.html')


class ManagePassword(View):
    @verify_token_required
    def get(self, request, *args, **kwargs):
        user_id = request.GET.get('user_id', '')

        data = {
            'user_id': user_id
        }

        kwargs.update({
            'data': data
        })
        service_obj = ViewServices(service_name='get_passwords')
        status_code, data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(data, safe=False, status=status_code)

    @verify_token_required
    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)

        kwargs.update({
            'data': data
        })
        service_obj = ViewServices(service_name='create_password')
        status_code, data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(data, safe=False, status=status_code)

    @verify_token_required
    def put(self, request, *args, **kwargs):
        data = json.loads(request.body)

        kwargs.update({
            'data': data
        })
        service_obj = ViewServices(service_name='update_password')
        status_code, data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(data, safe=False, status=status_code)

    @verify_token_required
    def delete(self, request, *args, **kwargs):
        data = json.loads(request.body)

        kwargs.update({
            'data': data
        })
        service_obj = ViewServices(service_name='delete_password')
        status_code, data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(data, safe=False, status=status_code)

class RefreshToken(View):
    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)

        kwargs.update({
            'data': data
        })
        service_obj = ViewServices(service_name='refresh_token')
        status_code, data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(data, safe=False, status=status_code)