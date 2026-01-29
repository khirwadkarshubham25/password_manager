import json

from django.http import JsonResponse
from django.shortcuts import render
from django.views import View

from password_manager.commons.token_verifier import verify_token_required
from password_manager.services.view_services import ViewServices

class RegisterAdminUser(View):
    def get(self, request, *args, **kwargs):
        return render(request=request, template_name='admin_register.html')

    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)

        kwargs.update({
            'data': data
        })
        service_obj = ViewServices(service_name='register_admin_user')
        status_code, data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(data, safe=False, status=status_code)


class LoginAdminUser(View):
    def get(self, request, *args, **kwargs):
        return render(request=request, template_name='admin_login.html')

    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)

        kwargs.update({
            'data': data
        })
        service_obj = ViewServices(service_name='login_admin_user')
        status_code, data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(data, safe=False, status=status_code)

class Dashboard(View):
    def get(self, request, *args, **kwargs):
        return render(request=request, template_name='admin_dashboard.html')


class ManageUsers(View):
    @verify_token_required
    def get(self, request, *args, **kwargs):
        service_obj = ViewServices(service_name='get_users')
        status_code, data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(data, safe=False, status=status_code)

    @verify_token_required
    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)

        kwargs.update({
            'data': data
        })
        service_obj = ViewServices(service_name='create_users')
        status_code, data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(data, safe=False, status=status_code)

    @verify_token_required
    def put(self, request, *args, **kwargs):
        data = json.loads(request.body)

        kwargs.update({
            'data': data
        })
        service_obj = ViewServices(service_name='update_users')
        status_code, data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(data, safe=False, status=status_code)

    @verify_token_required
    def delete(self, request, *args, **kwargs):
        data = json.loads(request.body)

        kwargs.update({
            'data': data
        })
        service_obj = ViewServices(service_name='delete_users')
        status_code, data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(data, safe=False, status=status_code)

class RefreshToken(View):
    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)
        data["is_admin"] = True

        kwargs.update({
            'data': data
        })
        service_obj = ViewServices(service_name='refresh_token')
        status_code, data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(data, safe=False, status=status_code)