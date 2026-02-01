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
        page = request.GET.get('page', '1')
        page_size = request.GET.get('page_size', '10')
        sort_by = request.GET.get('sort_by', 'created_at')
        sort_order = request.GET.get('sort_order', 'desc')

        data = {
            'page': page,
            'page_size': page_size,
            'sort_by': sort_by,
            'sort_order': sort_order
        }

        kwargs.update({
            'data': data
        })
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

class UsersDashboard(View):
    def get(self, request, *args, **kwargs):
        return render(request=request, template_name='users.html')

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

class PasswordPolicies(View):
    @verify_token_required
    def get(self, request, *args, **kwargs):
        data = {
            'page': request.GET.get('page', '1'),
            'page_size': request.GET.get('page_size', '10'),
            'sort_by': request.GET.get('sort_by', 'created_at'),
            'sort_order': request.GET.get('sort_order', 'desc'),
            'is_active': request.GET.get('is_active', '')
        }

        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='get_policies')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)


class PasswordPolicyDetails(View):
    @verify_token_required
    def get(self, request, *args, **kwargs):
        # Extract query parameters for getting policy details
        data = {
            'policy_id': request.GET.get('policy_id', ''),
        }

        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='get_policy_details')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

    @verify_token_required
    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)

        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='create_policy')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

    @verify_token_required
    def put(self, request, *args, **kwargs):
        data = json.loads(request.body)

        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='update_policy')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

    @verify_token_required
    def delete(self, request, *args, **kwargs):
        data = json.loads(request.body)

        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='delete_policy')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

class ManagePasswordPolicies(View):
    def get(self, request, *args, **kwargs):
        return render(request=request, template_name='policies.html')
