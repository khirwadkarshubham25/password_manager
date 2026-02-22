import json

from django.http import JsonResponse
from django.shortcuts import render
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from password_manager.commons.token_verifier import verify_token_required
from password_manager.services.view_services import ViewServices


# ---------------------------------------------------------------------------
# User Passwords — list + create + update + delete
# ---------------------------------------------------------------------------

@method_decorator(csrf_exempt, name='dispatch')
class UserPasswordsView(View):

    @verify_token_required
    def get(self, request, *args, **kwargs):
        data = {
            'user_id': request.user_id,
            'page': request.GET.get('page', '1'),
            'page_size': request.GET.get('page_size', '10'),
            'sort_by': request.GET.get('sort_by', 'created_at'),
            'sort_order': request.GET.get('sort_order', 'desc'),
            'search': request.GET.get('search', '').strip()
        }
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='get_user_passwords')
        status_code, data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(data, safe=False, status=status_code)

    @verify_token_required
    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)
        data['user_id'] = request.user_id
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='create_user_password')
        status_code, data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(data, safe=False, status=status_code)

    @verify_token_required
    def put(self, request, *args, **kwargs):
        data = json.loads(request.body)
        data['user_id'] = request.user_id
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='update_user_password')
        status_code, data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(data, safe=False, status=status_code)

    @verify_token_required
    def delete(self, request, *args, **kwargs):
        data = json.loads(request.body)
        data['user_id'] = request.user_id
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='delete_user_password')
        status_code, data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(data, safe=False, status=status_code)

# ---------------------------------------------------------------------------
# Generate Password — policy-aware, no length param
# ---------------------------------------------------------------------------

@method_decorator(csrf_exempt, name='dispatch')
class GeneratePasswordView(View):

    @verify_token_required
    def get(self, request, *args, **kwargs):
        data = {
            'user_id': request.user_id,
        }
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='generate_password')
        status_code, data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(data, safe=False, status=status_code)


# ---------------------------------------------------------------------------
# Template views
# ---------------------------------------------------------------------------

class VaultDashboard(View):
    def get(self, request, *args, **kwargs):
        return render(request, 'dashboard.html')
