import json

from django.http import JsonResponse
from django.shortcuts import render
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import ListView

from password_manager.commons.token_verifier import verify_token_required
from password_manager.services.view_services import ViewServices


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

@method_decorator(csrf_exempt, name='dispatch')
class UsersView(ListView):
    # @verify_token_required
    def get(self, request, *args, **kwargs):
        data = {
            'page': request.GET.get('page', '1'),
            'page_size': request.GET.get('page_size', '10'),
            'sort_by': request.GET.get('sort_by', 'created_at'),
            'sort_order': request.GET.get('sort_order', 'desc')
        }
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='get_users')
        status_code, data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(data, safe=False, status=status_code)


@method_decorator(csrf_exempt, name='dispatch')
class UserDetailsView(View):
    # @verify_token_required
    def get(self, request, *args, **kwargs):
        data = {'user_id': request.GET.get('user_id', 0)}
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='get_user_details')
        status_code, data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(data, safe=False, status=status_code)

    # @verify_token_required
    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='create_user')
        status_code, data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(data, safe=False, status=status_code)

    # @verify_token_required
    def put(self, request, *args, **kwargs):
        data = json.loads(request.body)
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='update_user')
        status_code, data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(data, safe=False, status=status_code)

    # @verify_token_required
    def delete(self, request, *args, **kwargs):
        data = json.loads(request.body)
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='delete_user')
        status_code, data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(data, safe=False, status=status_code)


# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------

@method_decorator(csrf_exempt, name='dispatch')
class RolesView(View):
    # @verify_token_required
    def get(self, request, *args, **kwargs):
        data = {
            'page': request.GET.get('page', '1'),
            'page_size': request.GET.get('page_size', '10')
        }
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='get_roles')
        status_code, data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(data, safe=False, status=status_code)

    # @verify_token_required
    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='create_role')
        status_code, data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(data, safe=False, status=status_code)

    # @verify_token_required
    def put(self, request, *args, **kwargs):
        data = json.loads(request.body)
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='update_role')
        status_code, data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(data, safe=False, status=status_code)

    # @verify_token_required
    def delete(self, request, *args, **kwargs):
        data = json.loads(request.body)
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='delete_role')
        status_code, data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(data, safe=False, status=status_code)


# ---------------------------------------------------------------------------
# Password Policies
# ---------------------------------------------------------------------------

@method_decorator(csrf_exempt, name='dispatch')
class PasswordPoliciesView(View):
    # @verify_token_required
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


@method_decorator(csrf_exempt, name='dispatch')
class PasswordPolicyDetailsView(View):
    # @verify_token_required
    def get(self, request, *args, **kwargs):
        data = {'policy_id': request.GET.get('policy_id', '')}
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='get_policy_details')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

    # @verify_token_required
    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='create_policy')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

    # @verify_token_required
    def put(self, request, *args, **kwargs):
        data = json.loads(request.body)
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='update_policy')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

    # @verify_token_required
    def delete(self, request, *args, **kwargs):
        data = json.loads(request.body)
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='delete_policy')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)


# ---------------------------------------------------------------------------
# Policy Assignments
# ---------------------------------------------------------------------------

@method_decorator(csrf_exempt, name='dispatch')
class PolicyAssignmentsView(View):
    # @verify_token_required
    def get(self, request, *args, **kwargs):
        data = {
            'page': request.GET.get('page', '1'),
            'page_size': request.GET.get('page_size', '10'),
            'sort_by': request.GET.get('sort_by', 'created_at'),
            'sort_order': request.GET.get('sort_order', 'desc')
        }
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='get_assignments')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)


@method_decorator(csrf_exempt, name='dispatch')
class PolicyAssignmentDetailsView(View):
    # @verify_token_required
    def get(self, request, *args, **kwargs):
        data = {'assignment_id': request.GET.get('assignment_id', '')}
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='get_assignment_details')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

    # @verify_token_required
    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='create_assignment')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

    # @verify_token_required
    def put(self, request, *args, **kwargs):
        data = json.loads(request.body)
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='update_assignment')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

    # @verify_token_required
    def delete(self, request, *args, **kwargs):
        data = json.loads(request.body)
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='delete_assignment')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)


# ---------------------------------------------------------------------------
# Breach Databases
# ---------------------------------------------------------------------------

@method_decorator(csrf_exempt, name='dispatch')
class BreachDatabasesView(View):
    # @verify_token_required
    def get(self, request, *args, **kwargs):
        data = {
            'page': request.GET.get('page', '1'),
            'page_size': request.GET.get('page_size', '10'),
            'sort_by': request.GET.get('sort_by', 'created_at'),
            'sort_order': request.GET.get('sort_order', 'desc')
        }
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='get_breach_databases')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)


@method_decorator(csrf_exempt, name='dispatch')
class BreachDatabaseDetailsView(View):
    # @verify_token_required
    def get(self, request, *args, **kwargs):
        data = {'breach_database_id': request.GET.get('breach_database_id', '')}
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='get_breach_database_details')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

    # @verify_token_required
    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='create_breach_database')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

    # @verify_token_required
    def put(self, request, *args, **kwargs):
        data = json.loads(request.body)
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='update_breach_database')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

    # @verify_token_required
    def delete(self, request, *args, **kwargs):
        data = json.loads(request.body)
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='delete_breach_database')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)


# ---------------------------------------------------------------------------
# Breached Password Hashes
# ---------------------------------------------------------------------------

@method_decorator(csrf_exempt, name='dispatch')
class BreachedPasswordHashesView(View):
    # @verify_token_required
    def get(self, request, *args, **kwargs):
        data = {
            'page': request.GET.get('page', '1'),
            'page_size': request.GET.get('page_size', '10'),
            'sort_by': request.GET.get('sort_by', 'occurrence_count'),
            'sort_order': request.GET.get('sort_order', 'desc'),
            'severity': request.GET.get('severity', ''),
            'breach_source_name': request.GET.get('breach_source_name', '')
        }
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='get_breached_hashes')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)


@method_decorator(csrf_exempt, name='dispatch')
class BreachedPasswordHashDetailsView(View):
    # @verify_token_required
    def get(self, request, *args, **kwargs):
        data = {'breach_hash_id': request.GET.get('breach_hash_id', '')}
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='get_breached_hash_details')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)


# ---------------------------------------------------------------------------
# Policy Violations
# ---------------------------------------------------------------------------

@method_decorator(csrf_exempt, name='dispatch')
class PolicyViolationsView(View):
    # @verify_token_required
    def get(self, request, *args, **kwargs):
        data = {
            'page': request.GET.get('page', '1'),
            'page_size': request.GET.get('page_size', '10'),
            'sort_by': request.GET.get('sort_by', 'category'),
            'sort_order': request.GET.get('sort_order', 'asc'),
            'severity': request.GET.get('severity', ''),
            'category': request.GET.get('category', '')
        }
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='get_policy_violations')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)


@method_decorator(csrf_exempt, name='dispatch')
class PolicyViolationDetailsView(View):
    # @verify_token_required
    def get(self, request, *args, **kwargs):
        data = {'violation_id': request.GET.get('violation_id', '')}
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='get_policy_violation_details')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)


# ---------------------------------------------------------------------------
# Audit Logs
# ---------------------------------------------------------------------------

@method_decorator(csrf_exempt, name='dispatch')
class AuditLogsView(View):
    # @verify_token_required
    def get(self, request, *args, **kwargs):
        data = {
            'page': request.GET.get('page', '1'),
            'page_size': request.GET.get('page_size', '10'),
            'sort_by': request.GET.get('sort_by', 'created_at'),
            'sort_order': request.GET.get('sort_order', 'desc'),
            'action': request.GET.get('action', ''),
            'resource_type': request.GET.get('resource_type', ''),
            'user_id': request.GET.get('user_id', '')
        }
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='get_audit_logs')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)


@method_decorator(csrf_exempt, name='dispatch')
class AuditLogDetailsView(View):
    # @verify_token_required
    def get(self, request, *args, **kwargs):
        data = {'audit_log_id': request.GET.get('audit_log_id', '')}
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='get_audit_log_details')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)


# ---------------------------------------------------------------------------
# Template views
# ---------------------------------------------------------------------------

class AdminDashboard(View):
    def get(self, request, *args, **kwargs):
        return render(request, 'admin_dashboard.html')


class Users(View):
    def get(self, request, *args, **kwargs):
        return render(request, 'users.html')


class Roles(View):
    def get(self, request, *args, **kwargs):
        return render(request, 'roles.html')


class PasswordPolicies(View):
    def get(self, request, *args, **kwargs):
        return render(request, 'policies.html')


class Assignment(View):
    def get(self, request, *args, **kwargs):
        return render(request, 'assignment.html')


class Breaches(View):
    def get(self, request, *args, **kwargs):
        return render(request, 'breach.html')

class PolicyViolations(View):
    def get(self, request, *args, **kwargs):
        return render(request, 'policy_violations.html')

class AuditLogs(View):
    def get(self, request, *args, **kwargs):
        return render(request, 'audit_logs.html')