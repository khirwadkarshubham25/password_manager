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

class PolicyViolations(View):
    @verify_token_required
    def get(self, request, *args, **kwargs):
        # Extract query parameters for pagination and sorting
        data = {
            'page': request.GET.get('page', '1'),
            'page_size': request.GET.get('page_size', '10'),
            'sort_by': request.GET.get('sort_by', 'created_at'),
            'sort_order': request.GET.get('sort_order', 'desc'),
            'severity': request.GET.get('severity', '')
        }

        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='get_violations')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)


class PolicyViolationDetails(View):
    @verify_token_required
    def get(self, request, *args, **kwargs):
        data = {
            'violation_id': request.GET.get('violation_id', '')
        }

        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='get_violation_details')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

class PolicyAssignments(View):
    @verify_token_required
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


class PolicyAssignmentDetails(View):
    @verify_token_required
    def get(self, request, *args, **kwargs):
        data = {
            'assignment_id': request.GET.get('assignment_id', '')
        }
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='get_assignment_details')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

    @verify_token_required
    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='create_assignment')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

    @verify_token_required
    def put(self, request, *args, **kwargs):
        data = json.loads(request.body)
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='update_assignment')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

    @verify_token_required
    def delete(self, request, *args, **kwargs):
        data = json.loads(request.body)
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='delete_assignment')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

class ManageAssignment(View):
    def get(self, request, *args, **kwargs):
        return render(request=request, template_name='assignment.html')

class BreachDatabases(View):
    @verify_token_required
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

class BreachDatabaseDetails(View):
    @verify_token_required
    def get(self, request, *args, **kwargs):
        data = {
            'breach_database_id': request.GET.get('breach_database_id', '')
        }
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='get_breach_database_details')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

    @verify_token_required
    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='create_breach_database')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

    @verify_token_required
    def put(self, request, *args, **kwargs):
        data = json.loads(request.body)
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='update_breach_database')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

    @verify_token_required
    def delete(self, request, *args, **kwargs):
        data = json.loads(request.body)
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='delete_breach_database')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

class HIBPBreaches(View):
    @verify_token_required
    def get(self, request, *args, **kwargs):
        data = {
            'domain': request.GET.get('domain', ''),  # Optional: filter by domain
        }
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='get_breaches')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)


class HIBPBreachDetails(View):
    @verify_token_required
    def get(self, request, *args, **kwargs):
        """Fetch specific breach details from HIBP API"""
        data = {
            'breach_name': request.GET.get('breach_name', '')
        }
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='get_breach_details')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

class ManageBreaches(View):
    def get(self, request, *args, **kwargs):
        return render(request=request, template_name='breach.html')


class BreachedPasswordHashes(View):
    """List all breached password hashes with pagination and filtering"""

    @verify_token_required
    def get(self, request, *args, **kwargs):
        data = {
            'page': request.GET.get('page', '1'),
            'page_size': request.GET.get('page_size', '10'),
            'sort_by': request.GET.get('sort_by', 'occurrence_count'),
            'sort_order': request.GET.get('sort_order', 'desc'),
            'severity': request.GET.get('severity', ''),
            'breach_source_name': request.GET.get('breach_source_name', ''),
        }
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='get_breached_hashes')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)


class BreachedPasswordHashDetails(View):
    @verify_token_required
    def get(self, request, *args, **kwargs):
        data = {
            'breach_hash_id': request.GET.get('breach_hash_id', '')
        }
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='get_breached_hash_details')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

    @verify_token_required
    def put(self, request, *args, **kwargs):
        data = json.loads(request.body)
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='update_breached_hash_details')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

class SecurityAuditLogs(View):
    @verify_token_required
    def get(self, request, *args, **kwargs):
        data = {
            'page': request.GET.get('page', '1'),
            'page_size': request.GET.get('page_size', '10'),
            'sort_by': request.GET.get('sort_by', 'created_at'),
            'sort_order': request.GET.get('sort_order', 'desc')
        }
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='get_audit_logs')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

class SecurityAuditLogDetails(View):
    @verify_token_required
    def get(self, request, *args, **kwargs):
        data = {
            'log_id': request.GET.get('log_id', '')
        }
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='get_audit_log_details')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

class AnomalyAlerts(View):
    @verify_token_required
    def get(self, request, *args, **kwargs):
        data = {
            'page': request.GET.get('page', '1'),
            'page_size': request.GET.get('page_size', '10'),
            'sort_by': request.GET.get('sort_by', 'created_at'),
            'sort_order': request.GET.get('sort_order', 'desc')
        }
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='get_anomaly_alerts')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)


class AnomalyAlertDetails(View):
    @verify_token_required
    def get(self, request, *args, **kwargs):
        data = {
            'alert_id': request.GET.get('alert_id', '')
        }
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='get_anomaly_alert_details')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

    @verify_token_required
    def put(self, request, *args, **kwargs):
        data = json.loads(request.body)
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='update_anomaly_alert')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

class AnalyzerConfigurations(View):
    @verify_token_required
    def get(self, request, *args, **kwargs):
        data = {
            'page': request.GET.get('page', '1'),
            'page_size': request.GET.get('page_size', '10'),
            'sort_by': request.GET.get('sort_by', 'created_at'),
            'sort_order': request.GET.get('sort_order', 'desc')
        }
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='get_configurations')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

class AnalyzerConfigurationDetails(View):
    @verify_token_required
    def get(self, request, *args, **kwargs):
        data = {
            'config_id': request.GET.get('config_id', '')
        }
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='get_configuration_details')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

    @verify_token_required
    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='create_configuration')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

    @verify_token_required
    def put(self, request, *args, **kwargs):
        data = json.loads(request.body)
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='update_configuration')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

    @verify_token_required
    def delete(self, request, *args, **kwargs):
        data = json.loads(request.body)
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='delete_configuration')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

class DictionaryWordlists(View):
    @verify_token_required
    def get(self, request, *args, **kwargs):
        data = {
            'page': request.GET.get('page', '1'),
            'page_size': request.GET.get('page_size', '10'),
            'sort_by': request.GET.get('sort_by', 'created_at'),
            'sort_order': request.GET.get('sort_order', 'desc')
        }
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='get_wordlists')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)


class DictionaryWordlistDetails(View):
    @verify_token_required
    def get(self, request, *args, **kwargs):
        data = {
            'wordlist_id': request.GET.get('wordlist_id', '')
        }
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='get_wordlist_details')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

    @verify_token_required
    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='create_wordlist')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

    @verify_token_required
    def put(self, request, *args, **kwargs):
        data = json.loads(request.body)
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='update_wordlist')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

    @verify_token_required
    def delete(self, request, *args, **kwargs):
        data = json.loads(request.body)
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='delete_wordlist')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)


class KeyboardPatterns(View):
    @verify_token_required
    def get(self, request, *args, **kwargs):
        data = {
            'page': request.GET.get('page', '1'),
            'page_size': request.GET.get('page_size', '10'),
            'sort_by': request.GET.get('sort_by', 'created_at'),
            'sort_order': request.GET.get('sort_order', 'desc')
        }
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='get_patterns')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)


class KeyboardPatternDetails(View):
    @verify_token_required
    def get(self, request, *args, **kwargs):
        data = {
            'pattern_id': request.GET.get('pattern_id', '')
        }
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='get_pattern_details')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

    @verify_token_required
    def post(self, request, *args, **kwargs):
        data = json.loads(request.body)
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='create_pattern')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

    @verify_token_required
    def put(self, request, *args, **kwargs):
        data = json.loads(request.body)
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='update_pattern')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)

    @verify_token_required
    def delete(self, request, *args, **kwargs):
        data = json.loads(request.body)
        kwargs.update({'data': data})
        service_obj = ViewServices(service_name='delete_pattern')
        status_code, response_data = service_obj.execute_service(*args, **kwargs)
        return JsonResponse(response_data, safe=False, status=status_code)
