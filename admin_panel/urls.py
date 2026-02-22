from django.urls import path

from admin_panel import views

urlpatterns = [
    # --- Users ---
    path('api/users', views.UsersView.as_view(), name='api-users'),
    path('api/user-details', views.UserDetailsView.as_view(), name='api-user-details'),

    # --- Roles ---
    path('api/roles', views.RolesView.as_view(), name='api-roles'),

    # --- Password Policies ---
    path('api/policies', views.PasswordPoliciesView.as_view(), name='api-policies'),
    path('api/policy-details', views.PasswordPolicyDetailsView.as_view(), name='api-policy-details'),

    # --- Policy Assignments ---
    path('api/assignments', views.PolicyAssignmentsView.as_view(), name='api-assignments'),
    path('api/assignment-details', views.PolicyAssignmentDetailsView.as_view(), name='api-assignment-details'),

    # --- Breach Databases ---
    path('api/breach-databases', views.BreachDatabasesView.as_view(), name='api-breach-databases'),
    path('api/breach-database-details', views.BreachDatabaseDetailsView.as_view(), name='api-breach-database-details'),

    # --- Breached Password Hashes ---
    path('api/breached-hashes', views.BreachedPasswordHashesView.as_view(), name='api-breached-hashes'),
    path('api/breached-hash-details', views.BreachedPasswordHashDetailsView.as_view(), name='api-breached-hash-details'),

    # --- Policy Violations ---
    path('api/policy-violations', views.PolicyViolationsView.as_view(), name='api-policy-violations'),
    path('api/policy-violation-details', views.PolicyViolationDetailsView.as_view(), name='api-policy-violation-details'),

    # --- Audit Logs ---
    path('api/audit-logs', views.AuditLogsView.as_view(), name='api-audit-logs'),
    path('api/audit-log-details', views.AuditLogDetailsView.as_view(), name='api-audit-log-details'),

    # --- Template views ---
    path('admin-dashboard', views.AdminDashboard.as_view(), name='admin-dashboard'),
    path('users', views.Users.as_view(), name='users'),
    path('roles', views.Roles.as_view(), name='roles'),
    path('policies', views.PasswordPolicies.as_view(), name='policies'),
    path('assignments', views.Assignment.as_view(), name='assignments'),
    path('breaches', views.Breaches.as_view(), name='breaches'),
    path('policy-violations', views.PolicyViolations.as_view(), name='policy-violations'),
    path('audit-logs', views.AuditLogs.as_view(), name='audit-logs'),
]