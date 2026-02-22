from rest_framework import status

from accounts.services.login_user_service import LoginUserService
from accounts.services.register_user_service import RegisterUserService
from accounts.services.refresh_token import RefreshTokenService
from admin_panel.services.assignment_create_service import AssignmentCreateService
from admin_panel.services.assignment_delete_service import AssignmentDeleteService
from admin_panel.services.assignment_details_get_service import AssignmentDetailsGetService
from admin_panel.services.assignment_update_service import AssignmentUpdateService
from admin_panel.services.assignments_get_service import AssignmentsGetService
from admin_panel.services.audit_log_details_get_service import AuditLogDetailsGetService
from admin_panel.services.audit_logs_get_service import AuditLogsGetService
from admin_panel.services.breach_database_create_service import BreachDatabaseCreateService
from admin_panel.services.breach_database_delete_service import BreachDatabaseDeleteService
from admin_panel.services.breach_database_details_get_service import BreachDatabaseDetailsGetService
from admin_panel.services.breach_database_update_service import BreachDatabaseUpdateService
from admin_panel.services.breach_databases_get_service import BreachDatabasesGetService
from admin_panel.services.breached_hash_details_get_service import BreachedHashDetailsGetService
from admin_panel.services.breached_hashes_get_service import BreachedHashesGetService
from admin_panel.services.policies_get_service import PoliciesGetService
from admin_panel.services.policy_create_service import PolicyCreateService
from admin_panel.services.policy_delete_service import PolicyDeleteService
from admin_panel.services.policy_details_get_service import PolicyDetailsGetService
from admin_panel.services.policy_update_service import PolicyUpdateService
from admin_panel.services.policy_violation_details_get_service import PolicyViolationDetailsGetService
from admin_panel.services.policy_violations_get_service import PolicyViolationsGetService
from admin_panel.services.role_create_service import RoleCreateService
from admin_panel.services.role_delete_service import RoleDeleteService
from admin_panel.services.role_update_service import RoleUpdateService
from admin_panel.services.roles_get_service import RolesGetService
from admin_panel.services.user_create_service import UserCreateService
from admin_panel.services.user_delete_service import UserDeleteService
from admin_panel.services.user_details_get_service import UserDetailsGetService
from admin_panel.services.user_update_service import UserUpdateService
from admin_panel.services.users_get_service import UsersGetService
from vault.services.generate_password_service import GeneratePasswordService
from vault.services.user_password_create_service import UserPasswordCreateService
from vault.services.user_password_delete_service import UserPasswordDeleteService
from vault.services.user_password_get_service import UserPasswordsGetService
from vault.services.user_password_update_service import UserPasswordUpdateService


class ViewServices:

    def __init__(self, service_name=None):
        self.service_config = {
            # Roles
            'get_roles': self.GetRoles,
            'create_role': self.CreateRole,
            'update_role': self.UpdateRole,
            'delete_role': self.DeleteRole,

            # Auth
            'register_user': self.RegisterUser,
            'login_user': self.LoginUser,
            'refresh_token': self.RefreshToken,

            # Users
            'get_users': self.GetUsers,
            'get_user_details': self.GetUserDetails,
            'create_user': self.CreateUser,
            'update_user': self.UpdateUser,
            'delete_user': self.DeleteUser,

            # Password Policies
            'get_policies': self.GetPolicies,
            'get_policy_details': self.GetPolicyDetails,
            'create_policy': self.CreatePolicy,
            'delete_policy': self.DeletePolicy,
            'update_policy': self.UpdatePolicy,

            # Policy Assignments
            'get_assignments': self.GetAssignments,
            'get_assignment_details': self.GetAssignmentDetails,
            'create_assignment': self.CreateAssignment,
            'update_assignment': self.UpdateAssignment,
            'delete_assignment': self.DeleteAssignment,

            # Breach Databases
            'get_breach_databases': self.GetBreachDatabases,
            'get_breach_database_details': self.GetBreachDatabaseDetails,
            'create_breach_database': self.CreateBreachDatabase,
            'update_breach_database': self.UpdateBreachDatabase,
            'delete_breach_database': self.DeleteBreachDatabase,

            # Breached Password Hashes
            'get_breached_hashes': self.GetBreachedHashes,
            'get_breached_hash_details': self.GetBreachedHashDetails,

            # Audit Logs
            'get_audit_logs': self.GetAuditLogs,
            'get_audit_log_details': self.GetAuditLogDetails,

            # Policy Violations
            'get_policy_violations': self.GetPolicyViolations,
            'get_policy_violation_details': self.GetPolicyViolationDetails,

            # Vault — User Passwords
            'get_user_passwords': self.GetUserPasswords,
            'create_user_password': self.CreateUserPassword,
            'update_user_password': self.UpdateUserPassword,
            'delete_user_password': self.DeleteUserPassword,
            'generate_password': self.GeneratePassword,
        }
        self.service_obj = self.service_config[service_name].get_instance()

    def execute_service(self, *args, **kwargs):
        self.service_obj.execute_service(*args, **kwargs)
        if self.service_obj.status_code is not None:
            status_code = self.service_obj.status_code
        else:
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR if self.service_obj.error else status.HTTP_200_OK
        return status_code, self.service_obj.data

    # --- Roles ---
    class GetRoles:
        @staticmethod
        def get_instance(): return RolesGetService()

    class CreateRole:
        @staticmethod
        def get_instance(): return RoleCreateService()

    class UpdateRole:
        @staticmethod
        def get_instance(): return RoleUpdateService()

    class DeleteRole:
        @staticmethod
        def get_instance(): return RoleDeleteService()

    # --- Auth ---
    class RegisterUser:
        @staticmethod
        def get_instance(): return RegisterUserService()

    class LoginUser:
        @staticmethod
        def get_instance(): return LoginUserService()

    class RefreshToken:
        @staticmethod
        def get_instance(): return RefreshTokenService()

    # --- Users ---
    class GetUsers:
        @staticmethod
        def get_instance(): return UsersGetService()

    class GetUserDetails:
        @staticmethod
        def get_instance(): return UserDetailsGetService()

    class CreateUser:
        @staticmethod
        def get_instance(): return UserCreateService()

    class UpdateUser:
        @staticmethod
        def get_instance(): return UserUpdateService()

    class DeleteUser:
        @staticmethod
        def get_instance(): return UserDeleteService()

    # --- Password Policies ---
    class GetPolicies:
        @staticmethod
        def get_instance(): return PoliciesGetService()

    class GetPolicyDetails:
        @staticmethod
        def get_instance(): return PolicyDetailsGetService()

    class CreatePolicy:
        @staticmethod
        def get_instance(): return PolicyCreateService()

    class DeletePolicy:
        @staticmethod
        def get_instance(): return PolicyDeleteService()

    class UpdatePolicy:
        @staticmethod
        def get_instance(): return PolicyUpdateService()

    # --- Policy Assignments ---
    class GetAssignments:
        @staticmethod
        def get_instance(): return AssignmentsGetService()

    class GetAssignmentDetails:
        @staticmethod
        def get_instance(): return AssignmentDetailsGetService()

    class CreateAssignment:
        @staticmethod
        def get_instance(): return AssignmentCreateService()

    class UpdateAssignment:
        @staticmethod
        def get_instance(): return AssignmentUpdateService()

    class DeleteAssignment:
        @staticmethod
        def get_instance(): return AssignmentDeleteService()

    # --- Breach Databases ---
    class GetBreachDatabases:
        @staticmethod
        def get_instance(): return BreachDatabasesGetService()

    class GetBreachDatabaseDetails:
        @staticmethod
        def get_instance(): return BreachDatabaseDetailsGetService()

    class CreateBreachDatabase:
        @staticmethod
        def get_instance(): return BreachDatabaseCreateService()

    class UpdateBreachDatabase:
        @staticmethod
        def get_instance(): return BreachDatabaseUpdateService()

    class DeleteBreachDatabase:
        @staticmethod
        def get_instance(): return BreachDatabaseDeleteService()

    # --- Breached Password Hashes ---
    class GetBreachedHashes:
        @staticmethod
        def get_instance(): return BreachedHashesGetService()

    class GetBreachedHashDetails:
        @staticmethod
        def get_instance(): return BreachedHashDetailsGetService()

    # --- Policy Violations ---
    class GetPolicyViolations:
        @staticmethod
        def get_instance(): return PolicyViolationsGetService()

    class GetPolicyViolationDetails:
        @staticmethod
        def get_instance(): return PolicyViolationDetailsGetService()

    # --- Audit Logs ---
    class GetAuditLogs:
        @staticmethod
        def get_instance(): return AuditLogsGetService()

    class GetAuditLogDetails:
        @staticmethod
        def get_instance(): return AuditLogDetailsGetService()

    class GetUserPasswords:
        @staticmethod
        def get_instance(): return UserPasswordsGetService()

    class CreateUserPassword:
        @staticmethod
        def get_instance(): return UserPasswordCreateService()

    class UpdateUserPassword:
        @staticmethod
        def get_instance(): return UserPasswordUpdateService()

    class DeleteUserPassword:
        @staticmethod
        def get_instance(): return UserPasswordDeleteService()

    class GeneratePassword:
        @staticmethod
        def get_instance(): return GeneratePasswordService()
