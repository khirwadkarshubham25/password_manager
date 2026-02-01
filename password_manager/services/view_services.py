from rest_framework import status

from password_manager_admin.services.create_assignment_service import CreateAssignmentService
from password_manager_admin.services.create_breach_database_service import CreateBreachDatabaseService
from password_manager_admin.services.create_policy_service import CreatePolicyService
from password_manager_admin.services.create_user_service import CreateUserService
from password_manager_admin.services.delete_assignment_service import DeleteAssignmentService
from password_manager_admin.services.delete_breach_database_service import DeleteBreachDatabaseService
from password_manager_admin.services.delete_policy_service import DeletePolicyService
from password_manager_admin.services.delete_user_service import DeleteUserService
from password_manager_admin.services.get_assignment_details_service import GetAssignmentDetailsService
from password_manager_admin.services.get_assignment_service import GetAssignmentsService
from password_manager_admin.services.get_breach_database_details_service import GetBreachDatabaseDetailsService
from password_manager_admin.services.get_breach_database_service import GetBreachDatabasesService
from password_manager_admin.services.get_policies_service import GetPoliciesService
from password_manager_admin.services.get_policy_details_service import GetPolicyDetailsService
from password_manager_admin.services.get_users_service import GetUsersService
from password_manager_admin.services.get_violation_details_service import GetViolationDetailsService
from password_manager_admin.services.get_violations_service import GetViolationsService
from password_manager_admin.services.login_admin_user_service import LoginAdminUserService
from password_manager_admin.services.register_admin_user_service import RegisterAdminUserService
from password_manager_admin.services.update_assignment_service import UpdateAssignmentService
from password_manager_admin.services.update_breach_database_service import UpdateBreachDatabaseService
from password_manager_admin.services.update_policy_service import UpdatePolicyService
from password_manager_admin.services.update_user_service import UpdateUserService
from password_vault_manager.services.create_password_service import CreatePasswordService
from password_vault_manager.services.delete_password_service import DeletePasswordService
from password_vault_manager.services.get_passwords_service import GetPasswordsService
from password_vault_manager.services.login_service import LoginService
from password_manager.services.refresh_token import RefreshTokenService
from password_vault_manager.services.register_service import RegisterService
from password_vault_manager.services.update_password_service import UpdatePasswordService


class ViewServices:

    def __init__(self, service_name=None):
        self.service_config = {
            # Admin Views Mapping
            'register_admin_user': self.RegisterAdminUser,
            'login_admin_user': self.LoginAdminUser,

            'get_users': self.GetUsers,
            'create_users': self.CreateUser,
            'update_users': self.UpdateUser,
            'delete_users': self.DeleteUser,

            'get_policies': self.GetPolicies,
            'get_policy_details': self.GetPolicyDetails,
            'create_policy': self.CreatePolicy,
            'update_policy': self.UpdatePolicy,
            'delete_policy': self.DeletePolicy,

            'get_violations': self.GetViolations,
            'get_violation_details': self.GetViolationDetails,

            'get_assignments': self.GetAssignments,
            'get_assignment_details': self.GetAssignmentDetails,
            'create_assignment': self.CreateAssignment,
            'update_assignment': self.UpdateAssignment,
            'delete_assignment': self.DeleteAssignment,

            'get_breach_databases': self.GetBreachDatabases,
            'get_breach_database_details': self.GetBreachDatabaseDetails,
            'create_breach_database': self.CreateBreachDatabase,
            'update_breach_database': self.UpdateBreachDatabase,
            'delete_breach_database': self.DeleteBreachDatabase,

            'get_breached_hashes': self.GetBreachedHashes,
            'get_breached_hash_details': self.GetBreachedHashDetails,

            'get_audit_logs': self.GetAuditLogs,
            'get_audit_log_details': self.GetAuditLogDetails,

            'get_anomaly_alerts': self.GetAnomalyAlerts,
            'get_anomaly_alert_details': self.GetAnomalyAlertDetails,
            'update_anomaly_alert': self.UpdateAnomalyAlert,

            'get_configurations': self.GetConfigurations,
            'get_configuration_details': self.GetConfigurationDetails,
            'create_configuration': self.CreateConfiguration,
            'update_configuration': self.UpdateConfiguration,
            'delete_configuration': self.DeleteConfiguration,

            'get_wordlists': self.GetWordlists,
            'get_wordlist_details': self.GetWordlistDetails,
            'create_wordlist': self.CreateWordlist,
            'update_wordlist': self.UpdateWordlist,
            'delete_wordlist': self.DeleteWordlist,

            'get_patterns': self.GetPatterns,
            'get_pattern_details': self.GetPatternDetails,
            'create_pattern': self.CreatePattern,
            'update_pattern': self.UpdatePattern,
            'delete_pattern': self.DeletePattern,

            # Vault Views Mapping
            'register_user': self.RegisterUser,
            'login_user': self.Login,
            'get_passwords': self.GetPasswords,
            'create_password': self.CreatePassword,
            'update_password': self.UpdatePassword,
            'delete_password': self.DeletePassword,

            # Common Views
            'refresh_token': self.RefreshToken,
        }
        self.service_obj = self.service_config[service_name].get_instance()

    def execute_service(self, *args, **kwargs):
        self.service_obj.execute_service(*args, **kwargs)
        if self.service_obj.status_code is not None:
            status_code = self.service_obj.status_code
        else:
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR if self.service_obj.error else status.HTTP_200_OK
        data = self.service_obj.data

        return status_code, data

    # Admin Mapping
    class RegisterAdminUser:
        @staticmethod
        def get_instance():
            return RegisterAdminUserService()

    class LoginAdminUser:
        @staticmethod
        def get_instance():
            return LoginAdminUserService()

    class GetUsers:
        @staticmethod
        def get_instance():
            return GetUsersService()

    class CreateUser:
        @staticmethod
        def get_instance():
            return CreateUserService()

    class UpdateUser:
        @staticmethod
        def get_instance():
            return UpdateUserService()

    class DeleteUser:
        @staticmethod
        def get_instance():
            return DeleteUserService()

    class GetPolicies:
        @staticmethod
        def get_instance():
            return GetPoliciesService()

    class GetPolicyDetails:
        @staticmethod
        def get_instance():
            return GetPolicyDetailsService()

    class CreatePolicy:
        @staticmethod
        def get_instance():
            return CreatePolicyService()

    class UpdatePolicy:
        @staticmethod
        def get_instance():
            return UpdatePolicyService()

    class DeletePolicy:
        @staticmethod
        def get_instance():
            return DeletePolicyService()

    class GetViolations:
        @staticmethod
        def get_instance():
            return GetViolationsService()

    class GetViolationDetails:
        @staticmethod
        def get_instance():
            return GetViolationDetailsService()

    class GetAssignments:
        @staticmethod
        def get_instance():
            return GetAssignmentsService()

    class GetAssignmentDetails:
        @staticmethod
        def get_instance():
            return GetAssignmentDetailsService()

    class CreateAssignment:
        @staticmethod
        def get_instance():
            return CreateAssignmentService()

    class UpdateAssignment:
        @staticmethod
        def get_instance():
            return UpdateAssignmentService()

    class DeleteAssignment:
        @staticmethod
        def get_instance():
            return DeleteAssignmentService()

    class GetBreachDatabases:
        @staticmethod
        def get_instance():
            return GetBreachDatabasesService()

    class GetBreachDatabaseDetails:
        @staticmethod
        def get_instance():
            return GetBreachDatabaseDetailsService()

    class CreateBreachDatabase:
        @staticmethod
        def get_instance():
            return CreateBreachDatabaseService()

    class UpdateBreachDatabase:
        @staticmethod
        def get_instance():
            return UpdateBreachDatabaseService()

    class DeleteBreachDatabase:
        @staticmethod
        def get_instance():
            return DeleteBreachDatabaseService()

    class GetBreachedHashes:
        @staticmethod
        def get_instance():
            return GetBreachedHashesService()

    class GetBreachedHashDetails:
        @staticmethod
        def get_instance():
            return GetBreachedHashDetailsService()

    class GetAuditLogs:
        @staticmethod
        def get_instance():
            return GetAuditLogsService()

    class GetAuditLogDetails:
        @staticmethod
        def get_instance():
            return GetAuditLogDetailsService()

    class GetAnomalyAlerts:
        @staticmethod
        def get_instance():
            return GetAnomalyAlertsService()

    class GetAnomalyAlertDetails:
        @staticmethod
        def get_instance():
            return GetAnomalyAlertDetailsService()

    class UpdateAnomalyAlert:
        @staticmethod
        def get_instance():
            return UpdateAnomalyAlertService()

    class GetConfigurations:
        @staticmethod
        def get_instance():
            return GetConfigurationsService()

    class GetConfigurationDetails:
        @staticmethod
        def get_instance():
            return GetConfigurationDetailsService()

    class CreateConfiguration:
        @staticmethod
        def get_instance():
            return CreateConfigurationService()

    class UpdateConfiguration:
        @staticmethod
        def get_instance():
            return UpdateConfigurationService()

    class DeleteConfiguration:
        @staticmethod
        def get_instance():
            return DeleteConfigurationService()

    class GetWordlists:
        @staticmethod
        def get_instance():
            return GetWordlistsService()

    class GetWordlistDetails:
        @staticmethod
        def get_instance():
            return GetWordlistDetailsService()

    class CreateWordlist:
        @staticmethod
        def get_instance():
            return CreateWordlistService()

    class UpdateWordlist:
        @staticmethod
        def get_instance():
            return UpdateWordlistService()

    class DeleteWordlist:
        @staticmethod
        def get_instance():
            return DeleteWordlistService()

    class GetPatterns:
        @staticmethod
        def get_instance():
            return GetPatternsService()

    class GetPatternDetails:
        @staticmethod
        def get_instance():
            return GetPatternDetailsService()

    class CreatePattern:
        @staticmethod
        def get_instance():
            return CreatePatternService()

    class UpdatePattern:
        @staticmethod
        def get_instance():
            return UpdatePatternService()

    class DeletePattern:
        @staticmethod
        def get_instance():
            return DeletePatternService()

    # Vault Mapping
    class RegisterUser:
        @staticmethod
        def get_instance():
            return RegisterService()

    class Login:
        @staticmethod
        def get_instance():
            return LoginService()

    class GetPasswords:
        @staticmethod
        def get_instance():
            return GetPasswordsService()

    class CreatePassword:
        @staticmethod
        def get_instance():
            return CreatePasswordService()

    class UpdatePassword:
        @staticmethod
        def get_instance():
            return UpdatePasswordService()

    class DeletePassword:
        @staticmethod
        def get_instance():
            return DeletePasswordService()

    # Common Mapping
    class RefreshToken:
        @staticmethod
        def get_instance():
            return RefreshTokenService()