from rest_framework import status

from password_vault_manager.services.create_master_password_service import CreateMasterPasswordService
from password_vault_manager.services.login_service import LoginService


class ViewServices:

    def __init__(self, service_name=None):
        self.service_config = {
            'create_master_password': self.CreateMasterPassword,
            'login': self.Login,
            'create_password': self.CreatePassword,
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

    class CreateMasterPassword:
        @staticmethod
        def get_instance():
            return CreateMasterPasswordService()

    class Login:
        @staticmethod
        def get_instance():
            return LoginService()

    class CreatePassword:
        @staticmethod
        def get_instance():
            return CreatePasswordService()