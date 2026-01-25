from rest_framework import status

from password_vault_manager.services.create_password_service import CreatePasswordService
from password_vault_manager.services.delete_password_service import DeletePasswordService
from password_vault_manager.services.get_passwords_service import GetPasswordsService
from password_vault_manager.services.login_user_service import LoginUserService
from password_vault_manager.services.register_user_service import RegisterUserService
from password_vault_manager.services.update_password_service import UpdatePasswordService


class ViewServices:

    def __init__(self, service_name=None):
        self.service_config = {
            'register_user': self.RegisterUser,
            'login_user': self.Login,
            'get_passwords': self.GetPasswords,
            'create_password': self.CreatePassword,
            'update_password': self.UpdatePassword,
            'delete_password': self.DeletePassword
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

    class RegisterUser:
        @staticmethod
        def get_instance():
            return RegisterUserService()

    class Login:
        @staticmethod
        def get_instance():
            return LoginUserService()

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