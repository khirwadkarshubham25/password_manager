import sys
import traceback

from rest_framework import status

from password_manager.commons.generic_constants import GenericConstants
from vault.models import UserPasswords
from vault.services.service_helper.vault_service_helper import VaultServiceHelper


class UserPasswordDeleteService(VaultServiceHelper):

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        data = kwargs.get('data', {})
        return {
            'user_id': data.get('user_id', ''),
            'user_password_id': data.get('user_password_id', '')
        }

    def get_data(self, *args, **kwargs):
        try:
            params = self.get_request_params(*args, **kwargs)

            is_valid, error = self.is_valid_parameters(
                params,
                required_fields=['user_id', 'user_password_id']
            )
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return error

            try:
                entry = UserPasswords.objects.get(
                    id=params['user_password_id'],
                    user_id=params['user_id']
                )
            except UserPasswords.DoesNotExist:
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {'message': GenericConstants.USER_PASSWORD_NOT_FOUND}

            entry.delete()

            self.set_status_code(status_code=status.HTTP_200_OK)
            return {'message': GenericConstants.PASSWORD_ENTRY_DELETE_SUCCESS_MESSAGE}

        except Exception:
            traceback.print_exc(file=sys.stdout)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE