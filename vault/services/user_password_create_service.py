import sys
import traceback

from rest_framework import status

from accounts.models import Users
from vault.models import UserPasswords
from vault.services.breached_password_hash_create_service import BreachedPasswordHashCreateService
from vault.services.password_policy_violation_create_service import PasswordPolicyViolationCreateService
from vault.services.service_helper.vault_service_helper import VaultServiceHelper
from password_manager.commons.generic_constants import GenericConstants
from password_manager.services.crypto_service import CryptoService


class UserPasswordCreateService(VaultServiceHelper):

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        data = kwargs.get('data', {})
        return {
            'user_id':  data.get('user_id', ''),
            'platform': data.get('platform', '').strip(),
            'url':      data.get('url', '').strip(),
            'email':    data.get('email', '').strip(),
            'password': data.get('password', '')
        }

    def get_data(self, *args, **kwargs):
        try:
            params = self.get_request_params(*args, **kwargs)

            is_valid, error = self.is_valid_parameters(
                params,
                required_fields=['user_id', 'platform', 'url', 'email', 'password']
            )
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return error

            try:
                user = Users.objects.get(id=params['user_id'])
            except Users.DoesNotExist:
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {'message': GenericConstants.USER_NOT_FOUND}

            if UserPasswords.objects.filter(
                user_id=params['user_id'],
                platform=params['platform'],
                email=params['email']
            ).exists():
                self.set_status_code(status_code=status.HTTP_409_CONFLICT)
                return {'message': GenericConstants.PASSWORD_ENTRY_ALREADY_EXISTS_ERROR_MESSAGE}

            # ---------------------------------------------------------------
            # Check policy violations
            # ---------------------------------------------------------------
            policy_result = PasswordPolicyViolationCreateService().get_data(data={
                'user_id':  params['user_id'],
                'password': params['password']
            })

            # ---------------------------------------------------------------
            # Check breach databases
            # ---------------------------------------------------------------
            breach_result = BreachedPasswordHashCreateService().get_data(data={
                'user_id':  params['user_id'],
                'password': params['password']
            })

            # ---------------------------------------------------------------
            # Create the entry regardless of violations or breach
            # ---------------------------------------------------------------
            encrypted_password = CryptoService.encrypt_password(
                params['password'],
                user.password
            )

            entry = UserPasswords.objects.create(
                user_id=params['user_id'],
                platform=params['platform'],
                url=params['url'],
                email=params['email'],
                password=encrypted_password
            )

            response = {
                'message': GenericConstants.PASSWORD_ENTRY_CREATED_SUCCESS_MESSAGE,
                'data': {
                    'user_password_id': entry.id,
                    'platform':         entry.platform,
                    'url':              entry.url,
                    'email':            entry.email,
                    'created_at':       entry.created_at.isoformat()
                }
            }

            if policy_result.get('violated'):
                response['policy_warning'] = {
                    'policy_id':       policy_result.get('policy_id'),
                    'policy_name':     policy_result.get('policy_name'),
                    'violation_count': policy_result.get('violation_count'),
                    'violations':      policy_result.get('violations')
                }

            if breach_result.get('breached'):
                response['breach_warning'] = {
                    'checked_databases': breach_result.get('checked_databases'),
                    'breached_in':       breach_result.get('breached_in')
                }

            return response

        except Exception:
            traceback.print_exc(file=sys.stdout)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE