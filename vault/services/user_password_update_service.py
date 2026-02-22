import sys
import traceback

from rest_framework import status

from vault.models import UserPasswords, UserPasswordHistory
from vault.services.breached_password_hash_create_service import BreachedPasswordHashCreateService
from vault.services.password_policy_violation_create_service import PasswordPolicyViolationCreateService
from vault.services.service_helper.vault_service_helper import VaultServiceHelper
from password_manager.commons.generic_constants import GenericConstants
from password_manager.services.crypto_service import CryptoService


class UserPasswordUpdateService(VaultServiceHelper):

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        data = kwargs.get('data', {})
        return {
            'user_id':          data.get('user_id', ''),
            'user_password_id': data.get('user_password_id', ''),
            'platform':         data.get('platform', '').strip(),
            'url':              data.get('url', '').strip(),
            'email':            data.get('email', '').strip(),
            'password':         data.get('password', '')
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
                entry = UserPasswords.objects.select_related('user').get(
                    id=params['user_password_id'],
                    user_id=params['user_id']
                )
            except UserPasswords.DoesNotExist:
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {'message': GenericConstants.PASSWORD_ENTRY_NOT_FOUND_ERROR_MESSAGE}

            new_password = params['password']
            policy_result = None
            breach_result = None

            if new_password:
                # ---------------------------------------------------------------
                # Check policy violations
                # ---------------------------------------------------------------
                policy_result = PasswordPolicyViolationCreateService().get_data(data={
                    'user_id':          params['user_id'],
                    'password':         new_password,
                    'user_password_id': params['user_password_id']
                })

                # ---------------------------------------------------------------
                # Check breach databases
                # ---------------------------------------------------------------
                breach_result = BreachedPasswordHashCreateService().get_data(data={
                    'user_id':  params['user_id'],
                    'password': new_password
                })

                # ---------------------------------------------------------------
                # Save old password to history then encrypt new one
                # ---------------------------------------------------------------
                UserPasswordHistory.objects.create(
                    user_password=entry,
                    encrypted_password=entry.password
                )
                entry.password = CryptoService.encrypt_password(
                    new_password,
                    entry.user.password
                )

            # Update other fields only if provided
            if params['platform']:
                entry.platform = params['platform']
            if params['url']:
                entry.url = params['url']
            if params['email']:
                entry.email = params['email']

            entry.save()

            # ---------------------------------------------------------------
            # Build response — always 200, warnings included if any
            # ---------------------------------------------------------------
            self.set_status_code(status_code=status.HTTP_200_OK)

            response = {
                'message': GenericConstants.PASSWORD_ENTRY_CREATED_SUCCESS_MESSAGE,
                'data': {
                    'user_password_id': entry.id,
                    'platform':         entry.platform,
                    'url':              entry.url,
                    'email':            entry.email,
                    'updated_at':       entry.updated_at.isoformat()
                }
            }

            if policy_result and policy_result.get('violated'):
                response['policy_warning'] = {
                    'policy_id':       policy_result.get('policy_id'),
                    'policy_name':     policy_result.get('policy_name'),
                    'violation_count': policy_result.get('violation_count'),
                    'violations':      policy_result.get('violations')
                }

            if breach_result and breach_result.get('breached'):
                response['breach_warning'] = {
                    'checked_databases': breach_result.get('checked_databases'),
                    'breached_in':       breach_result.get('breached_in')
                }

            return response

        except Exception:
            traceback.print_exc(file=sys.stdout)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE