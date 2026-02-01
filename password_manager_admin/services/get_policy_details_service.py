from rest_framework import status

from password_manager.commons.generic_constants import GenericConstants
from password_manager_admin.services.service_helper.password_admin_manager_service_helper import \
    PasswordAdminManagerServiceHelper
from password_manager_admin.models import PasswordPolicy


class GetPolicyDetailsService(PasswordAdminManagerServiceHelper):
    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        policy_id = kwargs.get('data', {}).get('policy_id', '').strip()

        return {
            'policy_id': policy_id,
        }

    def get_data(self, *args, **kwargs):
        try:
            # Get request parameters
            params = self.get_request_params(*args, **kwargs)

            policy_id = params.get('policy_id')

            # Validate policy_id
            if not policy_id:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'Policy ID is required'}

            try:
                policy_id = int(policy_id)
            except ValueError:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'Invalid policy ID'}

            # Build query
            policy = PasswordPolicy.objects.get(id=policy_id)

            if not policy:
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {'message': f'Policy with ID {policy_id} not found'}

            # Build response data
            policy_data = {
                'policy_id': policy.id,
                'policy_name': policy.policy_name,
                'description': policy.description,
                'min_length': policy.min_length,
                'max_length': policy.max_length,
                'require_uppercase': policy.require_uppercase,
                'require_lowercase': policy.require_lowercase,
                'require_digits': policy.require_digits,
                'require_special_chars': policy.require_special_chars,
                'min_complexity_types': policy.min_complexity_types,
                'reject_dictionary_words': policy.reject_dictionary_words,
                'max_age_days': policy.max_age_days,
                'min_rotation_days': policy.min_rotation_days,
                'history_count': policy.history_count,
                'exclude_username': policy.exclude_username,
                'exclude_name': policy.exclude_name,
                'exclude_email': policy.exclude_email,
                'special_chars_allowed': policy.special_chars_allowed,
                'special_chars_required': policy.special_chars_required,
                'created_at': policy.created_at.isoformat(),
                'is_active': True if policy.status == 1 else False
            }

            return {
                'data': policy_data
            }

        except Exception as e:
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE