import sys
import traceback

from rest_framework import status

from admin_panel.models import PasswordPolicy
from admin_panel.services.service_helper.admin_panel_service_helper import AdminPanelServiceHelper
from password_manager.commons.generic_constants import GenericConstants


class PolicyDetailsGetService(AdminPanelServiceHelper):

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        data = kwargs.get('data', {})
        return {
            'policy_id': data.get('policy_id', '').strip()
        }

    def get_data(self, *args, **kwargs):
        try:
            params = self.get_request_params(*args, **kwargs)
            policy_id = params.get('policy_id')

            if not policy_id:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'Policy ID is required'}

            try:
                policy_id = int(policy_id)
            except (ValueError, TypeError):
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'Invalid policy ID'}

            try:
                policy = PasswordPolicy.objects.get(id=policy_id)
            except PasswordPolicy.DoesNotExist:
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {'message': GenericConstants.POLICY_NOT_FOUND_MESSAGE}

            return {
                'data': {
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
                    'min_entropy_score': policy.min_entropy_score,
                    'exclude_username': policy.exclude_username,
                    'exclude_name': policy.exclude_name,
                    'exclude_email': policy.exclude_email,
                    'special_chars_allowed': policy.special_chars_allowed,
                    'special_chars_required': policy.special_chars_required,
                    'status': policy.status,
                    'is_active': policy.status == 1,
                    'created_at': policy.created_at.isoformat(),
                    'updated_at': policy.updated_at.isoformat()
                }
            }

        except Exception:
            traceback.print_exc(file=sys.stdout)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE