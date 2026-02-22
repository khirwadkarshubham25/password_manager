import sys
import traceback

from rest_framework import status

from admin_panel.models import PasswordPolicy
from admin_panel.services.service_helper.admin_panel_service_helper import AdminPanelServiceHelper
from password_manager.commons.commons import Commons
from password_manager.commons.generic_constants import GenericConstants


class PolicyCreateService(AdminPanelServiceHelper):

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        data = kwargs.get('data', {})
        return {
            'policy_name': data.get('policy_name', '').strip(),
            'description': data.get('description', '').strip(),
            'min_length': data.get('min_length', 8),
            'max_length': data.get('max_length', 128),
            'require_uppercase': data.get('require_uppercase', True),
            'require_lowercase': data.get('require_lowercase', True),
            'require_digits': data.get('require_digits', True),
            'require_special_chars': data.get('require_special_chars', True),
            'min_complexity_types': data.get('min_complexity_types', 3),
            'reject_dictionary_words': data.get('reject_dictionary_words', True),
            'max_age_days': data.get('max_age_days', 90),
            'min_rotation_days': data.get('min_rotation_days', 1),
            'history_count': data.get('history_count', 5),
            'min_entropy_score': data.get('min_entropy_score', 40.0),
            'exclude_username': data.get('exclude_username', True),
            'exclude_name': data.get('exclude_name', True),
            'exclude_email': data.get('exclude_email', True),
            'special_chars_allowed': data.get('special_chars_allowed', '!@#$%^&*-_=+[]{}|;:,.<>?'),
            'special_chars_required': data.get('special_chars_required', ''),
            'status': data.get('status', 1),
            'user_id': data.get('admin_user_id')
        }

    def get_data(self, *args, **kwargs):
        try:
            params = self.get_request_params(*args, **kwargs)

            is_valid, message = self.validate_policy_params(params)
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': message}

            if PasswordPolicy.objects.filter(policy_name=params.get('policy_name')).exists():
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': GenericConstants.POLICY_ALREADY_EXISTS_MESSAGE}

            policy = PasswordPolicy.objects.create(
                policy_name=params.get('policy_name'),
                description=params.get('description'),
                min_length=int(params.get('min_length')),
                max_length=int(params.get('max_length')),
                require_uppercase=params.get('require_uppercase'),
                require_lowercase=params.get('require_lowercase'),
                require_digits=params.get('require_digits'),
                require_special_chars=params.get('require_special_chars'),
                min_complexity_types=int(params.get('min_complexity_types')),
                reject_dictionary_words=params.get('reject_dictionary_words'),
                max_age_days=int(params.get('max_age_days')),
                min_rotation_days=int(params.get('min_rotation_days')),
                history_count=int(params.get('history_count')),
                min_entropy_score=float(params.get('min_entropy_score')),
                exclude_username=params.get('exclude_username'),
                exclude_name=params.get('exclude_name'),
                exclude_email=params.get('exclude_email'),
                special_chars_allowed=params.get('special_chars_allowed'),
                special_chars_required=params.get('special_chars_required'),
                status=params.get('status')
            )

            Commons.create_audit_log(
                user_id=params.get('user_id'),
                action='create',
                resource_type='password_policy',
                resource_id=policy.id,
                new_values={'policy_name': policy.policy_name, 'status': policy.status}
            )

            return {'message': GenericConstants.POLICY_CREATED_SUCCESSFUL_MESSAGE}

        except Exception:
            traceback.print_exc(file=sys.stdout)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE