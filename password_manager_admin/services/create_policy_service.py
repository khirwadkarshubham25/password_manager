from rest_framework import status

from password_manager.commons.generic_constants import GenericConstants
from password_manager.validators.policy_validator import PolicyValidator
from password_manager_admin.services.service_helper.password_admin_manager_service_helper import \
    PasswordAdminManagerServiceHelper
from password_manager_admin.models import PasswordPolicy
from rest_framework import status

from password_manager.commons.generic_constants import GenericConstants
from password_manager.validators.policy_validator import PolicyValidator
from password_manager_admin.models import PasswordPolicy
from password_manager_admin.services.service_helper.password_admin_manager_service_helper import \
    PasswordAdminManagerServiceHelper


class CreatePolicyService(PasswordAdminManagerServiceHelper):
    """Service for creating new password policies"""

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        policy_name = kwargs.get('data', {}).get('policy_name', '').strip()
        description = kwargs.get('data', {}).get('description', '').strip()
        min_length = kwargs.get('data', {}).get('min_length', '8')
        max_length = kwargs.get('data', {}).get('max_length', '128')
        require_uppercase = kwargs.get('data', {}).get('require_uppercase', True)
        require_lowercase = kwargs.get('data', {}).get('require_lowercase', True)
        require_digits = kwargs.get('data', {}).get('require_digits', True)
        require_special_chars = kwargs.get('data', {}).get('require_special_chars', True)
        min_complexity_types = kwargs.get('data', {}).get('min_complexity_types', '3')
        reject_dictionary_words = kwargs.get('data', {}).get('reject_dictionary_words', True)
        max_age_days = kwargs.get('data', {}).get('max_age_days', '90')
        min_rotation_days = kwargs.get('data', {}).get('min_rotation_days', '1')
        history_count = kwargs.get('data', {}).get('history_count', '5')
        exclude_username = kwargs.get('data', {}).get('exclude_username', True)
        exclude_name = kwargs.get('data', {}).get('exclude_name', True)
        exclude_email = kwargs.get('data', {}).get('exclude_email', True)
        special_chars_allowed = kwargs.get('data', {}).get('special_chars_allowed', "!@#$%^&*-_=+[]{}|;:,.<>?")
        special_chars_required = kwargs.get('data', {}).get('special_chars_required', '')
        is_active = kwargs.get('data', {}).get('is_active', None)

        return {
            'policy_name': policy_name,
            'description': description,
            'min_length': min_length,
            'max_length': max_length,
            'require_uppercase': require_uppercase,
            'require_lowercase': require_lowercase,
            'require_digits': require_digits,
            'require_special_chars': require_special_chars,
            'min_complexity_types': min_complexity_types,
            'reject_dictionary_words': reject_dictionary_words,
            'max_age_days': max_age_days,
            'min_rotation_days': min_rotation_days,
            'history_count': history_count,
            'exclude_username': exclude_username,
            'exclude_name': exclude_name,
            'exclude_email': exclude_email,
            'special_chars_allowed': special_chars_allowed,
            'special_chars_required': special_chars_required,
            'is_active': is_active
        }

    def get_data(self, *args, **kwargs):
        """Create new password policy"""
        try:
            # Get request parameters
            params = self.get_request_params(*args, **kwargs)

            # Validate parameters
            is_valid, message = PolicyValidator.validate_policy_params(params)
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': message}

            if PasswordPolicy.objects.filter(policy_name=params.get('policy_name')).exists():
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': f"Policy with name '{params.get('policy_name')}' already exists"}

            policy = PasswordPolicy.objects.create(
                policy_name=params.get('policy_name'),
                description=params.get('description', ''),
                min_length=int(params.get('min_length', 8)),
                max_length=int(params.get('max_length', 128)),
                require_uppercase=params.get('require_uppercase', True),
                require_lowercase=params.get('require_lowercase', True),
                require_digits=params.get('require_digits', True),
                require_special_chars=params.get('require_special_chars', True),
                min_complexity_types=int(params.get('min_complexity_types', 3)),
                reject_dictionary_words=params.get('reject_dictionary_words', True),
                max_age_days=int(params.get('max_age_days', 90)),
                min_rotation_days=int(params.get('min_rotation_days', 1)),
                history_count=int(params.get('history_count', 5)),
                exclude_username=params.get('exclude_username', True),
                exclude_name=params.get('exclude_name', True),
                exclude_email=params.get('exclude_email', True),
                special_chars_allowed=params.get('special_chars_allowed', "!@#$%^&*-_=+[]{}|;:,.<>?"),
                special_chars_required=params.get('special_chars_required', ''),
                status=True if params.get('is_active', None) is not None else False
            )

            return {
                'message': 'Policy created successfully',
            }

        except Exception as e:
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE