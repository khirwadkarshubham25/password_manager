from rest_framework import status

from password_manager.commons.generic_constants import GenericConstants
from password_manager_admin.services.service_helper.password_admin_manager_service_helper import \
    PasswordAdminManagerServiceHelper
from password_manager_admin.models import PasswordPolicy


class UpdatePolicyService(PasswordAdminManagerServiceHelper):
    """Service for updating existing password policies"""

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        """Extract and clean request parameters"""
        policy_id = kwargs.get('data', {}).get('policy_id', '').strip()
        policy_name = kwargs.get('data', {}).get('policy_name', '').strip()
        description = kwargs.get('data', {}).get('description', '').strip()
        min_length = kwargs.get('data', {}).get('min_length', '')
        max_length = kwargs.get('data', {}).get('max_length', '')
        require_uppercase = kwargs.get('data', {}).get('require_uppercase')
        require_lowercase = kwargs.get('data', {}).get('require_lowercase')
        require_digits = kwargs.get('data', {}).get('require_digits')
        require_special_chars = kwargs.get('data', {}).get('require_special_chars')
        min_complexity_types = kwargs.get('data', {}).get('min_complexity_types', '')
        reject_dictionary_words = kwargs.get('data', {}).get('reject_dictionary_words')
        max_age_days = kwargs.get('data', {}).get('max_age_days', '')
        min_rotation_days = kwargs.get('data', {}).get('min_rotation_days', '')
        history_count = kwargs.get('data', {}).get('history_count', '')
        exclude_username = kwargs.get('data', {}).get('exclude_username')
        exclude_name = kwargs.get('data', {}).get('exclude_name')
        exclude_email = kwargs.get('data', {}).get('exclude_email')
        special_chars_allowed = kwargs.get('data', {}).get('special_chars_allowed', '').strip()
        special_chars_required = kwargs.get('data', {}).get('special_chars_required', '').strip()
        is_active = kwargs.get('data', {}).get('is_active', None)

        return {
            'policy_id': policy_id,
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
        """Update existing password policy"""
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

            # Get policy
            try:
                policy = PasswordPolicy.objects.get(id=policy_id)
            except PasswordPolicy.DoesNotExist:
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {'message': f'Policy with ID {policy_id} not found'}

            # Update policy_name if provided and different
            if params.get('policy_name') and params.get('policy_name') != policy.policy_name:
                if PasswordPolicy.objects.filter(policy_name=params.get('policy_name')).exclude(id=policy_id).exists():
                    self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                    return {'message': f"Policy with name '{params.get('policy_name')}' already exists"}
                policy.policy_name = params.get('policy_name')

            # Update description if provided
            if params.get('description') is not None:
                policy.description = params.get('description')

            # Update numeric fields if provided
            if params.get('min_length'):
                try:
                    min_length = int(params.get('min_length'))
                    if min_length < 4 or min_length > 256:
                        self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                        return {'message': 'Min length must be between 4 and 256'}
                    policy.min_length = min_length
                except ValueError:
                    self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                    return {'message': 'Invalid min_length value'}

            if params.get('max_length'):
                try:
                    max_length = int(params.get('max_length'))
                    if max_length < 4 or max_length > 256:
                        self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                        return {'message': 'Max length must be between 4 and 256'}
                    policy.max_length = max_length
                except ValueError:
                    self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                    return {'message': 'Invalid max_length value'}

            # Validate min_length <= max_length
            if policy.min_length > policy.max_length:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'Min length cannot be greater than max length'}

            # Update boolean fields if provided
            if params.get('require_uppercase') is not None:
                policy.require_uppercase = params.get('require_uppercase')

            if params.get('require_lowercase') is not None:
                policy.require_lowercase = params.get('require_lowercase')

            if params.get('require_digits') is not None:
                policy.require_digits = params.get('require_digits')

            if params.get('require_special_chars') is not None:
                policy.require_special_chars = params.get('require_special_chars')

            if params.get('reject_dictionary_words') is not None:
                policy.reject_dictionary_words = params.get('reject_dictionary_words')

            if params.get('exclude_username') is not None:
                policy.exclude_username = params.get('exclude_username')

            if params.get('exclude_name') is not None:
                policy.exclude_name = params.get('exclude_name')

            if params.get('exclude_email') is not None:
                policy.exclude_email = params.get('exclude_email')

            # Update complexity types if provided
            if params.get('min_complexity_types'):
                try:
                    min_complexity = int(params.get('min_complexity_types'))
                    if min_complexity < 2 or min_complexity > 4:
                        self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                        return {'message': 'Min complexity types must be between 2 and 4'}
                    policy.min_complexity_types = min_complexity
                except ValueError:
                    self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                    return {'message': 'Invalid min_complexity_types value'}

            # Update age and rotation days if provided
            if params.get('max_age_days'):
                try:
                    max_age = int(params.get('max_age_days'))
                    if max_age < 0:
                        self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                        return {'message': 'Max age days cannot be negative'}
                    policy.max_age_days = max_age
                except ValueError:
                    self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                    return {'message': 'Invalid max_age_days value'}

            if params.get('min_rotation_days'):
                try:
                    min_rotation = int(params.get('min_rotation_days'))
                    if min_rotation < 0:
                        self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                        return {'message': 'Min rotation days cannot be negative'}
                    policy.min_rotation_days = min_rotation
                except ValueError:
                    self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                    return {'message': 'Invalid min_rotation_days value'}

            if params.get('history_count'):
                try:
                    history = int(params.get('history_count'))
                    if history < 0:
                        self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                        return {'message': 'History count cannot be negative'}
                    policy.history_count = history
                except ValueError:
                    self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                    return {'message': 'Invalid history_count value'}

            # Update special characters if provided
            if params.get('special_chars_allowed'):
                policy.special_chars_allowed = params.get('special_chars_allowed')

            if params.get('special_chars_required') is not None:
                policy.special_chars_required = params.get('special_chars_required')

            print(params.get('is_active'))
            if params.get('is_active') is not None:
                policy.status = 1 if params.get('is_active') else 0

            # Save the updated policy
            policy.save()
            return {
                'message': 'Policy updated successfully'
            }

        except Exception as e:
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE