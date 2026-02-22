from abc import ABC

from accounts.models import Users
from admin_panel.models import PasswordPolicy
from password_manager.commons.generic_constants import GenericConstants
from password_manager.services.base_service import BaseService


class AdminPanelServiceHelper(BaseService, ABC):
    def __init__(self):
        super().__init__()

    def set_status_code(self, *args, **kwargs):
        self.status_code = kwargs.get('status_code')

    @staticmethod
    def is_valid_parameters(params, required_fields=None):
        if required_fields is None:
            required_fields = []

        missing_fields = []
        for field in required_fields:
            value = params.get(field)
            if value is None or (isinstance(value, str) and not value.strip()):
                missing_fields.append(field)

        if missing_fields:
            return False, {"message": f"Missing or empty required fields: {', '.join(missing_fields)}"}

        return True, None

    @staticmethod
    def validate_pagination_params(page, page_size):
        if page < GenericConstants.MIN_PAGE:
            return False, f"Page number must be greater than or equal to {GenericConstants.MIN_PAGE}."

        if page_size < GenericConstants.MIN_PAGE_SIZE or page_size > GenericConstants.MAX_PAGE_SIZE:
            return False, f"Page size must be between {GenericConstants.MIN_PAGE_SIZE} and {GenericConstants.MAX_PAGE_SIZE}."

        return True, None

    @staticmethod
    def validate_sort_params(allowed_sort_fields, sort_by, sort_order):
        if sort_by not in allowed_sort_fields:
            return False, f"Invalid sort_by field '{sort_by}'. Allowed fields: {', '.join(allowed_sort_fields)}."

        if sort_order not in GenericConstants.VALID_SORT_ORDERS:
            return False, f"Invalid sort_order '{sort_order}'. Allowed values: {', '.join(GenericConstants.VALID_SORT_ORDERS)}."

        return True, None

    @staticmethod
    def validate_policy_params(params):
        policy_name = params.get('policy_name')
        if not policy_name:
            return False, 'Policy name is required.'

        min_length = int(params.get('min_length', 8))
        max_length = int(params.get('max_length', 128))
        if min_length < 4:
            return False, 'Minimum length must be at least 4.'
        if max_length > 256:
            return False, 'Maximum length cannot exceed 256.'
        if min_length > max_length:
            return False, 'Minimum length cannot be greater than maximum length.'

        min_complexity_types = int(params.get('min_complexity_types', 3))
        if min_complexity_types not in [2, 3, 4]:
            return False, 'min_complexity_types must be 2, 3, or 4.'

        max_age_days = int(params.get('max_age_days', 90))
        if max_age_days < 0:
            return False, 'max_age_days cannot be negative.'

        min_rotation_days = int(params.get('min_rotation_days', 1))
        if min_rotation_days < 0:
            return False, 'min_rotation_days cannot be negative.'

        history_count = int(params.get('history_count', 5))
        if history_count < 0:
            return False, 'history_count cannot be negative.'

        min_entropy_score = float(params.get('min_entropy_score', 40.0))
        if min_entropy_score < 0:
            return False, 'min_entropy_score cannot be negative.'

        return True, None

    @staticmethod
    def validate_ids(policy_id, user_id, admin_user_id):
        try:
            return True, int(policy_id), int(user_id), int(admin_user_id), None
        except (ValueError, TypeError):
            return False, None, None, None, 'Invalid ID format. IDs must be numeric'

    @staticmethod
    def validate_foreign_keys(policy_id, user_id, admin_user_id):
        if not PasswordPolicy.objects.filter(id=policy_id).exists():
            return False, GenericConstants.POLICY_NOT_FOUND_MESSAGE

        if not Users.objects.filter(id=user_id).exists():
            return False, GenericConstants.USER_NOT_FOUND

        if not Users.objects.filter(id=admin_user_id).exists():
            return False, GenericConstants.USER_NOT_FOUND

        return True, None

    @staticmethod
    def validate_assignment_id(assignment_id):
        if not assignment_id:
            return False, None, 'Assignment ID is required'
        try:
            return True, int(assignment_id), None
        except (ValueError, TypeError):
            return False, None, 'Invalid Assignment ID format. Must be numeric'

    @staticmethod
    def validate_authentication_method(auth_method):
        valid_methods = ['NONE', 'API_KEY', 'OAUTH', 'BASIC']
        if auth_method not in valid_methods:
            return False, f"Invalid authentication method. Must be one of: {', '.join(valid_methods)}"
        return True, None

    @staticmethod
    def validate_total_hashes(total_hashes):
        try:
            total_hashes_int = int(total_hashes)
            if total_hashes_int < 0:
                return False, None, 'Total hashes must be a positive number'
            return True, total_hashes_int, None
        except (ValueError, TypeError):
            return False, None, 'Total hashes must be a valid number'
