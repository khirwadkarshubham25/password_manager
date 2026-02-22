from abc import ABC

from password_manager.commons.generic_constants import GenericConstants
from password_manager.services.base_service import BaseService


class VaultServiceHelper(BaseService, ABC):

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