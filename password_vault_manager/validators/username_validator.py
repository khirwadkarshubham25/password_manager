import re

from password_manager.commons.generic_constants import GenericConstants


class UsernameValidator:
    """Validate username field"""

    def __init__(self, min_length=3, max_length=30):
        self.min_length = min_length
        self.max_length = max_length

    def validate(self, value):
        """
        Username validation rules:
        - Required field
        - 3-30 characters
        - Alphanumeric and underscore only
        - Start with letter
        - No consecutive underscores
        """
        if not value:
            return False, GenericConstants.USERNAME_MANDATORY_FIELD_ERROR_MESSAGE

        if not isinstance(value, str):
            return False, GenericConstants.USERNAME_INSTANCE_ERROR_MESSAGE

        value = value.strip()

        if len(value) < self.min_length:
            return False, GenericConstants.USERNAME_MINIMUM_LENGTH_ERROR_MESSAGE.format(self.min_length)

        if len(value) > self.max_length:
            return False, GenericConstants.USERNAME_MAXIMUM_LENGTH_ERROR_MESSAGE.format(self.max_length)

        # Check if starts with letter
        if not value[0].isalpha():
            return False, GenericConstants.USERNAME_START_ERROR_MESSAGE

        # Check allowed characters (alphanumeric and underscore)
        if not re.match(r'^[a-zA-Z0-9_]+$', value):
            return False, GenericConstants.USERNAME_START_ERROR_MESSAGE

        # Check consecutive underscores
        if '__' in value:
            return False, GenericConstants.USERNAME_CONSECUTIVE_UNDERSCORE_ERROR_MESSAGE

        return True, ""