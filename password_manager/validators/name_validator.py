import re

from password_manager.commons.generic_constants import GenericConstants


class NameValidator:
    """Validate first/last name fields"""

    def __init__(self, min_length=2, max_length=50):
        self.min_length = min_length
        self.max_length = max_length

    def validate(self, value):
        """
        Name validation rules:
        - Required field
        - 2-50 characters
        - Letters, spaces, hyphens, and apostrophes allowed
        - No numbers or special characters
        """
        if not value:
            return False, GenericConstants.NAME_MANDATORY_FIELD_ERROR_MESSAGE

        if not isinstance(value, str):
            return False, GenericConstants.NAME_INSTANCE_ERROR_MESSAGE

        value = value.strip()

        if len(value) < self.min_length:
            return False, GenericConstants.NAME_MINIMUM_LENGTH_ERROR_MESSAGE.format(self.min_length)

        if len(value) > self.max_length:
            return False, GenericConstants.NAME_MAXIMUM_LENGTH_ERROR_MESSAGE.format(self.max_length)

        # Only letters, spaces, hyphens, and apostrophes allowed
        if not re.match(r"^[a-zA-Z\s\-']+$", value):
            return False, GenericConstants.NAME_ALLOWED_CHARACTERS_ERROR_MESSAGE

        # Check for multiple consecutive spaces
        if '  ' in value:
            return False, GenericConstants.NAME_CONSECUTIVE_SPACE_ERROR_MESSAGE

        return True, ""
