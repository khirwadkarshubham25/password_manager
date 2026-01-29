import re

from password_manager.commons.generic_constants import GenericConstants


class EmailValidator:
    """Validate email field"""

    def __init__(self):
        # RFC 5322 simplified email regex
        self.email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        self.max_length = 254  # RFC 5321

    def validate(self, value):
        """
        Email validation rules:
        - Required field
        - Valid email format (RFC 5322 simplified)
        - Maximum 254 characters
        - No spaces
        """
        if not value:
            return False, GenericConstants.EMAIL_MANDATORY_FIELD_ERROR_MESSAGE

        if not isinstance(value, str):
            return False, GenericConstants.EMAIL_INSTANCE_ERROR_MESSAGE

        value = value.strip().lower()

        if len(value) > self.max_length:
            return False, GenericConstants.EMAIL_MAXIMUM_LENGTH_ERROR_MESSAGE.format(self.max_length)

        if ' ' in value:
            return False, GenericConstants.EMAIL_SPACE_CHARACTER_ERROR_MESSAGE

        if not re.match(self.email_pattern, value):
            return False, GenericConstants.EMAIL_INVALID_FORMAT_ERROR_MESSAGE

        # Additional validation
        local_part, domain = value.split('@')

        if len(local_part) > 64:
            return False, GenericConstants.EMAIL_LOCAL_MAXIMUM_LENGTH_ERROR_MESSAGE

        if '..' in value:
            return False, GenericConstants.EMAIL_CONSECUTIVE_DOT_ERROR_MESSAGE

        if value.startswith('.') or value.endswith('.'):
            return False, GenericConstants.EMAIL_START_END_ERROR_MESSAGE

        return True, ""