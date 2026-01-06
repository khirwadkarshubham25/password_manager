import re

from password_manager.commons.generic_constants import GenericConstants


class PasswordValidator:
    """Validate password field with strength requirements"""

    def __init__(self,
                 min_length=8,
                 max_length=128,
                 require_uppercase=True,
                 require_lowercase=True,
                 require_digit=True,
                 require_special=True):
        self.min_length = min_length
        self.max_length = max_length
        self.require_uppercase = require_uppercase
        self.require_lowercase = require_lowercase
        self.require_digit = require_digit
        self.require_special = require_special

    def validate(self, value):
        """
        Password validation rules:
        - Required field
        - 8-128 characters
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one digit
        - At least one special character
        - Not a common weak password
        """
        if not value:
            return False, GenericConstants.PASSWORD_MANDATORY_FIELD_ERROR_MESSAGE

        if not isinstance(value, str):
            return False, GenericConstants.PASSWORD_INSTANCE_ERROR_MESSAGE

        if len(value) < self.min_length:
            return False, GenericConstants.PASSWORD_MINIMUM_LENGTH_ERROR_MESSAGE.format(self.min_length)

        if len(value) > self.max_length:
            return False, GenericConstants.PASSWORD_MAXIMUM_LENGTH_ERROR_MESSAGE.format(self.max_length)

        if self.require_uppercase and not re.search(r'[A-Z]', value):
            return False, GenericConstants.PASSWORD_CONTAIN_UPPER_CASE_LETTER_ERROR_MESSAGE

        if self.require_lowercase and not re.search(r'[a-z]', value):
            return False, GenericConstants.PASSWORD_CONTAIN_LOWER_CASE_LETTER_ERROR_MESSAGE

        if self.require_digit and not re.search(r'\d', value):
            return False, GenericConstants.PASSWORD_CONTAIN_DIGIT_ERROR_MESSAGE

        if self.require_special and not re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', value):
            return False, GenericConstants.PASSWORD_CONTAIN_SPECIAL_CHARACTER_ERROR_MESSAGE

        if value.lower() in GenericConstants.WEAK_PASSWORDS:
            return False, GenericConstants.PASSWORD_COMMON_ERROR_MESSAGE

        return True, ""