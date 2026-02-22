class GenericConstants:
    ERROR_MESSAGE = {
        "message": "Internal server error!"
    }

    ROLE_ALREADY_EXISTS_MESSAGE = "Role already exists"
    ROLE_CREATED_SUCCESSFUL_MESSAGE = "Role successfully created"
    ROLE_NOT_FOUND_MESSAGE = "Role not found"
    ROLE_UPDATE_SUCCESSFUL_MESSAGE = "Role updated successfully"
    ROLE_DELETE_SUCCESSFUL_MESSAGE = "Role deleted successfully"

    REGISTRATION_ERROR_MESSAGE = "Registration Failed"
    REGISTRATION_SUCCESS_MESSAGE = "User created successfully."

    USER_EMAIL_EXISTS_ERROR_MESSAGE = "User email:{} already exists"
    USERNAME_EXISTS_ERROR_MESSAGE = "Username {} already exists"

    CREATE_PASSWORD_ERROR_MESSAGE = "Password creation error"
    CREATE_PASSWORD_SUCCESS_MESSAGE = "Password added successfully"
    UPDATE_PASSWORD_ERROR_MESSAGE = "Password update error"
    UPDATE_PASSWORD_SUCCESS_MESSAGE = "Password updated successfully"
    DELETE_PASSWORD_ERROR_MESSAGE = "Password deletion error"
    DELETE_PASSWORD_SUCCESS_MESSAGE = "Password deleted successfully"

    USERNAME_MANDATORY_FIELD_ERROR_MESSAGE = "Username is required"
    USERNAME_INSTANCE_ERROR_MESSAGE = "Username must be string"
    USERNAME_MINIMUM_LENGTH_ERROR_MESSAGE = "Username must be at least {} characters"
    USERNAME_MAXIMUM_LENGTH_ERROR_MESSAGE = "Username must not exceed {} characters"
    USERNAME_START_ERROR_MESSAGE = "Username must start with a letter"
    USERNAME_ALLOWED_CHARACTERS_ERROR_MESSAGE = "Username can only contain letters, numbers, underscores"
    USERNAME_CONSECUTIVE_UNDERSCORE_ERROR_MESSAGE = "Username cannot contain consecutive underscores"

    NAME_MANDATORY_FIELD_ERROR_MESSAGE = "First/Last Name is required"
    NAME_INSTANCE_ERROR_MESSAGE = "First/Last Name must be string"
    NAME_MINIMUM_LENGTH_ERROR_MESSAGE = "First/Last Name must be at least {} characters"
    NAME_MAXIMUM_LENGTH_ERROR_MESSAGE = "First/Last Name must not exceed {} characters"
    NAME_ALLOWED_CHARACTERS_ERROR_MESSAGE = "First/Last Name can only contain letters, spaces, hyphens, and apostrophes"
    NAME_CONSECUTIVE_SPACE_ERROR_MESSAGE = "First/Last Name cannot contain multiple consecutive spaces"

    EMAIL_MANDATORY_FIELD_ERROR_MESSAGE = "Email is required"
    EMAIL_INSTANCE_ERROR_MESSAGE = "Email must be string"
    EMAIL_MAXIMUM_LENGTH_ERROR_MESSAGE = "Email must not exceed {} characters"
    EMAIL_SPACE_CHARACTER_ERROR_MESSAGE = "Email cannot contain spaces"
    EMAIL_INVALID_FORMAT_ERROR_MESSAGE = "Email invalid format"
    EMAIL_LOCAL_MAXIMUM_LENGTH_ERROR_MESSAGE = "Email local part (before @) is too long"
    EMAIL_CONSECUTIVE_DOT_ERROR_MESSAGE = "Email cannot contain consecutive dots"
    EMAIL_START_END_ERROR_MESSAGE = "Email cannot start or end with a dot"

    PASSWORD_MANDATORY_FIELD_ERROR_MESSAGE = "Password is required"
    PASSWORD_INSTANCE_ERROR_MESSAGE = "Password must be string"
    PASSWORD_MINIMUM_LENGTH_ERROR_MESSAGE = "Password must be at least {} characters"
    PASSWORD_MAXIMUM_LENGTH_ERROR_MESSAGE = "Password must not exceed {} characters"
    PASSWORD_CONTAIN_UPPER_CASE_LETTER_ERROR_MESSAGE = "Password must contain at least one uppercase letter"
    PASSWORD_CONTAIN_LOWER_CASE_LETTER_ERROR_MESSAGE = "Password must contain at least one lowercase letter"
    PASSWORD_CONTAIN_DIGIT_ERROR_MESSAGE = "Password must contain at least one digit"
    PASSWORD_CONTAIN_SPECIAL_CHARACTER_ERROR_MESSAGE = "Password must contain at least one special character"
    PASSWORD_COMMON_ERROR_MESSAGE = "Password is too common. Please choose a stronger password"

    WEAK_PASSWORDS = {
        'password', '12345678', 'qwerty', 'abc123', 'password123',
        '111111', '123123', '000000', 'admin', 'letmein'
    }

    USER_NOT_FOUND = "User not found"
    USER_PASSWORD_NOT_FOUND = "User Password not found"
    INVALID_EMAIL_PASSWORD = "Invalid email/password"
    INVALID_USER_ID = "Invalid User ID"
    INVALID_USER_PASSWORD_ID = "Invalid User Password ID"
    USER_DELETE_SUCCESSFUL_MESSAGE = "User deleted successfully!"
    USER_UPDATE_SUCCESSFUL_MESSAGE = "User update successfully!"

    API_TOKEN_TYPE = 'api_token'
    REFRESH_TOKEN_TYPE = 'refresh_token'

    API_TOKEN_EXPIRY_HOURS = 24
    REFRESH_TOKEN_EXPIRY_DAYS = 7

    LOGIN_SUCCESS_MESSAGE = "Successfully logged in"
    LOGIN_FAILED_MESSAGE = "Login failed"

    DECRYPTED_PASSWORD_ERROR_MESSAGE = "Error in decrypting password"

    INVALID_REQUESTS = "Invalid requests"

    TOKEN_EXTRACTION_ERROR_MESSAGE = "Error in extracting token"

    PLATFORM_MANDATORY_FIELD_ERROR_MESSAGE = "Platform is required"
    URL_MANDATORY_FIELD_ERROR_MESSAGE = "URL is required"
    PASSWORD_ENTRY_ALREADY_EXISTS_ERROR_MESSAGE = "Password entry already exists"
    PASSWORD_ENTRY_CREATED_SUCCESS_MESSAGE = "New password details are successfully created"
    PASSWORD_ENTRY_DELETE_SUCCESS_MESSAGE = "Password details are successfully deleted"
    PASSWORD_ENTRY_CREATED_ERROR_MESSAGE = "Error in creating new password"
    PASSWORD_ENTRY_NOT_FOUND_ERROR_MESSAGE = "Password entry not found"

    REFRESH_TOKEN_MANDATORY_ERROR_MESSAGE = "Refresh Token is required"
    TOKEN_USER_ID_NOT_FOUND_ERROR_MESSAGE = "User ID Not Found"

    TOKEN_REFRESH_SUCCESS_MESSAGE = "Successfully refresh token"
    TOKEN_REFRESH_ERROR_MESSAGE = "Error in refreshing token"

    INVALID_ADMIN_USER_ID = "Invalid Admin User ID"

    AUDIT_LOG_CREATE_SUCCESSFUL_MESSAGE = "Audit log created successfully!"
    AUDIT_LOG_NOT_FOUND_MESSAGE = "Audit log not found!"

    MIN_PAGE = 1
    MIN_PAGE_SIZE = 1
    MAX_PAGE_SIZE = 100
    VALID_SORT_ORDERS = ['asc', 'desc']

    POLICY_ALREADY_EXISTS_MESSAGE = "Policy with this name already exists!"
    POLICY_CREATED_SUCCESSFUL_MESSAGE = "Policy created successfully!"
    POLICY_UPDATE_SUCCESSFUL_MESSAGE = "Policy updated successfully!"
    POLICY_NOT_FOUND_MESSAGE = "Policy not found!"
    POLICY_DELETE_SUCCESSFUL_MESSAGE = "Policy deleted successfully!"
    POLICY_HAS_ASSIGNMENTS_MESSAGE = "Cannot delete policy that has existing assignments."

    ASSIGNMENT_ALREADY_EXISTS_MESSAGE = "An active policy assignment already exists for this user."
    ASSIGNMENT_CREATED_SUCCESSFUL_MESSAGE = "Policy assignment created successfully!"
    ASSIGNMENT_NOT_FOUND_MESSAGE = "Policy assignment not found!"
    ASSIGNMENT_DELETE_SUCCESSFUL_MESSAGE = "Policy assignment deleted successfully!"
    ASSIGNMENT_UPDATE_SUCCESSFUL_MESSAGE = "Policy assignment updated successfully!"

    BREACH_DATABASE_ALREADY_EXISTS_MESSAGE = "Breach database with this source name already exists!"
    BREACH_DATABASE_CREATED_SUCCESSFUL_MESSAGE = "Breach database created successfully!"
    BREACH_DATABASE_NOT_FOUND_MESSAGE = "Breach database not found!"
    BREACH_DATABASE_DELETE_SUCCESSFUL_MESSAGE = "Breach database deleted successfully!"
    BREACH_DATABASE_UPDATE_SUCCESSFUL_MESSAGE = "Breach database updated successfully!"

    BREACHED_HASH_NOT_FOUND_MESSAGE = "Breached password hash not found!"

    DEFAULT_POLICY = {
        'min_length': 8,
        'max_length': 128,
        'require_uppercase': True,
        'require_lowercase': True,
        'require_digits': True,
        'require_special_chars': True,
        'special_chars_allowed': "!@#$%^&*-_=+[]{}|;:,.<>?",
        'special_chars_required': '',
        'min_complexity_types': 3,
        'history_count': 0,
        'exclude_username': False,
        'exclude_name': False,
        'exclude_email': True,
        'min_entropy_score': 0.0,
    }

    POLICY_VIOLATION_NOT_FOUND_ERROR_MESSAGE = "Password Policy Violation not found!"