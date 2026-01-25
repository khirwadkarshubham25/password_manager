class GenericConstants:
    ERROR_MESSAGE = {
        "message": "Internal server error!"
    }

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

    API_TOKEN_TYPE = 'api_token'
    REFRESH_TOKEN_TYPE = 'refresh_token'

    API_TOKEN_TIME = 20
    REFRESH_TOKEN_TIME = 60

    LOGIN_SUCCESS_MESSAGE = "Successfully logged in"
    LOGIN_FAILED_MESSAGE = "Login failed"

    DECRYPTED_PASSWORD_ERROR_MESSAGE = "Error in decrypting password"

    INVALID_REQUESTS = "Invalid requests"

    TOKEN_EXTRACTION_ERROR_MESSAGE = "Error in extracting token"

    PLATFORM_MANDATORY_FIELD_ERROR_MESSAGE = "Platform is required"
    URL_MANDATORY_FIELD_ERROR_MESSAGE = "URL is required"
    PASSWORD_ENTRY_ALREADY_EXISTS_ERROR_MESSAGE = "Password entry already exists"
    PASSWORD_ENTRY_CREATED_SUCCESS_MESSAGE = "New password details are successfully created"
    PASSWORD_ENTRY_CREATED_ERROR_MESSAGE = "Error in creating new password"

    REFRESH_TOKEN_MANDATORY_ERROR_MESSAGE = "Refresh Token is required"
    TOKEN_USER_ID_NOT_FOUND_ERROR_MESSAGE = "User ID Not Found"

    TOKEN_REFRESH_SUCCESS_MESSAGE = "Successfully refresh token"
    TOKEN_REFRESH_ERROR_MESSAGE = "Error in refreshing token"