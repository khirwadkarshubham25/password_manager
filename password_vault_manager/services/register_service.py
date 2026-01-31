from password_manager.commons.commons import Commons
from password_manager.commons.generic_constants import GenericConstants
from password_vault_manager.models import Users
from password_manager.services.crypto_service import CryptoService
from rest_framework import status

from password_vault_manager.services.service_helper.password_vault_manager_service_helper import \
    PasswordVaultManagerServiceHelper


class RegisterService(PasswordVaultManagerServiceHelper):
    """Service for user registration"""

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        """Extract and clean request parameters"""
        username = kwargs.get('data').get('username', '').strip()
        email = kwargs.get('data').get('email', '').strip().lower()
        first_name = kwargs.get('data').get('first_name', '').strip()
        last_name = kwargs.get('data').get('last_name', '').strip()
        master_password = kwargs.get('data').get('password', '')

        return {
            'username': username,
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'password': master_password
        }

    def get_data(self, *args, **kwargs):
        """Process registration and create user"""
        # Get request parameters
        params = self.get_request_params(*args, **kwargs)

        # Validate all parameters (is_sign_up=True means validate username and names)
        is_valid, message = self.is_valid_parameters(params, is_sign_up=True)

        if not is_valid:
            return message

        # Extract parameters from validated params
        username = params.get('username')
        email = params.get('email')
        first_name = params.get('first_name')
        last_name = params.get('last_name')
        master_password = params.get('password')

        # Check if username already exists
        if Users.objects.filter(username=username).exists():
            self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
            return {"message": GenericConstants.USER_EMAIL_EXISTS_ERROR_MESSAGE.format(params["email"])}

        # Check if email already exists
        if Users.objects.filter(email=email).exists():
            self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
            return {"message": GenericConstants.USERNAME_EXISTS_ERROR_MESSAGE.format(params["username"])}


        try:
            # Hash master password using CryptoService
            hashed_master_password = CryptoService.hash_master_password(master_password)

            # Create new user with hashed master password
            user = Users.objects.create(
                username=username,
                email=email,
                first_name=first_name,
                last_name=last_name,
                password=hashed_master_password
            )

            # Create payload for API token
            api_payload = {
                'user_id': user.id,
                'first_name': user.first_name,
                'last_name': user.last_name,
            }

            # Generate both API and refresh tokens
            tokens = Commons.generate_tokens(api_payload)

            self.set_status_code(status_code = status.HTTP_201_CREATED)
            return {
                'message': GenericConstants.REGISTRATION_SUCCESS_MESSAGE,
                'user_id': user.id,
                'first_name': user.first_name,
                'last_name': user.last_name,
                **tokens
            }

        except Exception as e:
            self.set_status_code(status_code = status.HTTP_500_INTERNAL_SERVER_ERROR)
            return {
                'message': GenericConstants.REGISTRATION_ERROR_MESSAGE
            }