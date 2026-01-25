from abc import ABC
from datetime import datetime, timedelta, timezone

import jwt
from rest_framework.status import HTTP_400_BAD_REQUEST

from password_manager import settings
from password_manager.commons.generic_constants import GenericConstants
from password_manager.services.base_service import BaseService
from password_vault_manager.validators.email_validator import EmailValidator
from password_vault_manager.validators.name_validator import NameValidator
from password_vault_manager.validators.password_validator import PasswordValidator
from password_vault_manager.validators.username_validator import UsernameValidator


class PasswordVaultManagerServiceHelper(BaseService, ABC):
    def __init__(self):
        super().__init__()

    def set_status_code(self, *args, **kwargs):
        self.status_code = kwargs['status_code']

    def is_valid_parameters(self, params, is_sign_up=True):
        is_valid, message = UsernameValidator().validate(params.get('username'))

        if not is_valid:
            self.set_status_code(status_code=HTTP_400_BAD_REQUEST)
            return is_valid, {"message": message}

        if is_sign_up:
            is_valid, message = NameValidator().validate(params.get('first_name'))

            if not is_valid:
                self.set_status_code(status_code=HTTP_400_BAD_REQUEST)
                return is_valid, {"message": message}

            is_valid, message = NameValidator().validate(params.get('last_name'))

            if not is_valid:
                self.set_status_code(status_code=HTTP_400_BAD_REQUEST)
                return is_valid, {"message": message}

            is_valid, message = EmailValidator().validate(params.get('email'))

            if not is_valid:
                self.set_status_code(status_code=HTTP_400_BAD_REQUEST)
                return is_valid, {"message": message}

        is_valid, message = PasswordValidator().validate(params.get('password'))

        if not is_valid:
            self.set_status_code(status_code=HTTP_400_BAD_REQUEST)
            return is_valid, {"message": message}

        return True, ""

    @staticmethod
    def get_expiry(token_type):
        exp = None
        if token_type == GenericConstants.API_TOKEN_TYPE:
            exp = datetime.now(timezone.utc) + timedelta(minutes=20)
        elif token_type == GenericConstants.REFRESH_TOKEN_TYPE:
            exp = datetime.now(timezone.utc) + timedelta(minutes=60)

        return exp

    def generate_jwt_token(self, token_type, payload):
        """
        Generate a JWT token

        Args:
            token_type: Type of token ('api_token' or 'refresh_token')
            user_id: User ID to include in token payload

        Returns:
            Tuple of (token, expiry)
        """
        # Get expiry time based on token type
        expiry = self.get_expiry(token_type)

        # Encode JWT token using secret key from settings
        secret_key = settings.SECRET_KEY
        token = jwt.encode(payload, secret_key, algorithm='HS256')

        return token, expiry

    def generate_tokens(self, payload):
        """
        Generate both API token and refresh token

        Args:
            payload: User Payload

        Returns:
            Dictionary with api_token, api_token_expiry, refresh_token, refresh_token_expiry
        """
        # Generate API token
        api_token, api_token_expiry = self.generate_jwt_token(
            GenericConstants.API_TOKEN_TYPE,
            payload
        )

        # Generate refresh token
        refresh_token, refresh_token_expiry = self.generate_jwt_token(
            GenericConstants.REFRESH_TOKEN_TYPE,
            payload
        )

        return {
            'api_token': api_token,
            'api_token_expiry': api_token_expiry.isoformat(),
            'refresh_token': refresh_token,
            'refresh_token_expiry': refresh_token_expiry.isoformat()
        }