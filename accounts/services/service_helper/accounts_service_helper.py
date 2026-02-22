from datetime import datetime, timedelta, timezone
from abc import ABC

import jwt
from django.conf import settings

from password_manager.commons.generic_constants import GenericConstants
from password_manager.services.base_service import BaseService


class AccountsServiceHelper(BaseService, ABC):
    def __init__(self):
        super().__init__()

    def set_status_code(self, *args, **kwargs):
        self.status_code = kwargs.get('status_code')

    @staticmethod
    def get_expiry(token_type):
        exp = None
        if token_type == GenericConstants.API_TOKEN_TYPE:
            exp = datetime.now(timezone.utc) + timedelta(hours=GenericConstants.API_TOKEN_EXPIRY_HOURS)
        elif token_type == GenericConstants.REFRESH_TOKEN_TYPE:
            exp = datetime.now(timezone.utc) + timedelta(days=GenericConstants.REFRESH_TOKEN_EXPIRY_DAYS)

        return exp

    def generate_jwt_token(self, token_type, payload):
        expiry = self.get_expiry(token_type)
        payload["exp"] = expiry
        secret_key = settings.SECRET_KEY
        token = jwt.encode(payload, secret_key, algorithm='HS256')

        return token, expiry

    def generate_tokens(self, payload):
        api_token, api_token_expiry = self.generate_jwt_token(
            GenericConstants.API_TOKEN_TYPE,
            payload
        )

        refresh_token, refresh_token_expiry = self.generate_jwt_token(
            GenericConstants.REFRESH_TOKEN_TYPE,
            payload
        )

        return api_token, refresh_token
