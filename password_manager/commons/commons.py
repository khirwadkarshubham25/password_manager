from datetime import datetime, timedelta, timezone

import jwt

from password_manager import settings
from password_manager.commons.generic_constants import GenericConstants


class Commons:
    def __init__(self):
        pass

    @staticmethod
    def get_expiry(token_type):
        exp = None
        if token_type == GenericConstants.API_TOKEN_TYPE:
            exp = datetime.now(timezone.utc) + timedelta(minutes=GenericConstants.API_TOKEN_TIME)
        elif token_type == GenericConstants.REFRESH_TOKEN_TYPE:
            exp = datetime.now(timezone.utc) + timedelta(minutes=GenericConstants.REFRESH_TOKEN_TIME)

        return exp

    @staticmethod
    def generate_jwt_token(token_type, payload):
        expiry = Commons.get_expiry(token_type)
        secret_key = settings.SECRET_KEY
        token = jwt.encode(payload, secret_key, algorithm='HS256')

        return token, expiry

    @staticmethod
    def generate_tokens(payload):
        api_token, api_token_expiry = Commons.generate_jwt_token(
            GenericConstants.API_TOKEN_TYPE,
            payload
        )

        refresh_token, refresh_token_expiry = Commons.generate_jwt_token(
            GenericConstants.REFRESH_TOKEN_TYPE,
            payload
        )

        return {
            'api_token': api_token,
            'api_token_expiry': api_token_expiry.isoformat(),
            'refresh_token': refresh_token,
            'refresh_token_expiry': refresh_token_expiry.isoformat()
        }