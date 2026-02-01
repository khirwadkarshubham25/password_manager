import jwt
from functools import wraps
from django.http import JsonResponse
from rest_framework import status

from password_manager import settings
from password_manager.commons.generic_constants import GenericConstants


def verify_token_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if len(args) < 2:
            return JsonResponse(
                {'message': GenericConstants.INVALID_REQUESTS},
                status_code=status.HTTP_400_BAD_REQUEST
            )

        self_or_view = args[0]
        request = args[1]

        # Verify token
        is_valid, result = TokenVerifier.verify_and_get_user_id(request)

        if not is_valid:
            return result

        request.user_id = result
        return view_func(*args, **kwargs)

    return wrapper


class TokenVerifier:

    @staticmethod
    def get_token_from_request(request):
        try:
            auth_header = request.META.get('HTTP_AUTHORIZATION', '')

            if not auth_header:
                return None

            parts = auth_header.split()

            if len(parts) != 2 or parts[0].lower() != 'bearer':
                return None

            return parts[1]

        except Exception as e:

            return JsonResponse(
                {'message': GenericConstants.TOKEN_EXTRACTION_ERROR_MESSAGE},
                       status_code=status.HTTP_400_BAD_REQUEST
            )


    @staticmethod
    def verify_token(token):
        try:
            # Decode and verify token using secret key
            secret_key = settings.SECRET_KEY
            payload = jwt.decode(token, secret_key, algorithms=['HS256'])

            return True, payload

        except jwt.ExpiredSignatureError:
            return False, "Token has expired"
        except jwt.InvalidTokenError:
            return False, "Invalid token"
        except Exception as e:
            return False, f"Error verifying token: {str(e)}"

    @staticmethod
    def get_user_id_from_token(token):
        """
        Extract user_id from token payload

        Args:
            token: JWT token string

        Returns:
            User ID (int) or None if invalid
        """
        is_valid, result = TokenVerifier.verify_token(token)

        if not is_valid:
            return None

        return result.get('user_id')

    @staticmethod
    def verify_and_get_user_id(request):
        """
        Verify token from request and extract user_id

        Args:
            request: Django request object

        Returns:
            Tuple: (is_valid, user_id_or_error_response)
            - If valid: (True, user_id)
            - If invalid: (False, JsonResponse)
        """
        # Get token from request
        token = TokenVerifier.get_token_from_request(request)

        if not token:
            error_response = JsonResponse(
                {'message': 'Authorization header missing or invalid'},
                status=status.HTTP_401_UNAUTHORIZED
            )
            return False, error_response

        # Verify token
        is_valid, result = TokenVerifier.verify_token(token)

        if not is_valid:
            error_response = JsonResponse(
                {'message': result},
                status=status.HTTP_401_UNAUTHORIZED
            )
            return False, error_response

        # Extract user_id
        user_id = result.get('user_id')
        admin_user_id = result.get('admin_user_id')

        if not user_id and not admin_user_id:
            error_response = JsonResponse(
                {'message': GenericConstants.TOKEN_USER_ID_NOT_FOUND_ERROR_MESSAGE},
                status=status.HTTP_401_UNAUTHORIZED
            )
            return False, error_response

        return True, user_id