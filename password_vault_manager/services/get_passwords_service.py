from password_manager.commons.generic_constants import GenericConstants
from password_vault_manager.models import Users, UserPasswords
from password_vault_manager.services.crypto_service import CryptoService
from rest_framework import status

from password_vault_manager.services.service_helper.password_vault_manager_service_helper import \
    PasswordVaultManagerServiceHelper


class GetPasswordsService(PasswordVaultManagerServiceHelper):
    """Service for retrieving and decrypting user passwords"""

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        """Extract and clean request parameters"""
        user_id = kwargs.get('data', {}).get('user_id', '')

        return {
            'user_id': user_id
        }

    def get_data(self, *args, **kwargs):
        """Process password retrieval and decryption"""
        # Get request parameters
        params = self.get_request_params(*args, **kwargs)

        # Extract parameters
        user_id = params.get('user_id')

        # Check if user_id is provided
        if not user_id:
            self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
            return {"message": GenericConstants.INVALID_USER_ID}

        try:
            # Get user from database
            user = Users.objects.filter(id=user_id).first()

            # Check if user exists
            if not user:
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {"message": GenericConstants.USER_NOT_FOUND}

            # Get all passwords for the user
            user_passwords = UserPasswords.objects.filter(user_id=user_id).values(
                'id',
                'platform',
                'url',
                'email',
                'password',
                'created_at',
                'updated_at'
            )

            # Decrypt passwords using the user's master password
            decrypted_passwords = []

            for password_entry in user_passwords:
                try:
                    # Decrypt the password using user's master password
                    decrypted_password = CryptoService.decrypt_password(
                        password_entry['password'],
                        user.password
                    )

                    # Create decrypted password entry with required fields only
                    decrypted_entry = {
                        'user_password_id': password_entry['id'],
                        'platform': password_entry['platform'],
                        'email': password_entry['email'],
                        'url': password_entry['url'],
                        'password': decrypted_password,
                        'updated_at': password_entry['updated_at'].isoformat() if password_entry[
                            'updated_at'] else None,
                    }
                    decrypted_passwords.append(decrypted_entry)

                except Exception as e:
                    self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
                    return {"message": GenericConstants.DECRYPTED_PASSWORD_ERROR_MESSAGE}

            self.set_status_code(status_code=status.HTTP_200_OK)
            return {
                'passwords': decrypted_passwords,
                'count': len(decrypted_passwords)
            }

        except Exception as e:
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return {"message": GenericConstants.DECRYPTED_PASSWORD_ERROR_MESSAGE}