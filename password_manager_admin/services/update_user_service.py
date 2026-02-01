from rest_framework import status

from password_manager.commons.generic_constants import GenericConstants
from password_manager_admin.services.service_helper.password_admin_manager_service_helper import \
    PasswordAdminManagerServiceHelper
from password_manager.services.crypto_service import CryptoService
from password_vault_manager.models import Users


class UpdateUserService(PasswordAdminManagerServiceHelper):
    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        data = kwargs.get('data', {})
        user_id = data.get('user_id')
        try:
            user_id = int(user_id) if user_id else None
        except (ValueError, TypeError):
            user_id = None

        username = data.get('username', '').strip()
        email = data.get('email', '').strip().lower()
        first_name = data.get('first_name', '').strip()
        last_name = data.get('last_name', '').strip()
        password = data.get('password', '')

        return {
            'user_id': user_id,
            'username': username,
            'email': email,
            'first_name': first_name,
            'last_name': last_name,
            'password': password
        }

    def get_data(self, *args, **kwargs):
        params = self.get_request_params(*args, **kwargs)

        # Validate user_id
        user_id = params.get('user_id')
        if not user_id:
            self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
            return {'message': 'User ID is required'}

        # Check if user exists
        try:
            user = Users.objects.get(id=user_id)
        except Users.DoesNotExist:
            self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
            return {'message': GenericConstants.USER_NOT_FOUND_MESSAGE.format(user_id)}

        try:
            # Update username if provided and different
            username = params.get('username')
            if username and username != user.username:
                if Users.objects.filter(username=username).exists():
                    self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                    return {"message": GenericConstants.USERNAME_EXISTS_ERROR_MESSAGE.format(username)}
                user.username = username

            # Update email if provided and different
            email = params.get('email')
            if email and email != user.email:
                if Users.objects.filter(email=email).exists():
                    self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                    return {"message": GenericConstants.USER_EMAIL_EXISTS_ERROR_MESSAGE.format(email)}
                user.email = email

            # Update first name if provided
            first_name = params.get('first_name')
            if first_name:
                user.first_name = first_name

            # Update last name if provided
            last_name = params.get('last_name')
            if last_name:
                user.last_name = last_name

            # Update password if provided
            password = params.get('password')
            if password:
                hashed_password = CryptoService.hash_master_password(password)
                user.password = hashed_password

            # Save the updated user
            user.save()

            self.set_status_code(status_code=status.HTTP_200_OK)
            return {
                'message': 'User updated successfully',
                'user_id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'updated_at': user.updated_at.isoformat()
            }

        except Exception as e:
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE