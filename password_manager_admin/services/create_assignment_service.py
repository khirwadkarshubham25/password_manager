import traceback
from datetime import datetime
from rest_framework import status
from django.db import transaction
from password_manager.commons.generic_constants import GenericConstants
from password_manager_admin.models import AdminUsers
from password_manager_admin.services.service_helper.password_admin_manager_service_helper import \
    PasswordAdminManagerServiceHelper
from password_vault_manager.models import PolicyAssignment, PasswordPolicy, Users


class CreateAssignmentService(PasswordAdminManagerServiceHelper):
    """Service for creating policy assignments"""

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        """Extract and clean request parameters"""
        data = kwargs.get('data', {})

        return {
            'policy_id': data.get('policy_id'),
            'user_id': data.get('user_id'),
            'admin_user_id': data.get('admin_user_id'),
            'effective_date': data.get('effective_date'),
            'expiry_date': data.get('expiry_date'),
        }

    def _validate_ids(self, policy_id, user_id, admin_user_id):
        """Validate that all IDs are valid integers"""
        try:
            policy_id = int(policy_id)
            user_id = int(user_id)
            admin_user_id = int(admin_user_id)
            return True, policy_id, user_id, admin_user_id, None
        except (ValueError, TypeError):
            return False, None, None, None, 'Invalid ID format. IDs must be numeric'

    def _validate_foreign_keys(self, policy_id, user_id, admin_user_id):
        """Validate that referenced records exist"""
        # Check if policy exists (adjust model name based on your actual model)
        if not PasswordPolicy.objects.filter(id=policy_id).exists():
            return False, f'Policy with ID {policy_id} does not exist'

        # Check if user exists (adjust model name based on your actual model)
        if not Users.objects.filter(id=user_id).exists():
            return False, f'User with ID {user_id} does not exist'

        # Check if admin user exists (adjust model name based on your actual model)
        if not AdminUsers.objects.filter(id=admin_user_id).exists():
            return False, f'Admin User with ID {admin_user_id} does not exist'

        return True, None

    def _validate_dates(self, effective_date, expiry_date):
        """Validate date formats and logic"""
        if not effective_date:
            return False, 'Effective date is required'

        # Parse and validate effective_date
        try:
            effective_dt = datetime.fromisoformat(effective_date.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            return False, 'Invalid effective_date format. Use ISO format (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)'

        # Validate expiry_date if provided
        if expiry_date:
            try:
                expiry_dt = datetime.fromisoformat(expiry_date.replace('Z', '+00:00'))
            except (ValueError, AttributeError):
                return False, 'Invalid expiry_date format. Use ISO format (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)'

            # Check if expiry is after effective date
            if expiry_dt <= effective_dt:
                return False, 'Expiry date must be after effective date'

        return True, None

    def get_data(self, *args, **kwargs):
        """Create new policy assignment"""
        try:
            params = self.get_request_params(*args, **kwargs)

            # Validate required fields
            if not params['policy_id']:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'Policy ID is required'}

            if not params['user_id']:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'User ID is required'}

            if not params['admin_user_id']:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'Admin User ID is required'}

            # Validate IDs are numeric
            is_valid, policy_id, user_id, admin_user_id, error_msg = self._validate_ids(
                params['policy_id'],
                params['user_id'],
                params['admin_user_id']
            )
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': error_msg}

            # Validate foreign key references exist
            is_valid, error_msg = self._validate_foreign_keys(policy_id, user_id, admin_user_id)
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {'message': error_msg}

            # Validate dates
            is_valid, error_msg = self._validate_dates(params['effective_date'], params['expiry_date'])
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': error_msg}

            # Check for duplicate active assignment
            existing_assignment = PolicyAssignment.objects.filter(
                password_policy_id=policy_id,
                user_id=user_id,
                status=1  # Only check active assignments
            ).exists()

            if existing_assignment:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'Active assignment already exists for this policy and user'}

            # Create assignment within a transaction
            with transaction.atomic():
                assignment = PolicyAssignment.objects.create(
                    password_policy_id=policy_id,
                    user_id=user_id,
                    admin_user_id=admin_user_id,  # Adjust field name based on your model
                    effective_date=params['effective_date'],
                    expiry_date=params['expiry_date'],
                    status=1  # Set default status
                )

            # Return assignment details
            return {
                'message': 'Assignment created successfully',
            }

        except Exception as e:
            traceback.print_exc(e)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE