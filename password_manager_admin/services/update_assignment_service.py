import traceback
from datetime import datetime

from django.db import transaction
from rest_framework import status

from password_manager.commons.generic_constants import GenericConstants
from password_manager_admin.services.service_helper.password_admin_manager_service_helper import \
    PasswordAdminManagerServiceHelper
from password_vault_manager.models import PolicyAssignment, PasswordPolicy, Users


class UpdateAssignmentService(PasswordAdminManagerServiceHelper):
    """Service for updating policy assignments"""

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        """Extract and clean request parameters"""
        data = kwargs.get('data', {})

        return {
            'assignment_id': data.get('assignment_id', '') if data.get('assignment_id') else None,
            'policy_id': data.get('policy_id', '') if data.get('policy_id') else None,
            'user_id': data.get('user_id', '') if data.get('user_id') else None,
            'effective_date': data.get('effective_date'),
            'expiry_date': data.get('expiry_date'),
            'is_active': data.get('is_active')
        }

    def _validate_id(self, id_value, field_name):
        """Validate that ID is a valid integer"""
        try:
            return True, int(id_value), None
        except (ValueError, TypeError):
            return False, None, f'Invalid {field_name}. Must be numeric'

    def _validate_foreign_keys(self, policy_id, user_id, assignment_id):
        """Validate that referenced records exist"""
        if policy_id:
            if not PasswordPolicy.objects.filter(id=policy_id).exists():
                return False, f'Policy with ID {policy_id} does not exist'

        if user_id:
            if not Users.objects.filter(id=user_id).exists():
                return False, f'User with ID {user_id} does not exist'

        return True, None

    def _validate_dates(self, effective_date, expiry_date):
        """Validate date formats and logic"""
        effective_dt = None
        expiry_dt = None

        # Parse effective_date if provided
        if effective_date:
            try:
                effective_dt = datetime.fromisoformat(effective_date.replace('Z', '+00:00'))
            except (ValueError, AttributeError):
                return False, 'Invalid effective_date format. Use ISO format (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)'

        # Parse expiry_date if provided
        if expiry_date:
            try:
                expiry_dt = datetime.fromisoformat(expiry_date.replace('Z', '+00:00'))
            except (ValueError, AttributeError):
                return False, 'Invalid expiry_date format. Use ISO format (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)'

        # Validate date logic if both are provided
        if effective_dt and expiry_dt:
            if expiry_dt <= effective_dt:
                return False, 'Expiry date must be after effective date'

        return True, None

    def _validate_is_active(self, is_active_value):
        """Validate is_active field"""
        if is_active_value is not None:
            if not isinstance(is_active_value, bool):
                return False, 'Invalid is_active value. Must be boolean (true/false)'
        return True, None

    def _check_duplicate(self, assignment, policy_id, user_id):
        """Check if update would create duplicate assignment"""
        # Determine what policy_id and user_id to check
        check_policy_id = policy_id if policy_id else assignment.password_policy_id
        check_user_id = user_id if user_id else assignment.user_id

        # Check if another active assignment exists with same policy and user
        duplicate = PolicyAssignment.objects.filter(
            password_policy_id=check_policy_id,
            user_id=check_user_id,
            status=1  # ✅ FIXED: Active status as integer
        ).exclude(id=assignment.id).exists()

        return not duplicate, 'Active assignment with this policy and user combination already exists'

    def get_data(self, *args, **kwargs):
        """Update policy assignment"""
        try:
            params = self.get_request_params(*args, **kwargs)

            # Validate assignment_id is required
            if not params['assignment_id']:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'Assignment ID is required'}

            # Validate assignment_id is numeric
            is_valid, assignment_id, error_msg = self._validate_id(params['assignment_id'], 'Assignment ID')
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': error_msg}

            # Check if assignment exists
            try:
                assignment = PolicyAssignment.objects.select_related(
                    'password_policy',
                    'user'
                ).get(id=assignment_id)
            except PolicyAssignment.DoesNotExist:
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {'message': f'Assignment with ID {assignment_id} not found'}

            # Track if any field is being updated
            has_updates = False
            policy_id = None
            user_id = None

            # Validate and prepare policy_id update
            if params['policy_id']:
                is_valid, policy_id, error_msg = self._validate_id(params['policy_id'], 'Policy ID')
                if not is_valid:
                    self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                    return {'message': error_msg}
                has_updates = True

            # Validate and prepare user_id update
            if params['user_id']:
                is_valid, user_id, error_msg = self._validate_id(params['user_id'], 'User ID')
                if not is_valid:
                    self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                    return {'message': error_msg}
                has_updates = True

            # Validate foreign keys exist
            is_valid, error_msg = self._validate_foreign_keys(policy_id, user_id, assignment_id)
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {'message': error_msg}

            # Validate dates
            is_valid, error_msg = self._validate_dates(params['effective_date'], params['expiry_date'])
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': error_msg}

            # ✅ ADDED: Validate is_active
            is_valid, error_msg = self._validate_is_active(params['is_active'])
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': error_msg}

            # Check for duplicate if policy_id or user_id is being updated
            if policy_id or user_id:
                is_valid, error_msg = self._check_duplicate(assignment, policy_id, user_id)
                if not is_valid:
                    self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                    return {'message': error_msg}

            # ✅ FIXED: Check if at least one field is being updated
            if (not has_updates and
                    not params['effective_date'] and
                    not params['expiry_date'] and
                    params['is_active'] is None):
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'No fields to update. Provide at least one field to update'}

            # Update assignment within transaction
            with transaction.atomic():
                if policy_id:
                    assignment.password_policy_id = policy_id

                if user_id:
                    assignment.user_id = user_id

                if params['effective_date']:
                    assignment.effective_date = params['effective_date']
                    has_updates = True

                if params['expiry_date']:
                    assignment.expiry_date = params['expiry_date']
                    has_updates = True

                if params['is_active'] is not None:
                    assignment.status = 1 if params['is_active'] else 0
                    has_updates = True

                assignment.save()

            # Return updated assignment details
            return {
                'message': 'Assignment updated successfully'
            }

        except Exception as e:
            traceback.print_exc(e)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return {'message': GenericConstants.ERROR_MESSAGE}