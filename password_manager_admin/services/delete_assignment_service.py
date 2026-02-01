import traceback

from django.db import transaction
from rest_framework import status

from password_manager.commons.generic_constants import GenericConstants
from password_manager_admin.services.service_helper.password_admin_manager_service_helper import \
    PasswordAdminManagerServiceHelper
from password_vault_manager.models import PolicyAssignment


class DeleteAssignmentService(PasswordAdminManagerServiceHelper):
    """Service for deleting policy assignments"""

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        """Extract and clean request parameters"""
        data = kwargs.get('data', {})
        assignment_id = data.get('assignment_id', '')
        return {'assignment_id': assignment_id}

    def _validate_assignment_id(self, assignment_id):
        """Validate assignment ID format"""
        if not assignment_id:
            return False, None, 'Assignment ID is required'

        try:
            assignment_id_int = int(assignment_id)
            return True, assignment_id_int, None
        except (ValueError, TypeError):
            return False, None, 'Invalid Assignment ID format. Must be numeric'

    def get_data(self, *args, **kwargs):
        """Delete policy assignment"""
        try:
            params = self.get_request_params(*args, **kwargs)

            # Validate assignment_id
            is_valid, assignment_id, error_msg = self._validate_assignment_id(params['assignment_id'])
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

            # Delete assignment within transaction
            with transaction.atomic():
                assignment.delete()

            return {
                'message': 'Assignment deleted successfully',
            }

        except Exception as e:
            traceback.print_exc(e)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE