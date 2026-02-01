import traceback

from rest_framework import status

from password_manager.commons.generic_constants import GenericConstants
from password_manager_admin.models import PasswordPolicy
from password_manager_admin.services.service_helper.password_admin_manager_service_helper import \
    PasswordAdminManagerServiceHelper
from password_vault_manager.models import PolicyAssignment


class DeletePolicyService(PasswordAdminManagerServiceHelper):
    """Service for deleting password policies"""

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        """Extract and clean request parameters"""
        policy_id = kwargs.get('data', {}).get('policy_id', '')

        return {
            'policy_id': policy_id
        }

    def get_data(self, *args, **kwargs):
        """Delete a password policy"""
        try:
            # Get request parameters
            params = self.get_request_params(*args, **kwargs)

            policy_id = params.get('policy_id')

            # Validate policy_id
            if not policy_id:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'Policy ID is required'}

            try:
                policy_id = int(policy_id)
            except ValueError:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'Invalid policy ID'}

            # Get policy
            try:
                policy = PasswordPolicy.objects.get(id=policy_id)
            except PasswordPolicy.DoesNotExist:
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {'message': f'Policy with ID {policy_id} not found'}

            # Check if policy has dependent assignments
            if PolicyAssignment.objects.filter(policy_id=policy_id).exists():
                self.set_status_code(status_code=status.HTTP_409_CONFLICT)
                return {'message': 'Cannot delete policy that has existing assignments'}

            # Store policy name and id before deletion
            policy_name = policy.policy_name
            policy_id_deleted = policy.id

            # Delete the policy
            policy.delete()

            # Verify deletion was successful
            if PasswordPolicy.objects.filter(id=policy_id_deleted).exists():
                self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
                return {'message': 'Failed to delete policy'}

            return {
                'message': f'Policy "{policy_name}" deleted successfully'
            }

        except Exception as e:
            traceback.print_exc(e)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE