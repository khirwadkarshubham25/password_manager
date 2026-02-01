import traceback

from rest_framework import status
from password_manager.commons.generic_constants import GenericConstants
from password_manager_admin.services.service_helper.password_admin_manager_service_helper import \
    PasswordAdminManagerServiceHelper
from password_vault_manager.models import PolicyAssignment


class GetAssignmentDetailsService(PasswordAdminManagerServiceHelper):
    """Service for retrieving specific policy assignment details"""

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        """Extract and clean request parameters"""
        assignment_id = kwargs.get('data', {}).get('assignment_id', '').strip()

        return {
            'assignment_id': assignment_id
        }

    def get_data(self, *args, **kwargs):
        """Retrieve assignment details"""
        try:
            params = self.get_request_params(*args, **kwargs)

            if not params['assignment_id']:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'Assignment ID is required'}

            try:
                assignment_id = int(params['assignment_id'])
            except ValueError:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'Invalid assignment ID format'}

            try:
                assignment = PolicyAssignment.objects.select_related(
                    'password_policy',
                    'user',
                    'admin_user'
                ).get(id=assignment_id)
            except PolicyAssignment.DoesNotExist:
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {'message': f'Assignment with ID {assignment_id} not found'}

            return {
                'data': {
                    'assignment_id': assignment.id,
                    'policy_id': assignment.password_policy.id if assignment.password_policy else None,
                    'policy_name': assignment.password_policy.policy_name if assignment.password_policy else None,
                    'user_id': assignment.user.id if assignment.user else None,
                    'first_name': assignment.user.first_name if assignment.user else None,
                    'last_name': assignment.user.last_name if assignment.user else None,
                    'effective_date': assignment.effective_date.isoformat() if assignment.effective_date else None,
                    'expiry_date': assignment.expiry_date.isoformat() if assignment.expiry_date else None,
                    'admin_user_id': assignment.admin_user.id if assignment.admin_user else None,
                    'admin_first_name': assignment.admin_user.first_name if assignment.admin_user else None,
                    'admin_last_name': assignment.admin_user.last_name if assignment.admin_user else None,
                    'is_active': True if assignment.status == 1 else False,
                    'created_at': assignment.created_at.isoformat() if assignment.created_at else None,
                }
            }

        except PolicyAssignment.DoesNotExist:
            self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
            return {'message': f'Assignment with not found'}
        except Exception as e:
            traceback.print_exc(e)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return {'message': GenericConstants.ERROR_MESSAGE}