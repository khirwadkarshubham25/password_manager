import sys
import traceback

from rest_framework import status

from admin_panel.models import PolicyAssignment
from admin_panel.services.service_helper.admin_panel_service_helper import AdminPanelServiceHelper
from password_manager.commons.generic_constants import GenericConstants


class AssignmentDetailsGetService(AdminPanelServiceHelper):

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        data = kwargs.get('data', {})
        return {
            'assignment_id': data.get('assignment_id', '').strip()
        }

    def get_data(self, *args, **kwargs):
        try:
            params = self.get_request_params(*args, **kwargs)

            if not params['assignment_id']:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'Assignment ID is required'}

            try:
                assignment_id = int(params['assignment_id'])
            except (ValueError, TypeError):
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'Invalid assignment ID format'}

            try:
                assignment = PolicyAssignment.objects.select_related(
                    'policy',
                    'user',
                    'assigned_by'
                ).get(id=assignment_id)
            except PolicyAssignment.DoesNotExist:
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {'message': GenericConstants.ASSIGNMENT_NOT_FOUND_MESSAGE}

            return {
                'data': {
                    'assignment_id': assignment.id,
                    'policy_id': assignment.policy.id if assignment.policy else None,
                    'policy_name': assignment.policy.policy_name if assignment.policy else None,
                    'user_id': assignment.user.id if assignment.user else None,
                    'first_name': assignment.user.first_name if assignment.user else None,
                    'last_name': assignment.user.last_name if assignment.user else None,
                    'email': assignment.user.email if assignment.user else None,
                    'assigned_by_id': assignment.assigned_by.id if assignment.assigned_by else None,
                    'assigned_by_first_name': assignment.assigned_by.first_name if assignment.assigned_by else None,
                    'assigned_by_last_name': assignment.assigned_by.last_name if assignment.assigned_by else None,
                    'assigned_by_email': assignment.assigned_by.email if assignment.assigned_by else None,
                    'created_at': assignment.created_at.isoformat() if assignment.created_at else None,
                    'updated_at': assignment.updated_at.isoformat() if assignment.updated_at else None
                }
            }

        except Exception:
            traceback.print_exc(file=sys.stdout)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE