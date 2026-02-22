import sys
import traceback

from django.db import transaction
from rest_framework import status

from admin_panel.models import PolicyAssignment
from admin_panel.services.service_helper.admin_panel_service_helper import AdminPanelServiceHelper
from password_manager.commons.commons import Commons
from password_manager.commons.generic_constants import GenericConstants


class AssignmentDeleteService(AdminPanelServiceHelper):

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        data = kwargs.get('data', {})
        return {
            'assignment_id': data.get('assignment_id', ''),
            'admin_user_id': data.get('admin_user_id')
        }

    def get_data(self, *args, **kwargs):
        try:
            params = self.get_request_params(*args, **kwargs)

            is_valid, assignment_id, error_msg = self.validate_assignment_id(params['assignment_id'])
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': error_msg}

            try:
                assignment = PolicyAssignment.objects.get(id=assignment_id)
            except PolicyAssignment.DoesNotExist:
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {'message': GenericConstants.ASSIGNMENT_NOT_FOUND_MESSAGE}

            old_values = {
                'policy_id': assignment.policy.id,
                'user_id': assignment.user.id
            }

            with transaction.atomic():
                assignment.delete()

            Commons.create_audit_log(
                user_id=params.get('admin_user_id'),
                action='delete',
                resource_type='policy_assignment',
                resource_id=assignment_id,
                old_values=old_values
            )

            return {'message': GenericConstants.ASSIGNMENT_DELETE_SUCCESSFUL_MESSAGE}

        except Exception:
            traceback.print_exc(file=sys.stdout)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE