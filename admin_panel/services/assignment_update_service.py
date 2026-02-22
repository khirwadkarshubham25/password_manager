import sys
import traceback

from django.db import transaction
from rest_framework import status

from admin_panel.models import PolicyAssignment, PasswordPolicy
from admin_panel.services.service_helper.admin_panel_service_helper import AdminPanelServiceHelper
from password_manager.commons.commons import Commons
from password_manager.commons.generic_constants import GenericConstants


class AssignmentUpdateService(AdminPanelServiceHelper):

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        data = kwargs.get('data', {})
        return {
            'assignment_id': data.get('assignment_id'),
            'policy_id': data.get('policy_id'),
            'admin_user_id': data.get('admin_user_id')
        }

    def _validate_id(self, id_value, field_name):
        try:
            return True, int(id_value), None
        except (ValueError, TypeError):
            return False, None, f'Invalid {field_name}. Must be numeric'

    def get_data(self, *args, **kwargs):
        try:
            params = self.get_request_params(*args, **kwargs)

            if not params['assignment_id']:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'Assignment ID is required'}

            is_valid, assignment_id, error_msg = self._validate_id(params['assignment_id'], 'Assignment ID')
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': error_msg}

            if not params['policy_id']:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'No fields to update. Provide at least a policy_id to update'}

            is_valid, policy_id, error_msg = self._validate_id(params['policy_id'], 'Policy ID')
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': error_msg}

            try:
                assignment = PolicyAssignment.objects.select_related('policy', 'user').get(id=assignment_id)
            except PolicyAssignment.DoesNotExist:
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {'message': GenericConstants.ASSIGNMENT_NOT_FOUND_MESSAGE}

            if not PasswordPolicy.objects.filter(id=policy_id).exists():
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {'message': GenericConstants.POLICY_NOT_FOUND_MESSAGE}

            # Check if the new policy is the same as the current one
            if assignment.policy_id == policy_id:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'Policy is already assigned to this user'}

            old_values = {'policy_id': assignment.policy_id}

            with transaction.atomic():
                assignment.policy_id = policy_id
                assignment.save()

            Commons.create_audit_log(
                user_id=params.get('admin_user_id'),
                action='update',
                resource_type='policy_assignment',
                resource_id=assignment_id,
                old_values=old_values,
                new_values={'policy_id': policy_id}
            )

            return {'message': GenericConstants.ASSIGNMENT_UPDATE_SUCCESSFUL_MESSAGE}

        except Exception:
            traceback.print_exc(file=sys.stdout)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE