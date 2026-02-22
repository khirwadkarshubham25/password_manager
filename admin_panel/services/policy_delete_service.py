import sys
import traceback

from rest_framework import status

from admin_panel.models import PasswordPolicy, PolicyAssignment
from admin_panel.services.service_helper.admin_panel_service_helper import AdminPanelServiceHelper
from password_manager.commons.commons import Commons
from password_manager.commons.generic_constants import GenericConstants


class PolicyDeleteService(AdminPanelServiceHelper):

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        data = kwargs.get('data', {})
        return {
            'policy_id': data.get('policy_id', ''),
            'user_id': data.get('admin_user_id')
        }

    def get_data(self, *args, **kwargs):
        try:
            params = self.get_request_params(*args, **kwargs)
            policy_id = params.get('policy_id')

            if not policy_id:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'Policy ID is required'}

            try:
                policy_id = int(policy_id)
            except (ValueError, TypeError):
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'Invalid policy ID'}

            try:
                policy = PasswordPolicy.objects.get(id=policy_id)
            except PasswordPolicy.DoesNotExist:
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {'message': GenericConstants.POLICY_NOT_FOUND_MESSAGE}

            if PolicyAssignment.objects.filter(policy_id=policy_id).exists():
                self.set_status_code(status_code=status.HTTP_409_CONFLICT)
                return {'message': GenericConstants.POLICY_HAS_ASSIGNMENTS_MESSAGE}

            old_values = {'policy_name': policy.policy_name, 'status': policy.status}
            policy.delete()

            Commons.create_audit_log(
                user_id=params.get('user_id'),
                action='delete',
                resource_type='password_policy',
                resource_id=policy_id,
                old_values=old_values
            )

            return {'message': GenericConstants.POLICY_DELETE_SUCCESSFUL_MESSAGE}

        except Exception:
            traceback.print_exc(file=sys.stdout)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE