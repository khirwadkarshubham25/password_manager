import sys
import traceback

from django.db import transaction
from rest_framework import status

from admin_panel.models import PolicyAssignment
from admin_panel.services.service_helper.admin_panel_service_helper import AdminPanelServiceHelper
from password_manager.commons.commons import Commons
from password_manager.commons.generic_constants import GenericConstants


class AssignmentCreateService(AdminPanelServiceHelper):

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        data = kwargs.get('data', {})
        return {
            'policy_id': data.get('policy_id'),
            'user_id': data.get('user_id'),
            'admin_user_id': data.get('admin_user_id')
        }

    def get_data(self, *args, **kwargs):
        try:
            params = self.get_request_params(*args, **kwargs)

            is_valid, message = self.is_valid_parameters(
                params,
                required_fields=['policy_id', 'user_id', 'admin_user_id']
            )
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return message

            is_valid, policy_id, user_id, admin_user_id, error_msg = self.validate_ids(
                params['policy_id'],
                params['user_id'],
                params['admin_user_id']
            )
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': error_msg}

            is_valid, error_msg = self.validate_foreign_keys(policy_id, user_id, admin_user_id)
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {'message': error_msg}

            if PolicyAssignment.objects.filter(user_id=user_id).exists():
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': GenericConstants.ASSIGNMENT_ALREADY_EXISTS_MESSAGE}

            with transaction.atomic():
                assignment = PolicyAssignment.objects.create(
                    policy_id=policy_id,
                    user_id=user_id,
                    assigned_by_id=admin_user_id
                )

            Commons.create_audit_log(
                user_id=admin_user_id,
                action='create',
                resource_type='policy_assignment',
                resource_id=assignment.id,
                new_values={'policy_id': policy_id, 'user_id': user_id}
            )

            return {'message': GenericConstants.ASSIGNMENT_CREATED_SUCCESSFUL_MESSAGE}

        except Exception:
            traceback.print_exc(file=sys.stdout)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE