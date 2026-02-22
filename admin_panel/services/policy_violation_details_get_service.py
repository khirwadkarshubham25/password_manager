import sys
import traceback

from rest_framework import status

from admin_panel.models import PolicyViolation
from admin_panel.services.service_helper.admin_panel_service_helper import AdminPanelServiceHelper
from password_manager.commons.generic_constants import GenericConstants


class PolicyViolationDetailsGetService(AdminPanelServiceHelper):

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        data = kwargs.get('data', {})
        return {
            'violation_id': data.get('violation_id', '').strip()
        }

    def get_data(self, *args, **kwargs):
        try:
            params       = self.get_request_params(*args, **kwargs)
            violation_id = params.get('violation_id')

            if not violation_id:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'Violation ID is required'}

            try:
                violation_id = int(violation_id)
            except (ValueError, TypeError):
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'Invalid violation ID. Must be numeric'}

            try:
                violation = PolicyViolation.objects.select_related('user').get(
                    id=violation_id,
                    user__isnull=False
                )
            except PolicyViolation.DoesNotExist:
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {'message': GenericConstants.POLICY_VIOLATION_NOT_FOUND_ERROR_MESSAGE}

            return {
                'data': {
                    'violation_id':   violation.id,
                    'violation_code': violation.violation_code,
                    'violation_name': violation.violation_name,
                    'description':    violation.description,
                    'severity':       violation.severity,
                    'category':       violation.category,
                    'user_id':        violation.user.id,
                    'first_name':     violation.user.first_name,
                    'last_name':      violation.user.last_name,
                    'email':          violation.user.email,
                    'created_at':     violation.created_at.isoformat()
                }
            }

        except Exception:
            traceback.print_exc(file=sys.stdout)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE