import sys
import traceback

from rest_framework import status

from admin_panel.models import AuditLogs
from admin_panel.services.service_helper.admin_panel_service_helper import AdminPanelServiceHelper
from password_manager.commons.generic_constants import GenericConstants


class AuditLogDetailsGetService(AdminPanelServiceHelper):

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        data = kwargs.get('data', {})
        return {
            'audit_log_id': data.get('audit_log_id', '').strip()
        }

    def get_data(self, *args, **kwargs):
        try:
            params = self.get_request_params(*args, **kwargs)
            audit_log_id = params.get('audit_log_id')

            if not audit_log_id:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'Audit log ID is required'}

            try:
                audit_log_id = int(audit_log_id)
            except (ValueError, TypeError):
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'Invalid audit log ID. Must be numeric'}

            try:
                log = AuditLogs.objects.select_related('user').get(id=audit_log_id)
            except AuditLogs.DoesNotExist:
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {'message': GenericConstants.AUDIT_LOG_NOT_FOUND_MESSAGE}

            return {
                'data': {
                    'audit_log_id': log.id,
                    'user_id': log.user.id if log.user else None,
                    'user_email': log.user.email if log.user else None,
                    'action': log.action,
                    'resource_type': log.resource_type,
                    'resource_id': log.resource_id,
                    'description': log.description,
                    'old_values': log.old_values,
                    'new_values': log.new_values,
                    'ip_address': log.ip_address,
                    'created_at': log.created_at.isoformat()
                }
            }

        except Exception:
            traceback.print_exc(file=sys.stdout)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE