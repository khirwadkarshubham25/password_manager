from admin_panel.services.audit_logs_create_service import AuditLogsCreateService


class Commons:

    @staticmethod
    def create_audit_log(user_id, action, resource_type, resource_id, old_values=None, new_values=None):
        data = {
            'user_id': user_id,
            'action': action,
            'resource_type': resource_type,
            'resource_id': resource_id,
            'old_values': old_values,
            'new_values': new_values
        }
        service = AuditLogsCreateService()
        service.execute_service(request=None, data=data)
        return service.data