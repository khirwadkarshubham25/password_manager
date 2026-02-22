import sys
import traceback

from rest_framework import status

from admin_panel.models import BreachedPasswordHash
from admin_panel.services.service_helper.admin_panel_service_helper import AdminPanelServiceHelper
from password_manager.commons.generic_constants import GenericConstants


class BreachedHashDetailsGetService(AdminPanelServiceHelper):

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        data = kwargs.get('data', {})
        return {
            'breach_hash_id': data.get('breach_hash_id', '').strip()
        }

    def get_data(self, *args, **kwargs):
        try:
            params = self.get_request_params(*args, **kwargs)
            breach_hash_id = params.get('breach_hash_id')

            if not breach_hash_id:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'Breach hash ID is required'}

            try:
                breach_hash_id = int(breach_hash_id)
            except (ValueError, TypeError):
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'Invalid breach hash ID. Must be numeric'}

            try:
                hash_obj = BreachedPasswordHash.objects.select_related('breach_database').get(id=breach_hash_id)
            except BreachedPasswordHash.DoesNotExist:
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {'message': GenericConstants.BREACHED_HASH_NOT_FOUND_MESSAGE}

            return {
                'data': {
                    'breach_hash_id': hash_obj.id,
                    'password_hash': hash_obj.password_hash,
                    'hash_format': hash_obj.hash_format,
                    'occurrence_count': hash_obj.occurrence_count,
                    'severity': hash_obj.severity,
                    'is_indexed': hash_obj.is_indexed,
                    'first_seen_date': hash_obj.first_seen_date.isoformat() if hash_obj.first_seen_date else None,
                    'breach_database_id': hash_obj.breach_database.id,
                    'breach_source_name': hash_obj.breach_database.source_name,
                    'breach_source_url': hash_obj.breach_database.source_url,
                    'created_at': hash_obj.created_at.isoformat(),
                    'updated_at': hash_obj.updated_at.isoformat()
                }
            }

        except Exception:
            traceback.print_exc(file=sys.stdout)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE