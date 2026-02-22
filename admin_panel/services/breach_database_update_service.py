import sys
import traceback

from django.db import transaction
from rest_framework import status

from admin_panel.models import BreachDatabase
from admin_panel.services.service_helper.admin_panel_service_helper import AdminPanelServiceHelper
from password_manager.commons.commons import Commons
from password_manager.commons.generic_constants import GenericConstants


class BreachDatabaseUpdateService(AdminPanelServiceHelper):

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        data = kwargs.get('data', {})
        return {
            'breach_database_id': data.get('breach_database_id'),
            'source_name': data.get('source_name'),
            'source_url': data.get('source_url'),
            'last_updated': data.get('last_updated'),
            'next_update_scheduled': data.get('next_update_scheduled'),
            'api_key': data.get('api_key'),
            'authentication_method': data.get('authentication_method'),
            'description': data.get('description'),
            'status': data.get('status'),
            'user_id': data.get('admin_user_id')
        }

    def _validate_database_id(self, database_id):
        if not database_id:
            return False, None, 'Breach database ID is required'
        try:
            return True, int(database_id), None
        except (ValueError, TypeError):
            return False, None, 'Invalid breach database ID. Must be numeric'

    def get_data(self, *args, **kwargs):
        try:
            params = self.get_request_params(*args, **kwargs)

            is_valid, database_id, error_msg = self._validate_database_id(params['breach_database_id'])
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': error_msg}

            try:
                breach_database = BreachDatabase.objects.get(id=database_id)
            except BreachDatabase.DoesNotExist:
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {'message': GenericConstants.BREACH_DATABASE_NOT_FOUND_MESSAGE}

            # Validate authentication method if provided
            if params['authentication_method']:
                is_valid, error_msg = self.validate_authentication_method(params['authentication_method'])
                if not is_valid:
                    self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                    return {'message': error_msg}

            # Check for duplicate source name
            source_name = params['source_name']
            if source_name and source_name != breach_database.source_name:
                if BreachDatabase.objects.filter(source_name=source_name).exclude(id=database_id).exists():
                    self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                    return {'message': GenericConstants.BREACH_DATABASE_ALREADY_EXISTS_MESSAGE}

            # Check at least one field is provided
            updatable = ['source_name', 'source_url', 'api_key', 'authentication_method',
                         'description', 'data_storage_path', 'last_updated',
                         'next_update_scheduled', 'status']
            if not any(params.get(f) is not None for f in updatable) and params['total_hashes'] is None:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'No fields to update. Provide at least one field to update'}

            old_values = {
                'source_name': breach_database.source_name,
                'source_url': breach_database.source_url,
                'authentication_method': breach_database.authentication_method,
                'status': breach_database.status
            }

            with transaction.atomic():
                if source_name:
                    breach_database.source_name = source_name

                if params['source_url']:
                    breach_database.source_url = params['source_url']

                if params['last_updated']:
                    breach_database.last_updated = params['last_updated']

                if params['next_update_scheduled']:
                    breach_database.next_update_scheduled = params['next_update_scheduled']

                if params['api_key'] is not None:
                    breach_database.api_key = params['api_key']

                if params['authentication_method']:
                    breach_database.authentication_method = params['authentication_method']

                if params['description'] is not None:
                    breach_database.description = params['description']

                if params['status'] is not None:
                    breach_database.status = params['status']

                breach_database.save()

            Commons.create_audit_log(
                user_id=params.get('user_id'),
                action='update',
                resource_type='breach_database',
                resource_id=database_id,
                old_values=old_values,
                new_values={
                    'source_name': breach_database.source_name,
                    'source_url': breach_database.source_url,
                    'authentication_method': breach_database.authentication_method,
                    'status': breach_database.status
                }
            )

            return {'message': GenericConstants.BREACH_DATABASE_UPDATE_SUCCESSFUL_MESSAGE}

        except Exception:
            traceback.print_exc(file=sys.stdout)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE