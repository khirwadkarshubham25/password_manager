import sys
import traceback

from django.db import transaction
from rest_framework import status

from admin_panel.models import BreachDatabase
from admin_panel.services.service_helper.admin_panel_service_helper import AdminPanelServiceHelper
from password_manager.commons.commons import Commons
from password_manager.commons.generic_constants import GenericConstants


class BreachDatabaseCreateService(AdminPanelServiceHelper):

    HASH_FORMAT = 'SHA256'

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        data = kwargs.get('data', {})
        return {
            'source_name': data.get('source_name', '').strip(),
            'source_url': data.get('source_url', '').strip(),
            'api_key': data.get('api_key'),
            'authentication_method': data.get('authentication_method', 'NONE'),
            'description': data.get('description', '').strip(),
            'user_id': data.get('admin_user_id')
        }

    def get_data(self, *args, **kwargs):
        try:
            params = self.get_request_params(*args, **kwargs)

            is_valid, message = self.is_valid_parameters(
                params,
                required_fields=['source_name', 'source_url']
            )
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return message

            is_valid, error_msg = self.validate_authentication_method(params['authentication_method'])
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': error_msg}

            if BreachDatabase.objects.filter(source_name=params['source_name']).exists():
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': GenericConstants.BREACH_DATABASE_ALREADY_EXISTS_MESSAGE}

            with transaction.atomic():
                breach_database = BreachDatabase.objects.create(
                    source_name=params['source_name'],
                    source_url=params['source_url'],
                    api_key=params['api_key'],
                    authentication_method=params['authentication_method'],
                    hash_format=self.HASH_FORMAT,
                    description=params['description'],
                    status=1
                )

            Commons.create_audit_log(
                user_id=params.get('user_id'),
                action='create',
                resource_type='breach_database',
                resource_id=breach_database.id,
                new_values={
                    'source_name': breach_database.source_name,
                    'source_url': breach_database.source_url,
                    'authentication_method': breach_database.authentication_method,
                    'hash_format': breach_database.hash_format
                }
            )

            return {
                'message': GenericConstants.BREACH_DATABASE_CREATED_SUCCESSFUL_MESSAGE,
            }

        except Exception:
            traceback.print_exc(file=sys.stdout)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE