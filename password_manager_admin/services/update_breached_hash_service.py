from django.db import transaction
from rest_framework import status

from password_manager.commons.generic_constants import GenericConstants
from password_manager_admin.services.service_helper.password_admin_manager_service_helper import \
    PasswordAdminManagerServiceHelper
from password_manager_admin.models import BreachedPasswordHash


class UpdateBreachedHashService(PasswordAdminManagerServiceHelper):
    """Service for updating breached password hash"""

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        """Extract and clean request parameters"""
        data = kwargs.get('data', {})

        return {
            'breach_hash_id': data.get('breach_hash_id', '').strip() if data.get('breach_hash_id') else None,
            'occurrence_count': data.get('occurrence_count'),
            'severity': data.get('severity'),
            'first_seen_date': data.get('first_seen_date'),
            'is_indexed': data.get('is_indexed'),
        }

    def _validate_breach_hash_id(self, breach_hash_id):
        """Validate breach hash ID format"""
        if not breach_hash_id:
            return False, None, 'Breach hash ID is required'

        try:
            breach_hash_id_int = int(breach_hash_id)
            return True, breach_hash_id_int, None
        except (ValueError, TypeError):
            return False, None, 'Invalid breach hash ID format. Must be numeric'

    def _validate_occurrence_count(self, occurrence_count):
        """Validate occurrence count"""
        if occurrence_count is not None:
            try:
                count = int(occurrence_count)
                if count < 1:
                    return False, None, 'Occurrence count must be at least 1'
                return True, count, None
            except (ValueError, TypeError):
                return False, None, 'Invalid occurrence count. Must be numeric'
        return True, None, None

    def _validate_severity(self, severity):
        """Validate severity"""
        if severity:
            valid_severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
            if severity.upper() not in valid_severities:
                return False, f'Invalid severity. Must be one of: {", ".join(valid_severities)}'
        return True, None

    def _validate_is_indexed(self, is_indexed_value):
        """Validate is_indexed field"""
        if is_indexed_value is not None:
            if not isinstance(is_indexed_value, bool):
                return False, 'Invalid is_indexed value. Must be boolean (true/false)'
        return True, None

    def get_data(self, *args, **kwargs):
        """Update breached hash details"""
        try:
            params = self.get_request_params(*args, **kwargs)

            # Validate breach_hash_id
            is_valid, breach_hash_id, error_msg = self._validate_breach_hash_id(params['breach_hash_id'])
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': error_msg}

            # Check if breached hash exists
            try:
                breached_hash = BreachedPasswordHash.objects.get(id=breach_hash_id)
            except BreachedPasswordHash.DoesNotExist:
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {'message': f'Breached hash with ID {breach_hash_id} not found'}

            # Validate occurrence_count
            is_valid, occurrence_count, error_msg = self._validate_occurrence_count(params['occurrence_count'])
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': error_msg}

            # Validate severity
            is_valid, error_msg = self._validate_severity(params['severity'])
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': error_msg}

            # Validate is_indexed
            is_valid, error_msg = self._validate_is_indexed(params['is_indexed'])
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': error_msg}

            # Check if at least one field is being updated
            if (params['occurrence_count'] is None and
                not params['severity'] and
                not params['first_seen_date'] and
                params['is_indexed'] is None):
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'No fields to update. Provide at least one field to update'}

            # Update breached hash within transaction
            with transaction.atomic():
                if params['occurrence_count'] is not None:
                    breached_hash.occurrence_count = occurrence_count

                if params['severity']:
                    breached_hash.severity = params['severity'].upper()

                if params['first_seen_date']:
                    breached_hash.first_seen_date = params['first_seen_date']

                if params['is_indexed'] is not None:
                    breached_hash.is_indexed = params['is_indexed']

                breached_hash.save()

            # Return updated breached hash details
            return {
                'message': 'Breached hash updated successfully',
            }

        except Exception as e:
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return {'message': GenericConstants.ERROR_MESSAGE}