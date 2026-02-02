from rest_framework import status

from password_manager.commons.generic_constants import GenericConstants
from password_manager_admin.services.service_helper.password_admin_manager_service_helper import \
    PasswordAdminManagerServiceHelper
from password_manager_admin.models import PolicyViolation


class GetViolationDetailsService(PasswordAdminManagerServiceHelper):
    """Service for retrieving specific policy violation details"""

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        """Extract and clean request parameters"""
        violation_id = kwargs.get('data', {}).get('violation_id', '').strip()

        return {
            'violation_id': violation_id
        }

    def get_data(self, *args, **kwargs):
        """Retrieve specific violation details"""
        try:
            # Get request parameters
            params = self.get_request_params(*args, **kwargs)

            violation_id = params.get('violation_id')

            # Validate violation_id
            if not violation_id:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'Violation ID is required'}

            try:
                violation_id = int(violation_id)
            except ValueError:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'Invalid violation ID'}

            # Get violation
            try:
                violation = PolicyViolation.objects.get(id=violation_id)
            except PolicyViolation.DoesNotExist:
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {'message': f'Violation with ID {violation_id} not found'}

            # Build response data
            violation_data = {
                'id': violation.id,
                'violation_code': violation.violation_code,
                'violation_name': violation.violation_name,
                'severity': violation.severity,
                'category': violation.category,
                'created_at': violation.created_at.isoformat() if violation.created_at else None
            }

            self.set_status_code(status_code=status.HTTP_200_OK)
            return {
                'data': violation_data
            }

        except Exception as e:
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE