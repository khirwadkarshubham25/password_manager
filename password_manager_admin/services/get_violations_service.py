from rest_framework import status

from password_manager.commons.generic_constants import GenericConstants
from password_manager.validators.page_validator import PageValidator
from password_manager.validators.sort_validator import SortValidator
from password_manager_admin.services.service_helper.password_admin_manager_service_helper import \
    PasswordAdminManagerServiceHelper
from password_manager_admin.models import PolicyViolation


class GetViolationsService(PasswordAdminManagerServiceHelper):
    """Service for retrieving policy violations with pagination and sorting"""

    def __init__(self):
        super().__init__()
        self.valid_severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

    def get_request_params(self, *args, **kwargs):
        """Extract and clean request parameters"""
        page = kwargs.get('data', {}).get('page', '1').strip()
        page_size = kwargs.get('data', {}).get('page_size', '10').strip()
        sort_by = kwargs.get('data', {}).get('sort_by', 'created_at').strip()
        sort_order = kwargs.get('data', {}).get('sort_order', 'desc').strip().lower()
        severity = kwargs.get('data', {}).get('severity', '').strip().upper()

        return {
            'page': page,
            'page_size': page_size,
            'sort_by': sort_by,
            'sort_order': sort_order,
            'severity': severity
        }

    def validate_severity(self, severity):
        """Validate severity filter parameter"""
        if not severity:
            return True, None, ""

        if severity not in self.valid_severities:
            return False, None, f"Invalid severity. Valid values: {', '.join(self.valid_severities)}"

        return True, severity, ""

    def get_data(self, *args, **kwargs):
        """Retrieve violations with pagination and sorting"""
        try:
            # Get request parameters
            params = self.get_request_params(*args, **kwargs)

            page = params.get('page')
            page_size = params.get('page_size')
            sort_by = params.get('sort_by')
            sort_order = params.get('sort_order')
            severity = params.get('severity')

            # Validate pagination parameters
            is_valid, message, page, page_size = PageValidator().validate_pagination_params(page, page_size)
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': message}

            # Validate sort parameters
            is_valid, message = SortValidator().validate_sort_params(['violation_code', 'violation_name', 'severity', 'category', 'created_at'], sort_by, sort_order)
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': message}

            # Validate severity filter
            is_valid, severity_value, message = self.validate_severity(severity)
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': message}

            # Build base query
            query = PolicyViolation.objects.all()

            # Filter by severity if provided
            if severity_value:
                query = query.filter(severity=severity_value)

            # Get total count before pagination
            total_count = query.count()

            # Apply sorting (Django uses '-' prefix for descending)
            if sort_order == 'desc':
                sort_field = f'-{sort_by}'
            else:
                sort_field = sort_by

            query = query.order_by(sort_field)

            # Calculate pagination
            start_index = (page - 1) * page_size
            end_index = start_index + page_size

            # Apply pagination
            violations = query[start_index:end_index]

            # Build response data
            violations_data = []
            for violation in violations:
                violations_data.append({
                    'id': violation.id,
                    'violation_code': violation.violation_code,
                    'violation_name': violation.violation_name,
                    'severity': violation.severity,
                    'category': violation.category,
                    'created_at': violation.created_at.isoformat() if violation.created_at else None,
                })

            # Calculate total pages
            total_pages = (total_count + page_size - 1) // page_size

            return {
                'data': violations_data,
                'pagination': {
                    'total': total_count,
                    'page': page,
                    'page_size': page_size,
                    'total_pages': total_pages
                },
                'sorting': {
                    'sort_by': sort_by,
                    'sort_order': sort_order
                }
            }

        except Exception as e:
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE