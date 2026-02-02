import requests
from rest_framework import status

from password_manager.commons.generic_constants import GenericConstants
from password_manager_admin.services.service_helper.password_admin_manager_service_helper import \
    PasswordAdminManagerServiceHelper


class GetBreachDetailsService(PasswordAdminManagerServiceHelper):
    """Service for fetching specific breach details from Have I Been Pwned API"""

    HIBP_API_BASE_URL = "https://haveibeenpwned.com/api/v3/breach"

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        """Extract and clean request parameters"""
        data = kwargs.get('data', {})

        return {
            'breach_name': data.get('breach_name', '').strip() if data.get('breach_name') else None
        }

    def get_data(self, *args, **kwargs):
        """Fetch specific breach details from HIBP API"""
        try:
            params = self.get_request_params(*args, **kwargs)

            # Validate breach_name
            if not params['breach_name']:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'Breach name is required'}

            # Build API URL with breach name
            api_url = f"{self.HIBP_API_BASE_URL}/{params['breach_name']}"

            # Set required headers for HIBP API
            headers = {
                'User-Agent': 'PasswordManager-Admin-Panel',
                'Accept': 'application/json'
            }

            # Make request to HIBP API
            try:
                response = requests.get(
                    api_url,
                    headers=headers,
                    timeout=10
                )

                # Check if request was successful
                if response.status_code == 200:
                    breach_data = response.json()

                    # Transform data to our format
                    breach_details = {
                        'name': breach_data.get('Name'),
                        'title': breach_data.get('Title'),
                        'domain': breach_data.get('Domain'),
                        'breach_date': breach_data.get('BreachDate'),
                        'added_date': breach_data.get('AddedDate'),
                        'modified_date': breach_data.get('ModifiedDate'),
                        'pwn_count': breach_data.get('PwnCount'),
                        'description': breach_data.get('Description'),
                        'data_classes': breach_data.get('DataClasses', []),
                        'is_verified': breach_data.get('IsVerified'),
                        'is_fabricated': breach_data.get('IsFabricated'),
                        'is_sensitive': breach_data.get('IsSensitive'),
                        'is_retired': breach_data.get('IsRetired'),
                        'is_spam_list': breach_data.get('IsSpamList'),
                        'logo_path': breach_data.get('LogoPath')
                    }

                    return {
                        'message': 'Breach details retrieved successfully from HIBP',
                        'data': breach_details
                    }

                elif response.status_code == 404:
                    # Breach not found
                    self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                    return {'message': f'Breach "{params["breach_name"]}" not found in HIBP database'}

                elif response.status_code == 429:
                    # Rate limit exceeded
                    self.set_status_code(status_code=status.HTTP_429_TOO_MANY_REQUESTS)
                    return {'message': 'Rate limit exceeded. Please try again later'}

                else:
                    # Other error from HIBP API
                    self.set_status_code(status_code=status.HTTP_502_BAD_GATEWAY)
                    return {'message': f'HIBP API error: {response.status_code}'}

            except requests.exceptions.Timeout:
                self.set_status_code(status_code=status.HTTP_504_GATEWAY_TIMEOUT)
                return {'message': 'Request to HIBP API timed out. Please try again'}

            except requests.exceptions.ConnectionError:
                self.set_status_code(status_code=status.HTTP_503_SERVICE_UNAVAILABLE)
                return {'message': 'Unable to connect to HIBP API. Please check your internet connection'}

            except requests.exceptions.RequestException as e:
                self.set_status_code(status_code=status.HTTP_502_BAD_GATEWAY)
                return {'message': f'Error connecting to HIBP API: {str(e)}'}

        except Exception as e:
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE