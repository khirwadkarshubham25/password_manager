import requests
from rest_framework import status

from password_manager.commons.generic_constants import GenericConstants
from password_manager_admin.services.service_helper.password_admin_manager_service_helper import \
    PasswordAdminManagerServiceHelper


class GetBreachesService(PasswordAdminManagerServiceHelper):
    """Service for fetching breach list from Have I Been Pwned API"""

    HIBP_API_URL = "https://haveibeenpwned.com/api/v3/breaches"

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        """Extract and clean request parameters"""
        data = kwargs.get('data', {})

        return {
            'domain': data.get('domain', '').strip() if data.get('domain') else None
        }

    def get_data(self, *args, **kwargs):
        """Fetch breaches from HIBP API"""
        try:
            params = self.get_request_params(*args, **kwargs)

            # Build API URL
            api_url = self.HIBP_API_URL
            query_params = {}

            # Add domain filter if provided
            if params['domain']:
                query_params['domain'] = params['domain']

            # Set required headers for HIBP API
            headers = {
                'User-Agent': 'PasswordManager-Admin-Panel',
                'Accept': 'application/json'
            }

            # Make request to HIBP API
            try:
                response = requests.get(
                    api_url,
                    params=query_params,
                    headers=headers,
                    timeout=10
                )

                # Check if request was successful
                if response.status_code == 200:
                    breaches_data = response.json()

                    # Transform data to our format
                    breaches = [
                        {
                            'name': breach.get('Name'),
                            'title': breach.get('Title'),
                            'domain': breach.get('Domain'),
                            'breach_date': breach.get('BreachDate'),
                            'added_date': breach.get('AddedDate'),
                            'modified_date': breach.get('ModifiedDate'),
                            'pwn_count': breach.get('PwnCount'),
                            'description': breach.get('Description'),
                            'data_classes': breach.get('DataClasses', []),
                            'is_verified': breach.get('IsVerified'),
                            'is_fabricated': breach.get('IsFabricated'),
                            'is_sensitive': breach.get('IsSensitive'),
                            'is_retired': breach.get('IsRetired'),
                            'is_spam_list': breach.get('IsSpamList'),
                            'logo_path': breach.get('LogoPath')
                        }
                        for breach in breaches_data
                    ]

                    return {
                        'message': 'Breaches retrieved successfully from HIBP',
                        'data': breaches,
                        'total': len(breaches)
                    }

                elif response.status_code == 404:
                    # No breaches found for domain
                    return {
                        'message': 'No breaches found',
                        'data': [],
                        'total': 0
                    }

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