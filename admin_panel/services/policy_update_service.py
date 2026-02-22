import sys
import traceback

from rest_framework import status

from admin_panel.models import PasswordPolicy
from admin_panel.services.service_helper.admin_panel_service_helper import AdminPanelServiceHelper
from password_manager.commons.commons import Commons
from password_manager.commons.generic_constants import GenericConstants


class PolicyUpdateService(AdminPanelServiceHelper):

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        data = kwargs.get('data', {})
        return {
            'policy_id': data.get('policy_id'),
            'user_id': data.get('admin_user_id'),
            'policy_name': data.get('policy_name', '').strip() if data.get('policy_name') else None,
            'description': data.get('description', '').strip() if data.get('description') else None,
            'min_length': data.get('min_length'),
            'max_length': data.get('max_length'),
            'require_uppercase': data.get('require_uppercase'),
            'require_lowercase': data.get('require_lowercase'),
            'require_digits': data.get('require_digits'),
            'require_special_chars': data.get('require_special_chars'),
            'min_complexity_types': data.get('min_complexity_types'),
            'reject_dictionary_words': data.get('reject_dictionary_words'),
            'max_age_days': data.get('max_age_days'),
            'min_rotation_days': data.get('min_rotation_days'),
            'history_count': data.get('history_count'),
            'min_entropy_score': data.get('min_entropy_score'),
            'exclude_username': data.get('exclude_username'),
            'exclude_name': data.get('exclude_name'),
            'exclude_email': data.get('exclude_email'),
            'special_chars_allowed': data.get('special_chars_allowed'),
            'special_chars_required': data.get('special_chars_required'),
            'status': data.get('status')
        }

    def get_data(self, *args, **kwargs):
        try:
            params = self.get_request_params(*args, **kwargs)

            if not params['policy_id']:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'Policy ID is required'}

            try:
                policy_id = int(params['policy_id'])
            except (ValueError, TypeError):
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'Invalid policy ID'}

            try:
                policy = PasswordPolicy.objects.get(id=policy_id)
            except PasswordPolicy.DoesNotExist:
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {'message': GenericConstants.POLICY_NOT_FOUND_MESSAGE}

            # Validate updated numeric params only if provided
            update_params = {k: v for k, v in params.items() if k not in ('policy_id', 'user_id') and v is not None}
            if not update_params:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': 'No fields to update. Provide at least one field'}

            is_valid, message = self.validate_policy_params({
                'policy_name': params['policy_name'] or policy.policy_name,
                'min_length': params['min_length'] if params['min_length'] is not None else policy.min_length,
                'max_length': params['max_length'] if params['max_length'] is not None else policy.max_length,
                'min_complexity_types': params['min_complexity_types'] if params['min_complexity_types'] is not None else policy.min_complexity_types,
                'max_age_days': params['max_age_days'] if params['max_age_days'] is not None else policy.max_age_days,
                'min_rotation_days': params['min_rotation_days'] if params['min_rotation_days'] is not None else policy.min_rotation_days,
                'history_count': params['history_count'] if params['history_count'] is not None else policy.history_count,
                'min_entropy_score': params['min_entropy_score'] if params['min_entropy_score'] is not None else policy.min_entropy_score,
            })
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return {'message': message}

            # Check duplicate policy name
            if params['policy_name'] and params['policy_name'] != policy.policy_name:
                if PasswordPolicy.objects.filter(policy_name=params['policy_name']).exclude(id=policy_id).exists():
                    self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                    return {'message': GenericConstants.POLICY_ALREADY_EXISTS_MESSAGE}

            old_values = {
                'policy_name': policy.policy_name,
                'min_length': policy.min_length,
                'max_length': policy.max_length,
                'status': policy.status
            }

            if params['policy_name'] is not None:
                policy.policy_name = params['policy_name']
            if params['description'] is not None:
                policy.description = params['description']
            if params['min_length'] is not None:
                policy.min_length = int(params['min_length'])
            if params['max_length'] is not None:
                policy.max_length = int(params['max_length'])
            if params['require_uppercase'] is not None:
                policy.require_uppercase = params['require_uppercase']
            if params['require_lowercase'] is not None:
                policy.require_lowercase = params['require_lowercase']
            if params['require_digits'] is not None:
                policy.require_digits = params['require_digits']
            if params['require_special_chars'] is not None:
                policy.require_special_chars = params['require_special_chars']
            if params['min_complexity_types'] is not None:
                policy.min_complexity_types = int(params['min_complexity_types'])
            if params['reject_dictionary_words'] is not None:
                policy.reject_dictionary_words = params['reject_dictionary_words']
            if params['max_age_days'] is not None:
                policy.max_age_days = int(params['max_age_days'])
            if params['min_rotation_days'] is not None:
                policy.min_rotation_days = int(params['min_rotation_days'])
            if params['history_count'] is not None:
                policy.history_count = int(params['history_count'])
            if params['min_entropy_score'] is not None:
                policy.min_entropy_score = float(params['min_entropy_score'])
            if params['exclude_username'] is not None:
                policy.exclude_username = params['exclude_username']
            if params['exclude_name'] is not None:
                policy.exclude_name = params['exclude_name']
            if params['exclude_email'] is not None:
                policy.exclude_email = params['exclude_email']
            if params['special_chars_allowed'] is not None:
                policy.special_chars_allowed = params['special_chars_allowed']
            if params['special_chars_required'] is not None:
                policy.special_chars_required = params['special_chars_required']
            if params['status'] is not None:
                policy.status = params['status']

            policy.save()

            Commons.create_audit_log(
                user_id=params.get('user_id'),
                action='update',
                resource_type='password_policy',
                resource_id=policy_id,
                old_values=old_values,
                new_values={
                    'policy_name': policy.policy_name,
                    'min_length': policy.min_length,
                    'max_length': policy.max_length,
                    'status': policy.status
                }
            )

            return {'message': GenericConstants.POLICY_UPDATE_SUCCESSFUL_MESSAGE}

        except Exception:
            traceback.print_exc(file=sys.stdout)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE