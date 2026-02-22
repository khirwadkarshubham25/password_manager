import secrets
import string
import sys
import traceback

from rest_framework import status

from accounts.models import Users
from admin_panel.models import PolicyAssignment
from vault.services.service_helper.vault_service_helper import VaultServiceHelper
from password_manager.commons.generic_constants import GenericConstants


class GeneratePasswordService(VaultServiceHelper):

    DEFAULT_POLICY = {
        'min_length':             8,
        'max_length':             128,
        'require_uppercase':      True,
        'require_lowercase':      True,
        'require_digits':         False,
        'require_special_chars':  True,
        'special_chars_allowed':  "!@#$%^&*-_=+[]{}|;:,.<>?",
        'special_chars_required': '',
        'min_complexity_types':   3,
    }

    # Generated password length = min_length + this buffer for comfort
    LENGTH_BUFFER = 4

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        data = kwargs.get('data', {})
        return {
            'user_id': data.get('user_id', '')
        }

    # -----------------------------------------------------------------------
    # Policy resolution
    # -----------------------------------------------------------------------

    def resolve_policy(self, user_id) -> tuple[dict, str, int | None]:
        """
        Returns (policy_dict, policy_name, policy_id).
        Falls back to DEFAULT_POLICY if no active assignment exists.
        """
        assignment = PolicyAssignment.objects.filter(
            user_id=user_id
        ).select_related('policy').first()

        if assignment and assignment.policy.status == 1:
            p = assignment.policy
            return {
                'min_length':             p.min_length,
                'max_length':             p.max_length,
                'require_uppercase':      p.require_uppercase,
                'require_lowercase':      p.require_lowercase,
                'require_digits':         p.require_digits,
                'require_special_chars':  p.require_special_chars,
                'special_chars_allowed':  p.special_chars_allowed,
                'special_chars_required': p.special_chars_required,
                'min_complexity_types':   p.min_complexity_types,
            }, p.policy_name, p.id

        return self.DEFAULT_POLICY, 'Default Policy', None

    # -----------------------------------------------------------------------
    # Password generator
    # -----------------------------------------------------------------------

    @staticmethod
    def generate(policy: dict) -> str:
        uppercase   = string.ascii_uppercase
        lowercase   = string.ascii_lowercase
        digits      = string.digits
        special     = policy['special_chars_allowed'] or "!@#$%^&*-_=+[]{}|;:,.<>?"

        # Build the full character pool from enabled character types
        pool = ''
        guaranteed = []

        if policy['require_uppercase']:
            pool += uppercase
            guaranteed.append(secrets.choice(uppercase))

        if policy['require_lowercase']:
            pool += lowercase
            guaranteed.append(secrets.choice(lowercase))

        if policy['require_digits']:
            pool += digits
            guaranteed.append(secrets.choice(digits))

        if policy['require_special_chars']:
            pool += special
            guaranteed.append(secrets.choice(special))

        # Any specific chars that must appear
        if policy.get('special_chars_required'):
            for ch in policy['special_chars_required']:
                if ch not in [g for g in guaranteed]:
                    guaranteed.append(ch)
                    if ch not in pool:
                        pool += ch

        # Fallback — if somehow pool is empty, use all printable ASCII
        if not pool:
            pool = string.ascii_letters + string.digits + "!@#$%^&*"
            guaranteed.append(secrets.choice(pool))

        # Target length: min_length + buffer, capped at max_length
        min_len = policy['min_length']
        max_len = policy['max_length']
        target  = min(min_len + GeneratePasswordService.LENGTH_BUFFER, max_len)
        target  = max(target, len(guaranteed))  # ensure guaranteed chars fit

        # Fill remaining slots randomly from pool
        remaining = target - len(guaranteed)
        password_chars = guaranteed + [secrets.choice(pool) for _ in range(remaining)]

        # Shuffle so guaranteed chars aren't always at the front
        secrets.SystemRandom().shuffle(password_chars)

        return ''.join(password_chars)

    # -----------------------------------------------------------------------
    # Main
    # -----------------------------------------------------------------------

    def get_data(self, *args, **kwargs):
        try:
            params = self.get_request_params(*args, **kwargs)

            is_valid, error = self.is_valid_parameters(
                params,
                required_fields=['user_id']
            )
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return error

            try:
                Users.objects.get(id=params['user_id'])
            except Users.DoesNotExist:
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {'message': GenericConstants.USER_NOT_FOUND}

            policy, policy_name, policy_id = self.resolve_policy(params['user_id'])

            password = self.generate(policy)

            self.set_status_code(status_code=status.HTTP_200_OK)
            return {
                'password':    password,
                'length':      len(password),
                'policy_id':   policy_id,
                'policy_name': policy_name
            }

        except Exception:
            traceback.print_exc(file=sys.stdout)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE