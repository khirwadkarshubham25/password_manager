import math
import re
import sys
import traceback

from rest_framework import status

from accounts.models import Users
from admin_panel.models import PolicyAssignment, PolicyViolation
from password_manager.commons.generic_constants import GenericConstants
from password_manager.services.crypto_service import CryptoService
from vault.models import UserPasswordHistory
from vault.services.service_helper.vault_service_helper import VaultServiceHelper


class PasswordPolicyViolationCreateService(VaultServiceHelper):

    # Default policy applied when no policy is assigned to the user
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
        'history_count':          0,
        'exclude_username':       False,
        'exclude_name':           False,
        'exclude_email':          True,
        'min_entropy_score':      0.0,
    }

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        data = kwargs.get('data', {})
        return {
            'user_id':          data.get('user_id', ''),
            'password':         data.get('password', ''),
            # Optional — only needed for history / personal info checks
            'user_password_id': data.get('user_password_id', None)
        }

    # -----------------------------------------------------------------------
    # Entropy calculation
    # -----------------------------------------------------------------------

    @staticmethod
    def calculate_entropy(password: str) -> float:
        """Shannon entropy: measures unpredictability of the password."""
        if not password:
            return 0.0
        freq = {}
        for ch in password:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(password)
        entropy = -sum((c / length) * math.log2(c / length) for c in freq.values())
        return round(entropy * length, 2)

    # -----------------------------------------------------------------------
    # Individual rule checks — each returns a violation_code or None
    # -----------------------------------------------------------------------

    @staticmethod
    def check_length(password: str, min_len: int, max_len: int) -> list:
        violations = []
        if len(password) < min_len:
            violations.append('PWD_TOO_SHORT')
        if len(password) > max_len:
            violations.append('PWD_TOO_LONG')
        return violations

    @staticmethod
    def check_uppercase(password: str) -> str | None:
        return 'PWD_NO_UPPERCASE' if not re.search(r'[A-Z]', password) else None

    @staticmethod
    def check_lowercase(password: str) -> str | None:
        return 'PWD_NO_LOWERCASE' if not re.search(r'[a-z]', password) else None

    @staticmethod
    def check_digits(password: str) -> str | None:
        return 'PWD_NO_DIGIT' if not re.search(r'\d', password) else None

    @staticmethod
    def check_special_chars(password: str, allowed: str, required: str) -> list:
        violations = []
        if not re.search(rf'[{re.escape(allowed)}]', password):
            violations.append('PWD_NO_SPECIAL_CHAR')
        if required:
            for ch in required:
                if ch not in password:
                    violations.append('PWD_MISSING_REQUIRED_CHAR')
                    break
        return violations

    @staticmethod
    def check_complexity(password: str, min_types: int) -> str | None:
        types_present = sum([
            bool(re.search(r'[A-Z]',          password)),
            bool(re.search(r'[a-z]',          password)),
            bool(re.search(r'\d',             password)),
            bool(re.search(r'[^A-Za-z0-9]',  password)),
        ])
        return 'PWD_LOW_COMPLEXITY' if types_present < min_types else None

    @staticmethod
    def check_entropy(password: str, min_entropy: float) -> str | None:
        if min_entropy <= 0:
            return None
        freq   = {}
        for ch in password:
            freq[ch] = freq.get(ch, 0) + 1
        length  = len(password)
        entropy = -sum((c / length) * math.log2(c / length) for c in freq.values()) * length
        return 'PWD_LOW_ENTROPY' if entropy < min_entropy else None

    @staticmethod
    def check_personal_info(password: str, user: Users, policy: dict) -> list:
        violations = []
        pwd_lower  = password.lower()

        if policy.get('exclude_email') and user.email:
            local_part = user.email.split('@')[0].lower()
            if local_part and local_part in pwd_lower:
                violations.append('PWD_CONTAINS_EMAIL')

        if policy.get('exclude_name'):
            if user.first_name and len(user.first_name) > 2:
                if user.first_name.lower() in pwd_lower:
                    violations.append('PWD_CONTAINS_NAME')
            if user.last_name and len(user.last_name) > 2:
                if user.last_name.lower() in pwd_lower:
                    violations.append('PWD_CONTAINS_NAME')

        return violations

    @staticmethod
    def check_history(
        password: str,
        user: Users,
        user_password_id,
        history_count: int
    ) -> str | None:
        if history_count <= 0 or not user_password_id:
            return None

        try:
            recent_history = UserPasswordHistory.objects.filter(
                user_password_id=user_password_id
            ).order_by('-changed_at')[:history_count]

            for record in recent_history:
                try:
                    decrypted = CryptoService.decrypt_password(
                        record.encrypted_password,
                        user.password
                    )
                    if decrypted == password:
                        return 'PWD_REUSED'
                except Exception:
                    continue
        except Exception:
            pass

        return None

    # -----------------------------------------------------------------------
    # Resolve violation_codes → save PolicyViolation records + return details
    # -----------------------------------------------------------------------

    @staticmethod
    def resolve_violations(violation_codes: list, user) -> list:
        VIOLATION_META = {
            'PWD_TOO_SHORT':              ('Password Too Short',              'LOW',    'LENGTH'),
            'PWD_TOO_LONG':               ('Password Too Long',               'LOW',    'LENGTH'),
            'PWD_NO_UPPERCASE':           ('No Uppercase Letter',             'MEDIUM', 'COMPLEXITY'),
            'PWD_NO_LOWERCASE':           ('No Lowercase Letter',             'MEDIUM', 'COMPLEXITY'),
            'PWD_NO_DIGIT':               ('No Digit',                        'MEDIUM', 'COMPLEXITY'),
            'PWD_NO_SPECIAL_CHAR':        ('No Special Character',            'MEDIUM', 'COMPLEXITY'),
            'PWD_MISSING_REQUIRED_CHAR':  ('Missing Required Character',      'MEDIUM', 'COMPLEXITY'),
            'PWD_LOW_COMPLEXITY':         ('Insufficient Complexity',         'HIGH',   'COMPLEXITY'),
            'PWD_LOW_ENTROPY':            ('Low Entropy',                     'HIGH',   'COMPLEXITY'),
            'PWD_CONTAINS_EMAIL':         ('Password Contains Email',         'HIGH',   'PERSONAL_INFO'),
            'PWD_CONTAINS_NAME':          ('Password Contains Name',          'HIGH',   'PERSONAL_INFO'),
            'PWD_REUSED':                 ('Password Recently Used',          'HIGH',   'HISTORY'),
        }

        results = []
        for code in violation_codes:
            meta = VIOLATION_META.get(code)
            violation_name = meta[0] if meta else code
            severity       = meta[1] if meta else 'MEDIUM'
            category       = meta[2] if meta else 'COMPLEXITY'

            try:
                PolicyViolation.objects.create(
                    user=user,
                    violation_code=code,
                    violation_name=violation_name,
                    description='',
                    severity=severity,
                    category=category
                )
            except Exception:
                traceback.print_exc(file=sys.stdout)

            results.append({
                'violation_code': code,
                'violation_name': violation_name,
                'severity':       severity,
                'category':       category
            })

        return results

    # -----------------------------------------------------------------------
    # Main
    # -----------------------------------------------------------------------

    def get_data(self, *args, **kwargs):
        try:
            params = self.get_request_params(*args, **kwargs)

            is_valid, error = self.is_valid_parameters(
                params,
                required_fields=['user_id', 'password']
            )
            if not is_valid:
                self.set_status_code(status_code=status.HTTP_400_BAD_REQUEST)
                return error

            try:
                user = Users.objects.get(id=params['user_id'])
            except Users.DoesNotExist:
                self.set_status_code(status_code=status.HTTP_404_NOT_FOUND)
                return {'message': GenericConstants.USER_NOT_FOUND}

            # ---------------------------------------------------------------
            # Resolve policy — assigned or default
            # ---------------------------------------------------------------
            policy         = None
            policy_name    = 'Default Policy'
            policy_id      = None
            assignment     = PolicyAssignment.objects.filter(
                user_id=params['user_id']
            ).select_related('policy').first()

            if assignment and assignment.policy.status == 1:
                p           = assignment.policy
                policy_id   = p.id
                policy_name = p.policy_name
                policy      = {
                    'min_length':             p.min_length,
                    'max_length':             p.max_length,
                    'require_uppercase':      p.require_uppercase,
                    'require_lowercase':      p.require_lowercase,
                    'require_digits':         p.require_digits,
                    'require_special_chars':  p.require_special_chars,
                    'special_chars_allowed':  p.special_chars_allowed,
                    'special_chars_required': p.special_chars_required,
                    'min_complexity_types':   p.min_complexity_types,
                    'history_count':          p.history_count,
                    'exclude_username':       p.exclude_username,
                    'exclude_name':           p.exclude_name,
                    'exclude_email':          p.exclude_email,
                    'min_entropy_score':      p.min_entropy_score,
                }
            else:
                policy = self.DEFAULT_POLICY

            password         = params['password']
            violation_codes  = []

            # ---------------------------------------------------------------
            # Run all checks
            # ---------------------------------------------------------------

            # Length
            violation_codes.extend(
                self.check_length(password, policy['min_length'], policy['max_length'])
            )

            # Uppercase
            if policy['require_uppercase']:
                code = self.check_uppercase(password)
                if code:
                    violation_codes.append(code)

            # Lowercase
            if policy['require_lowercase']:
                code = self.check_lowercase(password)
                if code:
                    violation_codes.append(code)

            # Digits
            if policy['require_digits']:
                code = self.check_digits(password)
                if code:
                    violation_codes.append(code)

            # Special characters
            if policy['require_special_chars']:
                violation_codes.extend(
                    self.check_special_chars(
                        password,
                        policy['special_chars_allowed'],
                        policy['special_chars_required']
                    )
                )

            # Complexity
            code = self.check_complexity(password, policy['min_complexity_types'])
            if code:
                violation_codes.append(code)

            # Entropy
            code = self.check_entropy(password, policy['min_entropy_score'])
            if code:
                violation_codes.append(code)

            # Personal info
            violation_codes.extend(
                self.check_personal_info(password, user, policy)
            )

            # History
            code = self.check_history(
                password,
                user,
                params['user_password_id'],
                policy['history_count']
            )
            if code:
                violation_codes.append(code)

            # ---------------------------------------------------------------
            # Deduplicate and resolve
            # ---------------------------------------------------------------
            violation_codes = list(dict.fromkeys(violation_codes))

            if not violation_codes:
                self.set_status_code(status_code=status.HTTP_200_OK)
                return {
                    'violated':    False,
                    'message':     'Password meets all policy requirements.',
                    'policy_id':   policy_id,
                    'policy_name': policy_name
                }

            violations = self.resolve_violations(violation_codes, user=user)

            self.set_status_code(status_code=status.HTTP_200_OK)
            return {
                'violated':        True,
                'message':         'Password violates one or more policy rules.',
                'policy_id':       policy_id,
                'policy_name':     policy_name,
                'violation_count': len(violations),
                'violations':      violations
            }

        except Exception:
            traceback.print_exc(file=sys.stdout)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE