import hashlib
import sys
import traceback
from datetime import date

import requests
from rest_framework import status

from admin_panel.models import BreachDatabase, BreachedPasswordHash
from vault.services.service_helper.vault_service_helper import VaultServiceHelper
from password_manager.commons.generic_constants import GenericConstants


class BreachedPasswordHashCreateService(VaultServiceHelper):

    def __init__(self):
        super().__init__()

    def get_request_params(self, *args, **kwargs):
        data = kwargs.get('data', {})
        return {
            'user_id':  data.get('user_id', ''),
            'password': data.get('password', '')
        }

    # -----------------------------------------------------------------------
    # Hashing helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def hash_password(plaintext: str, hash_format: str) -> str:
        encoded = plaintext.encode('utf-8')
        if hash_format == 'SHA1':
            return hashlib.sha1(encoded).hexdigest().upper()
        elif hash_format == 'SHA256':
            return hashlib.sha256(encoded).hexdigest().upper()
        elif hash_format == 'MD5':
            return hashlib.md5(encoded).hexdigest().upper()
        return hashlib.sha1(encoded).hexdigest().upper()

    @staticmethod
    def resolve_severity(occurrence_count: int) -> str:
        if occurrence_count <= 10:
            return 'LOW'
        elif occurrence_count <= 100:
            return 'MEDIUM'
        elif occurrence_count <= 1000:
            return 'HIGH'
        return 'CRITICAL'

    # -----------------------------------------------------------------------
    # HIBP k-Anonymity check
    # -----------------------------------------------------------------------

    @staticmethod
    def check_hibp(url, plaintext: str) -> tuple[bool, int]:
        """
        Check password against HIBP using k-Anonymity.
        Sends only the first 5 chars of the SHA-1 hash.
        Returns (is_breached, occurrence_count).
        """
        sha1      = hashlib.sha1(plaintext.encode('utf-8')).hexdigest().upper()
        prefix    = sha1[:5]
        suffix    = sha1[5:]

        response = requests.get(
            url.format(prefix=prefix),
            headers={'Add-Padding': 'true'},
            timeout=5
        )
        response.raise_for_status()

        for line in response.text.splitlines():
            hash_suffix, _, count = line.partition(':')
            if hash_suffix.strip() == suffix:
                return True, int(count.strip())

        return False, 0

    @staticmethod
    def is_hibp_source(source_url: str) -> bool:
        if not source_url:
            return False
        url_lower = source_url.lower()
        return 'haveibeenpwned.com' in url_lower or 'pwnedpasswords.com' in url_lower

    # -----------------------------------------------------------------------
    # Generic external API check
    # -----------------------------------------------------------------------

    @staticmethod
    def check_external_api(db: BreachDatabase, password_hash: str) -> tuple[bool, int]:
        """
        Call a generic external breach API.
        Sends the password hash and expects a JSON response with
        'breached' (bool) and optionally 'occurrence_count' (int).
        """
        headers = {'Content-Type': 'application/json'}

        if db.authentication_method == 'API_KEY' and db.api_key:
            headers['Authorization'] = f'Bearer {db.api_key}'
        elif db.authentication_method == 'BASIC' and db.api_key:
            headers['Authorization'] = f'Basic {db.api_key}'

        response = requests.post(
            db.source_url,
            json={'hash': password_hash, 'hash_format': db.hash_format},
            headers=headers,
            timeout=5
        )
        response.raise_for_status()

        data = response.json()
        is_breached      = bool(data.get('breached', False))
        occurrence_count = int(data.get('occurrence_count', 1)) if is_breached else 0

        return is_breached, occurrence_count

    # -----------------------------------------------------------------------
    # Persist breach record
    # -----------------------------------------------------------------------

    def record_breach(self, db: BreachDatabase, password_hash: str, occurrence_count: int):
        severity = self.resolve_severity(occurrence_count)

        breached_hash, created = BreachedPasswordHash.objects.get_or_create(
            password_hash=password_hash,
            breach_database=db,
            defaults={
                'hash_format':      db.hash_format,
                'occurrence_count': occurrence_count,
                'severity':         severity,
                'first_seen_date':  date.today(),
                'is_indexed':       True
            }
        )

        if not created:
            breached_hash.occurrence_count = occurrence_count
            breached_hash.severity         = severity
            breached_hash.save(update_fields=['occurrence_count', 'severity', 'updated_at'])

        return severity

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

            active_databases = BreachDatabase.objects.filter(status=1)

            if not active_databases.exists():
                self.set_status_code(status_code=status.HTTP_200_OK)
                return {
                    'breached': False,
                    'message':  'No active breach databases available to check against.'
                }

            breached_entries  = []
            checked_databases = 0

            for db in active_databases:
                try:
                    password_hash = self.hash_password(params['password'], db.hash_format)

                    # ---------------------------------------------------
                    # Step 1: check our BreachedPasswordHash table first
                    # ---------------------------------------------------
                    existing = BreachedPasswordHash.objects.filter(
                        password_hash=password_hash,
                        breach_database=db
                    ).first()

                    if existing:
                        breached_entries.append({
                            'breach_database_id': db.id,
                            'source_name':        db.source_name,
                            'hash_format':        db.hash_format,
                            'occurrence_count':   existing.occurrence_count,
                            'severity':           existing.severity,
                            'source':             'local'
                        })
                        checked_databases += 1
                        continue

                    # ---------------------------------------------------
                    # Step 2: not in our table — call the external API
                    # ---------------------------------------------------
                    is_breached      = False
                    occurrence_count = 0

                    if self.is_hibp_source(db.source_url):
                        is_breached, occurrence_count = self.check_hibp(db.source_url, params['password'])
                    elif db.source_url and db.authentication_method != 'NONE':
                        is_breached, occurrence_count = self.check_external_api(db, password_hash)

                    # ---------------------------------------------------
                    # Step 3: if breached, record it and add to results
                    # ---------------------------------------------------
                    if is_breached:
                        severity = self.record_breach(db, password_hash, occurrence_count)
                        breached_entries.append({
                            'breach_database_id': db.id,
                            'source_name':        db.source_name,
                            'hash_format':        db.hash_format,
                            'occurrence_count':   occurrence_count,
                            'severity':           severity,
                            'source':             'api'
                        })

                    checked_databases += 1

                except Exception:
                    traceback.print_exc(file=sys.stdout)
                    checked_databases += 1
                    continue

            if breached_entries:
                self.set_status_code(status_code=status.HTTP_200_OK)
                return {
                    'breached':          True,
                    'message':           'Password found in breach database(s).',
                    'checked_databases': checked_databases,
                    'breached_in':       breached_entries
                }

            self.set_status_code(status_code=status.HTTP_200_OK)
            return {
                'breached':          False,
                'message':           'Password not found in any breach database.',
                'checked_databases': checked_databases
            }

        except Exception:
            traceback.print_exc(file=sys.stdout)
            self.set_status_code(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return GenericConstants.ERROR_MESSAGE