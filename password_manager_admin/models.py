from django.core.validators import MinValueValidator, MaxValueValidator
from django.db import models


class AdminUsers(models.Model):
    id = models.BigAutoField(primary_key=True)
    username = models.CharField(max_length=100, unique=True, null=False)
    first_name = models.CharField(max_length=100, null=False)
    last_name = models.CharField(max_length=100, null=False)
    email = models.CharField(max_length=255, unique=True, null=False)
    password = models.CharField(max_length=255, null=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "admin_users"

class PasswordPolicy(models.Model):
    COMPLEXITY_CHOICES = [
        (2, 'Medium - 2 character types required'),
        (3, 'High - 3 character types required'),
        (4, 'Very High - All 4 character types required'),
    ]
    id = models.BigAutoField(primary_key=True)
    policy_name = models.CharField(max_length=255, unique=True)
    description = models.TextField()
    min_length = models.IntegerField(default=8, validators=[MinValueValidator(4)])
    max_length = models.IntegerField(default=128, validators=[MaxValueValidator(256)])
    require_uppercase = models.BooleanField(default=True)
    require_lowercase = models.BooleanField(default=True)
    require_digits = models.BooleanField(default=True)
    require_special_chars = models.BooleanField(default=True)
    min_complexity_types = models.IntegerField(default=3, choices=COMPLEXITY_CHOICES, validators=[MinValueValidator(2), MaxValueValidator(4)])
    reject_dictionary_words = models.BooleanField(default=True)
    max_age_days = models.IntegerField(default=90, validators=[MinValueValidator(0)])
    min_rotation_days = models.IntegerField(default=1, validators=[MinValueValidator(0)])
    history_count = models.IntegerField(default=5, validators=[MinValueValidator(0)])
    exclude_username = models.BooleanField(default=True)
    exclude_name = models.BooleanField(default=True)
    exclude_email = models.BooleanField(default=True)
    special_chars_allowed = models.CharField(max_length=100, default="!@#$%^&*-_=+[]{}|;:,.<>?")
    special_chars_required = models.CharField(max_length=100, blank=True)
    status = models.IntegerField(default=1, null=False, blank=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "password_policy"
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.policy_name} (min_length: {self.min_length}, complexity: {self.min_complexity_types})"

class PolicyViolation(models.Model):
    SEVERITY_CHOICES = [
        ('LOW', 'Low - Minor issue'),
        ('MEDIUM', 'Medium - Should be fixed'),
        ('HIGH', 'High - Must be fixed'),
        ('CRITICAL', 'Critical - Security risk'),
    ]

    CATEGORY_CHOICES = [
        ('LENGTH', 'Password Length'),
        ('COMPLEXITY', 'Character Complexity'),
        ('PATTERNS', 'Pattern Detection'),
        ('HISTORY', 'Password History'),
        ('PERSONAL_INFO', 'Personal Information'),
    ]
    id = models.BigAutoField(primary_key=True)
    violation_code = models.CharField(max_length=50, unique=True)
    violation_name = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "policy_violation"
        ordering = ['category', '-severity']
        indexes = [
            models.Index(fields=['violation_code']),
            models.Index(fields=['category']),
        ]

    def __str__(self):
        return f"{self.violation_code} - {self.violation_name} ({self.severity})"


class BreachDatabase(models.Model):
    AUTH_METHOD_CHOICES = [
        ('NONE', 'No Authentication'),
        ('API_KEY', 'API Key'),
        ('OAUTH', 'OAuth'),
        ('BASIC', 'Basic Auth'),
    ]

    HASH_FORMAT_CHOICES = [
        ('SHA1', 'SHA-1'),
        ('SHA256', 'SHA-256'),
        ('MD5', 'MD5'),
    ]

    id = models.BigAutoField(primary_key=True)
    source_name = models.CharField(max_length=255, unique=True)
    source_url = models.URLField()
    total_hashes = models.BigIntegerField(default=0)
    last_updated = models.DateTimeField(null=True, blank=True)
    next_update_scheduled = models.DateTimeField(null=True, blank=True)
    api_key = models.CharField(max_length=500, blank=True, null=True)
    authentication_method = models.CharField(max_length=20, choices=AUTH_METHOD_CHOICES, default='NONE')
    hash_format = models.CharField(max_length=20, choices=HASH_FORMAT_CHOICES, default='SHA1')
    description = models.TextField()
    data_storage_path = models.CharField(max_length=500, blank=True, null=True)
    status = models.IntegerField(default=1, null=False, blank=False)  # ADD THIS LINE
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "breach_database"
        ordering = ['-last_updated']
        indexes = [
            models.Index(fields=['status']),
            models.Index(fields=['source_name']),
        ]

    def __str__(self):
        return f"{self.source_name} - {self.total_hashes:,} hashes"


from django.core.validators import MinValueValidator
from django.db import models


class BreachedPasswordHash(models.Model):
    SEVERITY_CHOICES = [
        ('LOW', 'Found 1-10 times'),
        ('MEDIUM', 'Found 11-100 times'),
        ('HIGH', 'Found 101-1000 times'),
        ('CRITICAL', 'Found 1000+ times'),
    ]

    HASH_FORMAT_CHOICES = [
        ('SHA1', 'SHA-1'),
        ('SHA256', 'SHA-256'),
        ('MD5', 'MD5'),
    ]

    id = models.BigAutoField(primary_key=True)
    password_hash = models.CharField(max_length=256, db_index=True)
    hash_format = models.CharField(max_length=20, choices=HASH_FORMAT_CHOICES, default='SHA1')
    breach_database = models.ForeignKey(BreachDatabase, on_delete=models.CASCADE)
    occurrence_count = models.IntegerField(default=1, validators=[MinValueValidator(1)])
    first_seen_date = models.DateField(null=True, blank=True)
    last_updated = models.DateTimeField(auto_now=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='LOW')
    is_indexed = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)  # FIXED: Changed from auto_now_add to auto_now

    class Meta:
        db_table = "breached_password_hash"
        unique_together = ['password_hash', 'breach_database']
        ordering = ['-occurrence_count']
        indexes = [
            models.Index(fields=['password_hash']),
            models.Index(fields=['breach_database', 'occurrence_count']),
            models.Index(fields=['severity']),
        ]  # FIXED: Added closing bracket

    def __str__(self):
        return f"{self.password_hash[:10]}... ({self.occurrence_count} occurrences)"

    def calculate_severity(self):
        """Auto-calculate severity based on occurrence count"""
        if self.occurrence_count >= 1000:
            return 'CRITICAL'
        elif self.occurrence_count >= 101:
            return 'HIGH'
        elif self.occurrence_count >= 11:
            return 'MEDIUM'
        else:
            return 'LOW'

    def save(self, *args, **kwargs):
        """Auto-calculate severity before saving"""
        if not self.severity or self.severity == 'LOW':
            self.severity = self.calculate_severity()
        super().save(*args, **kwargs)


class AdminSecurityAuditLog(models.Model):
    ACTION_CHOICES = [
        ('POLICY_CREATE', 'Policy Created'),
        ('POLICY_UPDATE', 'Policy Updated'),
        ('POLICY_DELETE', 'Policy Deleted'),
        ('POLICY_ASSIGN', 'Policy Assigned'),
        ('BREACH_DB_UPDATE', 'Breach Database Updated'),
        ('BREACH_DB_CONFIG', 'Breach Database Configured'),
        ('WORDLIST_UPDATE', 'Wordlist Updated'),
        ('CONFIG_UPDATE', 'Configuration Updated'),
        ('ALERT_ACKNOWLEDGE', 'Alert Acknowledged'),
    ]

    RESOURCE_CHOICES = [
        ('POLICY', 'Policy'),
        ('BREACH_DB', 'Breach Database'),
        ('CONFIGURATION', 'Configuration'),
        ('WORDLIST', 'Wordlist'),
        ('PATTERN', 'Pattern'),
    ]

    STATUS_CHOICES = [
        ('SUCCESS', 'Success'),
        ('FAILURE', 'Failure'),
    ]

    SEVERITY_CHOICES = [
        ('INFO', 'Information'),
        ('WARNING', 'Warning'),
        ('ERROR', 'Error'),
        ('CRITICAL', 'Critical'),
    ]

    id = models.BigAutoField(primary_key=True)
    admin_user = models.ForeignKey(AdminUsers, on_delete=models.CASCADE)
    action_type = models.CharField(max_length=30, choices=ACTION_CHOICES)
    action_details = models.JSONField(default=dict, blank=True)
    resource_type = models.CharField(max_length=30, choices=RESOURCE_CHOICES)
    resource_id = models.CharField(max_length=100, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.CharField(max_length=45, blank=True)
    user_agent = models.CharField(max_length=500, blank=True)
    error_details = models.TextField(blank=True)
    severity_level = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='INFO')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "admin_security_audit_log"
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['admin_user', '-timestamp']),
            models.Index(fields=['action_type']),
            models.Index(fields=['status']),
        ]

    def __str__(self):
        return f"{self.admin_user.username} - {self.get_action_type_display()}"


class AdminAnomalyAlert(models.Model):
    ALERT_TYPE_CHOICES = [
        ('MASS_WEAK_PASSWORDS', 'Mass Weak Passwords Detected'),
        ('BREACH_SPIKE', 'Breach Detection Spike'),
        ('POLICY_VIOLATIONS', 'Policy Violation Rate High'),
        ('UNUSUAL_PATTERN', 'Unusual System Activity'),
    ]

    SEVERITY_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]

    id = models.BigAutoField(primary_key=True)
    alert_type = models.CharField(max_length=50, choices=ALERT_TYPE_CHOICES)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    description = models.TextField()
    affected_count = models.IntegerField(default=0)
    details = models.JSONField(default=dict, blank=True)
    is_acknowledged = models.BooleanField(default=False)
    acknowledged_by = models.ForeignKey(AdminUsers, on_delete=models.SET_NULL, null=True, blank=True)
    acknowledgment_time = models.DateTimeField(null=True, blank=True)
    action_taken = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "admin_anomaly_alert"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['alert_type']),
            models.Index(fields=['severity']),
            models.Index(fields=['is_acknowledged']),
        ]

    def __str__(self):
        return f"{self.get_alert_type_display()} - {self.severity}"


class AnalyzerConfiguration(models.Model):
    VALUE_TYPE_CHOICES = [
        ('STRING', 'String'),
        ('INTEGER', 'Integer'),
        ('BOOLEAN', 'Boolean'),
        ('JSON', 'JSON'),
    ]

    id = models.BigAutoField(primary_key=True)
    config_key = models.CharField(max_length=255, unique=True)
    config_value = models.TextField()
    value_type = models.CharField(max_length=20, choices=VALUE_TYPE_CHOICES, default='STRING')
    description = models.TextField(blank=True)
    is_sensitive = models.BooleanField(default=False)
    admin_user = models.ForeignKey(AdminUsers, on_delete=models.SET_DEFAULT, default=1, null=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "analyzer_configuration"
        ordering = ['config_key']
        indexes = [
            models.Index(fields=['config_key']),
        ]

    def __str__(self):
        return f"{self.config_key}"


class DictionaryWordlist(models.Model):
    WORDLIST_TYPE_CHOICES = [
        ('COMMON', 'Common Passwords'),
        ('DICTIONARY', 'Dictionary Words'),
        ('PATTERNS', 'Common Patterns'),
        ('CUSTOM', 'Custom Wordlist'),
    ]

    id = models.BigAutoField(primary_key=True)
    wordlist_name = models.CharField(max_length=255, unique=True)
    wordlist_type = models.CharField(max_length=50, choices=WORDLIST_TYPE_CHOICES)
    description = models.TextField()
    word_count = models.IntegerField(default=0)
    file_path = models.CharField(max_length=500)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "dictionary_wordlist"
        ordering = ['wordlist_name']
        indexes = [
            models.Index(fields=['is_active']),
            models.Index(fields=['wordlist_type']),
        ]

    def __str__(self):
        return f"{self.wordlist_name}"


class KeyboardPattern(models.Model):
    PATTERN_TYPE_CHOICES = [
        ('QWERTY', 'QWERTY Layout'),
        ('DVORAK', 'Dvorak Layout'),
        ('NUMPAD', 'Number Pad'),
        ('CUSTOM', 'Custom Pattern'),
    ]

    RISK_LEVEL_CHOICES = [
        ('LOW', 'Low Risk'),
        ('MEDIUM', 'Medium Risk'),
        ('HIGH', 'High Risk'),
    ]

    id = models.BigAutoField(primary_key=True)
    pattern_name = models.CharField(max_length=255, unique=True)
    pattern_string = models.CharField(max_length=500)
    pattern_type = models.CharField(max_length=20, choices=PATTERN_TYPE_CHOICES)
    is_active = models.BooleanField(default=True)
    risk_level = models.CharField(max_length=20, choices=RISK_LEVEL_CHOICES, default='MEDIUM')
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "keyboard_pattern"
        ordering = ['pattern_type', 'pattern_name']
        indexes = [
            models.Index(fields=['is_active']),
            models.Index(fields=['risk_level']),
        ]

    def __str__(self):
        return f"{self.pattern_name}"
