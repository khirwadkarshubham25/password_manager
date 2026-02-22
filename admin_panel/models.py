from django.core.validators import MinValueValidator, MaxValueValidator
from django.db import models

from accounts.models import Users


class AuditLogs(models.Model):
    ACTION_CHOICES = [
        ('create', 'Create'),
        ('update', 'Update'),
        ('delete', 'Delete')
    ]
    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(Users, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    resource_type = models.CharField(max_length=100)
    resource_id = models.IntegerField()
    description = models.TextField(blank=True)
    old_values = models.JSONField(null=True, blank=True)
    new_values = models.JSONField(null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'audit_logs'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['action', '-created_at']),
        ]

    def __str__(self):
        return f"{self.get_action_display()} - {self.resource_type} ({self.user})"


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
    min_complexity_types = models.IntegerField(
        default=3,
        choices=COMPLEXITY_CHOICES,
        validators=[MinValueValidator(2), MaxValueValidator(4)]
    )
    reject_dictionary_words = models.BooleanField(default=True)
    max_age_days = models.IntegerField(default=90, validators=[MinValueValidator(0)])
    min_rotation_days = models.IntegerField(default=1, validators=[MinValueValidator(0)])
    history_count = models.IntegerField(default=5, validators=[MinValueValidator(0)])
    min_entropy_score = models.FloatField(default=40.0, validators=[MinValueValidator(0)])
    exclude_username = models.BooleanField(default=True)
    exclude_name = models.BooleanField(default=True)
    exclude_email = models.BooleanField(default=True)
    special_chars_allowed = models.CharField(max_length=100, default="!@#$%^&*-_=+[]{}|;:,.<>?")
    special_chars_required = models.CharField(max_length=100, blank=True, null=True)
    status = models.IntegerField(default=1, null=False, blank=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "password_policy"
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.policy_name} (min_length: {self.min_length}, complexity: {self.min_complexity_types})"


class PolicyAssignment(models.Model):
    id = models.BigAutoField(primary_key=True)
    user = models.OneToOneField(Users, on_delete=models.CASCADE, related_name='policy_assignment')
    policy = models.ForeignKey(PasswordPolicy, on_delete=models.PROTECT, related_name='assignments')
    assigned_by = models.ForeignKey(
        Users,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='policy_assignments_made'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "policy_assignment"
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.email} -> {self.policy.policy_name}"


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
        ('BREACH', 'Breach Detection'),
    ]
    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(Users, on_delete=models.CASCADE, related_name='policy_violations', null=True, blank=True)
    violation_code = models.CharField(max_length=50)
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
            models.Index(fields=['user', '-created_at']),
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
    last_updated = models.DateTimeField(null=True, blank=True)
    next_update_scheduled = models.DateTimeField(null=True, blank=True)
    api_key = models.CharField(max_length=500, blank=True, null=True)
    authentication_method = models.CharField(max_length=20, choices=AUTH_METHOD_CHOICES, default='NONE')
    hash_format = models.CharField(max_length=20, choices=HASH_FORMAT_CHOICES, default='SHA1')
    description = models.TextField()
    status = models.IntegerField(default=1, null=False, blank=False)
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
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "breached_password_hash"
        unique_together = ['password_hash', 'breach_database']
        ordering = ['-occurrence_count']
        indexes = [
            models.Index(fields=['password_hash']),
            models.Index(fields=['breach_database', 'occurrence_count']),
            models.Index(fields=['severity']),
        ]

    def __str__(self):
        return f"{self.password_hash[:10]}... ({self.occurrence_count} occurrences)"

    def calculate_severity(self):
        if self.occurrence_count >= 1000:
            return 'CRITICAL'
        elif self.occurrence_count >= 101:
            return 'HIGH'
        elif self.occurrence_count >= 11:
            return 'MEDIUM'
        else:
            return 'LOW'

    def save(self, *args, **kwargs):
        if not self.severity or self.severity == 'LOW':
            self.severity = self.calculate_severity()
        super().save(*args, **kwargs)