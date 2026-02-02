from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator

from password_manager_admin.models import AdminUsers, PasswordPolicy


class Users(models.Model):
    id = models.BigAutoField(primary_key=True)
    username = models.CharField(max_length=100, unique=True, null=False)
    first_name = models.CharField(max_length=100, null=False)
    last_name = models.CharField(max_length=100, null=False)
    email = models.CharField(max_length=255, unique=True, null=False)
    password = models.CharField(max_length=255, null=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "users"


class UserPasswords(models.Model):
    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(Users, on_delete=models.CASCADE)
    platform = models.CharField(max_length=100, null=False)
    url = models.CharField(max_length=255, null=False)
    email = models.CharField(max_length=255, null=False)
    password = models.CharField(max_length=255, null=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "user_passwords"


class PasswordAnalysisResult(models.Model):
    STRENGTH_CHOICES = [
        ('VERY_WEAK', 'Very Weak (0-20)'),
        ('WEAK', 'Weak (21-40)'),
        ('FAIR', 'Fair (41-60)'),
        ('STRONG', 'Strong (61-80)'),
        ('VERY_STRONG', 'Very Strong (81-100)'),
    ]
    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(Users, on_delete=models.SET_NULL, null=True)
    password_hash = models.CharField(max_length=256, null=False)
    analysis_timestamp = models.DateTimeField(auto_now_add=True)
    overall_score = models.IntegerField(validators=[MinValueValidator(0), MaxValueValidator(100)])
    length_score = models.IntegerField(validators=[MinValueValidator(0), MaxValueValidator(20)])
    complexity_score = models.IntegerField(validators=[MinValueValidator(0), MaxValueValidator(30)])
    pattern_score = models.IntegerField(validators=[MinValueValidator(0), MaxValueValidator(30)])
    entropy_score = models.IntegerField(validators=[MinValueValidator(0), MaxValueValidator(20)])
    entropy_bits = models.FloatField(default=0.0)
    strength_level = models.CharField(max_length=20, choices=STRENGTH_CHOICES)
    is_breached = models.BooleanField(default=False)
    breach_count = models.IntegerField(default=0)
    breach_source = models.CharField(max_length=255, blank=True, null=True)
    feedback = models.JSONField(default=list, blank=True)
    recommendations = models.JSONField(default=list, blank=True)
    policy_compliant = models.BooleanField(default=True)
    policy_violations = models.JSONField(default=list, blank=True)
    analysis_details = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    notes = models.TextField(blank=True, null=True)

    class Meta:
        db_table = "password_analysis_result"
        ordering = ['-analysis_timestamp']
        indexes = [
            models.Index(fields=['user', '-analysis_timestamp']),
            models.Index(fields=['strength_level']),
            models.Index(fields=['is_breached']),
        ]

    def __str__(self):
        return f"{self.get_strength_level_display()} - {self.analysis_timestamp.strftime('%Y-%m-%d %H:%M')}"

    @property
    def is_very_weak(self):
        return self.overall_score <= 20

    @property
    def is_weak(self):
        return 21 <= self.overall_score <= 40

    @property
    def is_fair(self):
        return 41 <= self.overall_score <= 60

    @property
    def is_strong(self):
        return 61 <= self.overall_score <= 80

    @property
    def is_very_strong(self):
        return self.overall_score >= 81

    @property
    def score_breakdown(self):
        return {
            'overall': self.overall_score,
            'length': self.length_score,
            'complexity': self.complexity_score,
            'pattern': self.pattern_score,
            'entropy': self.entropy_score,
        }


class PasswordStrengthMetrics(models.Model):
    id = models.BigAutoField(primary_key=True)
    metric_date = models.DateField(unique=True)
    total_passwords_analyzed = models.IntegerField(default=0, validators=[MinValueValidator(0)])
    average_strength_score = models.FloatField(default=0.0, validators=[MinValueValidator(0), MaxValueValidator(100)])
    weak_passwords_count = models.IntegerField(default=0, validators=[MinValueValidator(0)])
    strong_passwords_count = models.IntegerField(default=0, validators=[MinValueValidator(0)])
    very_strong_passwords_count = models.IntegerField(default=0, validators=[MinValueValidator(0)])
    breached_count = models.IntegerField(default=0, validators=[MinValueValidator(0)])
    average_entropy = models.FloatField(default=0.0, validators=[MinValueValidator(0)])
    most_common_weakness = models.CharField(max_length=255, blank=True)
    policy_compliance_rate = models.FloatField(default=0.0, validators=[MinValueValidator(0), MaxValueValidator(100)])
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "password_strength_metrics"
        ordering = ['-metric_date']
        indexes = [
            models.Index(fields=['-metric_date']),
            models.Index(fields=['average_strength_score']),
        ]

    def __str__(self):
        return f"Metrics for {self.metric_date} - Avg Score: {self.average_strength_score:.1f}"

    @property
    def fair_passwords_count(self):
        return self.total_passwords_analyzed - (
                self.weak_passwords_count +
                self.strong_passwords_count +
                self.very_strong_passwords_count
        )

    @property
    def breached_percentage(self):
        if self.total_passwords_analyzed == 0:
            return 0.0
        return (self.breached_count / self.total_passwords_analyzed) * 100

    @property
    def weak_passwords_percentage(self):
        if self.total_passwords_analyzed == 0:
            return 0.0
        return (self.weak_passwords_count / self.total_passwords_analyzed) * 100

    @property
    def strong_passwords_percentage(self):
        if self.total_passwords_analyzed == 0:
            return 0.0
        strong_total = self.strong_passwords_count + self.very_strong_passwords_count
        return (strong_total / self.total_passwords_analyzed) * 100

    @property
    def is_healthy(self):
        return (
                self.policy_compliance_rate >= 80 and
                self.breached_percentage < 5 and
                self.weak_passwords_percentage < 20
        )

    @property
    def health_score(self):
        compliance_score = self.policy_compliance_rate * 0.4
        breach_score = (100 - self.breached_percentage) * 0.35
        strength_score = self.strong_passwords_percentage * 0.25
        return round(compliance_score + breach_score + strength_score, 2)

    @property
    def summary_text(self):
        return (
            f"On {self.metric_date}, {self.total_passwords_analyzed} passwords "
            f"were analyzed with an average strength of {self.average_strength_score:.1f}/100. "
            f"{self.strong_passwords_percentage:.1f}% were strong or very strong, "
            f"{self.weak_passwords_percentage:.1f}% were weak, and "
            f"{self.breached_percentage:.1f}% were found in breach databases."
        )

class PolicyAssignment(models.Model):
    """Link policies to users/groups"""
    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(
        Users,
        on_delete=models.CASCADE
    )
    password_policy = models.ForeignKey(
        PasswordPolicy,
        on_delete=models.CASCADE
    )
    effective_date = models.DateField(auto_now_add=True)
    expiry_date = models.DateField(blank=True, null=True)
    status = models.IntegerField(default=1, null=False, blank=False)
    admin_user = models.ForeignKey(
        AdminUsers,
        on_delete=models.SET_NULL,
        null=True
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "policy_assignment"
        unique_together = ['user', 'password_policy']
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'status']),
            models.Index(fields=['password_policy', 'status']),
        ]

    def __str__(self):
        return f"{self.user.username} - {self.password_policy.policy_name}"

class BreachCheckLog(models.Model):
    STATUS_CHOICES = [
        (200, 'Success'),
        (429, 'Rate Limited'),
        (500, 'Server Error'),
        (0, 'Connection Failed'),
    ]
    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(Users, on_delete=models.SET_NULL, null=True, blank=True)
    checked_hash = models.CharField(max_length=256)
    is_breached = models.BooleanField()
    breach_count = models.IntegerField(default=0)
    matching_breaches = models.JSONField(default=list, blank=True)
    api_used = models.CharField(max_length=255)
    check_timestamp = models.DateTimeField(auto_now_add=True)
    response_time_ms = models.IntegerField(default=0)
    status_code = models.IntegerField(choices=STATUS_CHOICES)
    error_message = models.CharField(max_length=500, blank=True, null=True)

    class Meta:
        db_table = "breach_check_log"
        ordering = ['-check_timestamp']
        indexes = [
            models.Index(fields=['user', '-check_timestamp']),
            models.Index(fields=['is_breached']),
            models.Index(fields=['check_timestamp']),
        ]

    def __str__(self):
        status = "BREACHED" if self.is_breached else "SAFE"
        return f"{status} - {self.check_timestamp.strftime('%Y-%m-%d %H:%M')}"


class GeneratedPassword(models.Model):
    COMPLEXITY_CHOICES = [
        ('low', 'Low - Uppercase, lowercase, digits only'),
        ('medium', 'Medium - With some special characters'),
        ('high', 'High - With all special characters'),
    ]

    GENERATION_METHOD_CHOICES = [
        ('random', 'Random'),
        ('passphrase', 'Passphrase'),
        ('pattern', 'Pattern-based'),
    ]
    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(Users, on_delete=models.CASCADE)
    password_hash = models.CharField(max_length=256)
    length = models.IntegerField(validators=[MinValueValidator(8), MaxValueValidator(64)])
    complexity_level = models.CharField(max_length=20, choices=COMPLEXITY_CHOICES)
    includes_uppercase = models.BooleanField(default=True)
    includes_lowercase = models.BooleanField(default=True)
    includes_digits = models.BooleanField(default=True)
    includes_special_chars = models.BooleanField(default=False)
    exclude_ambiguous = models.BooleanField(default=True)
    is_passphrase = models.BooleanField(default=False)
    word_count = models.IntegerField(null=True, blank=True)
    word_separator = models.CharField(max_length=10, blank=True)
    generation_method = models.CharField(max_length=20, choices=GENERATION_METHOD_CHOICES)
    generated_at = models.DateTimeField(auto_now_add=True)
    used_date = models.DateTimeField(null=True, blank=True)
    is_used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "generated_password"
        ordering = ['-generated_at']
        indexes = [
            models.Index(fields=['user', '-generated_at']),
            models.Index(fields=['is_used']),
        ]

    def __str__(self):
        return f"Generated - {self.length} chars ({self.complexity_level}) - {self.generated_at.strftime('%Y-%m-%d %H:%M')}"


class SecurityAuditLog(models.Model):
    ACTION_CHOICES = [
        ('ANALYZE', 'Password Analysis'),
        ('GENERATE', 'Password Generation'),
        ('CHECK_BREACH', 'Breach Check'),
        ('POLICY_CREATE', 'Policy Created'),
        ('POLICY_UPDATE', 'Policy Updated'),
        ('POLICY_DELETE', 'Policy Deleted'),
        ('BREACH_DB_UPDATE', 'Breach Database Updated'),
        ('REPORT_GENERATE', 'Report Generated'),
    ]

    RESOURCE_CHOICES = [
        ('PASSWORD', 'Password'),
        ('POLICY', 'Policy'),
        ('BREACH_DB', 'Breach Database'),
        ('REPORT', 'Report'),
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
    user = models.ForeignKey(
        Users,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_logs'
    )
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

    class Meta:
        db_table = "security_audit_log"
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', '-timestamp']),
            models.Index(fields=['action_type']),
            models.Index(fields=['status']),
        ]

    def __str__(self):
        return f"{self.get_action_type_display()} - {self.status} - {self.timestamp.strftime('%Y-%m-%d %H:%M')}"


class PasswordAnalysisReport(models.Model):
    """Generate and store analysis reports"""

    REPORT_TYPE_CHOICES = [
        ('INDIVIDUAL', 'Individual Password Analysis'),
        ('SUMMARY', 'Summary Report'),
        ('POLICY_COMPLIANCE', 'Policy Compliance Report'),
        ('BREACH_REPORT', 'Breach Analysis Report'),
    ]

    FILE_FORMAT_CHOICES = [
        ('HTML', 'HTML'),
        ('PDF', 'PDF'),
        ('CSV', 'CSV'),
        ('JSON', 'JSON'),
    ]
    id = models.BigAutoField(primary_key=True)
    report_id = models.CharField(max_length=100, unique=True)
    user = models.ForeignKey(
        Users,
        on_delete=models.CASCADE,
        related_name='generated_reports'
    )
    report_type = models.CharField(max_length=30, choices=REPORT_TYPE_CHOICES)
    analysis_results = models.JSONField(default=dict, blank=True)
    summary_statistics = models.JSONField(default=dict, blank=True)
    recommendations_summary = models.JSONField(default=list, blank=True)
    generated_at = models.DateTimeField()
    generated_by = models.ForeignKey(
        Users,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='authored_reports'
    )
    file_format = models.CharField(max_length=10, choices=FILE_FORMAT_CHOICES, default='HTML')
    file_path = models.FileField(upload_to='reports/', blank=True, null=True)
    is_public = models.BooleanField(default=False)
    access_token = models.CharField(max_length=100, blank=True, unique=True)
    expires_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "password_analysis_report"
        ordering = ['-generated_at']
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['report_type']),
            models.Index(fields=['is_public']),
        ]

    def __str__(self):
        return f"{self.get_report_type_display()} - {self.generated_at.strftime('%Y-%m-%d %H:%M')}"

class AnomalyAlert(models.Model):
    ALERT_TYPE_CHOICES = [
        ('MASS_WEAK_PASSWORDS', 'Multiple Weak Passwords'),
        ('BREACH_SPIKE', 'Breach Detection Spike'),
        ('POLICY_VIOLATIONS', 'Policy Violation Rate High'),
        ('UNUSUAL_PATTERN', 'Unusual Password Pattern'),
    ]

    SEVERITY_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]
    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(
        Users,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='anomaly_alerts'
    )
    alert_type = models.CharField(max_length=50, choices=ALERT_TYPE_CHOICES)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    description = models.TextField()
    affected_count = models.IntegerField(default=0)
    details = models.JSONField(default=dict, blank=True)
    is_acknowledged = models.BooleanField(default=False)
    acknowledged_by = models.ForeignKey(
        Users,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='acknowledged_alerts'
    )
    acknowledgment_time = models.DateTimeField(null=True, blank=True)
    action_taken = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "anomaly_alert"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['alert_type']),
            models.Index(fields=['severity']),
            models.Index(fields=['is_acknowledged']),
        ]

    def __str__(self):
        return f"{self.get_alert_type_display()} - {self.severity} - {self.created_at.strftime('%Y-%m-%d %H:%M')}"
