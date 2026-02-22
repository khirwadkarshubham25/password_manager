from django.db import models

from accounts.models import Users


class UserPasswords(models.Model):
    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(Users, on_delete=models.CASCADE, related_name='passwords')
    platform = models.CharField(max_length=100, null=False)
    url = models.CharField(max_length=255, null=False)
    email = models.CharField(max_length=255, null=False)
    password = models.CharField(max_length=255, null=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'user_passwords'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', '-created_at']),
        ]

    def __str__(self):
        return f"{self.user.email} - {self.platform}"


class UserPasswordHistory(models.Model):
    id = models.BigAutoField(primary_key=True)
    user_password = models.ForeignKey(UserPasswords, on_delete=models.CASCADE, related_name='history')
    encrypted_password = models.CharField(max_length=255, null=False)
    changed_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'user_password_history'
        ordering = ['-changed_at']
        indexes = [
            models.Index(fields=['user_password', '-changed_at']),
        ]

    def __str__(self):
        return f"History for password_id={self.user_password_id} at {self.changed_at}"