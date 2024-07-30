from django.db import models
from django.core.files.storage import FileSystemStorage

class CloudLog(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    activity = models.CharField(max_length=255)
    file_name = models.CharField(max_length=255)
    file_path = models.CharField(max_length=255, default='', blank=True)
    is_deleted = models.BooleanField(default=False)  # New field to track deletion status

    def save(self, *args, **kwargs):
        if not self.file_path:
            self.file_path = FileSystemStorage().location + '/' + self.file_name
        super().save(*args, **kwargs)

    def delete(self, using=None, keep_parents=False):
        self.is_deleted = True  # Set is_deleted to True instead of removing
        self.save()

class NIDSLog(models.Model):
    message = models.TextField()
    logged_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.logged_at}: {self.message}"
