from django.db import models
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.conf import settings
from django.contrib.auth.models import User
import mimetypes

# Create your models here.

class FileSystemItem(models.Model):

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    full_path = models.TextField(editable=False, db_index=True, unique=True)

    def __str__(self):
        return self.full_path

    class Meta:
        abstract = True

class Folder(FileSystemItem):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    name = models.CharField(max_length=255, blank=True, null=True)
    parent = models.ForeignKey(
        'self', null=True, blank=True, on_delete=models.CASCADE, related_name='subfolders')

    def save(self, *args, **kwargs):
        if self.parent:
            if self.parent.full_path.endswith('/'):
                full_path = self.parent.full_path[:-1]
            else:
                full_path = self.parent.full_path
            self.full_path = f"{full_path}/{self.name}"
        else:
            # Root folders are specific to users, no single root path
            # The full_path should likely include username or be handled differently
            # For now, let's prevent saving root folders directly this way
            # or enforce a user-specific root convention elsewhere.
            # We'll rely on filtering by owner instead of a shared root path.
            if self.name is None and self.parent is None:
                 # Allow creation of user's root representation
                 self.full_path = f"/userroot_{self.owner_id}" # Temporary unique path for user root
            else:
                 raise ValidationError("Cannot determine full_path without parent or name being null for root.")
        super().save(*args, **kwargs)

    def clean(self):
        if self.name and "/" in self.name:
            raise ValidationError(
                {'name': "Name cannot contain slash."})
        if self.parent and not self.name:
            raise ValidationError(
                {'name': "Name is required if not root folder."})
        if self.name and not self.parent:
            raise ValidationError(
                {'parent': "Parent is required if name is defined."})

class File(FileSystemItem):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    file = models.FileField(upload_to='uploads/')
    folder = models.ForeignKey(
        Folder, on_delete=models.CASCADE, related_name='files')
    content_type = models.CharField(editable=False, max_length=100, null=True, blank=True)

    def save(self, *args, **kwargs):
        # Create file name only if full_path was not given
        if not self.full_path:
            if self.folder:
                self.full_path = f"{self.folder.full_path}/{self.file.name}"
            else:
                # Cannot determine path without a folder, and root is now user-specific
                raise ValidationError("File must belong to a folder.")

        if not self.content_type:
            guessed_type, _ = mimetypes.guess_type(self.file.path)
            self.content_type = guessed_type or 'application/octet-stream'

        super().save(*args, **kwargs)



    def clean(self):
        # Ensure owner is set
        if not self.owner_id:
            raise ValidationError("Owner must be set.")
        super().clean()

class LoginToken(models.Model):
    token = models.CharField(max_length=128, unique=True)
    user = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    validated = models.BooleanField(default=False)

    def is_expired(self):
        return timezone.now() - self.created_at > timezone.timedelta(minutes=10)
