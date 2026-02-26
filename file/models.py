from django.db import models
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.conf import settings
from django.contrib.auth.models import User
import mimetypes
import secrets

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
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True)
    name = models.CharField(max_length=255, blank=True, null=True)
    parent = models.ForeignKey(
        'self', null=True, blank=True, on_delete=models.CASCADE, related_name='subfolders')

    def save(self, *args, **kwargs):
        if self.parent:
            # Subfolder - calculate path from parent
            parent_path = self.parent.full_path
            if not parent_path.endswith('/'):
                parent_path += '/'
            self.full_path = f"{parent_path}{self.name}/"
        else:
            # Root folder
            if self.name is None and self.parent is None:
                # Shared folder root: full_path already set externally
                if self.full_path and self.full_path.startswith('/__shared__/'):
                    pass
                elif self.owner:
                    self.full_path = f"/{self.owner.username}/"
                else:
                    raise ValidationError("Root folder must have an owner or a shared path.")
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

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['owner', 'parent', 'name'],
                name='unique_folder_per_parent_per_user'
            ),
            models.UniqueConstraint(
                fields=['owner'],
                condition=models.Q(parent__isnull=True, name__isnull=True, owner__isnull=False),
                name='unique_root_folder_per_user'
            ),
        ]
        indexes = [
            models.Index(fields=['owner', 'parent'], name='folder_owner_parent_idx'),
            models.Index(fields=['owner', 'full_path'], name='folder_owner_path_idx'),
        ]

class File(FileSystemItem):
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True)
    file = models.FileField(upload_to='uploads/')
    parent = models.ForeignKey(
        Folder, on_delete=models.CASCADE, related_name='files')
    content_type = models.CharField(editable=False, max_length=100, null=True, blank=True)

    def save(self, *args, **kwargs):
        if self.parent:
            filename = self.file.name.split('/')[-1] if '/' in self.file.name else self.file.name
            self.full_path = f"{self.parent.full_path}{filename}"
        else:
            raise ValidationError("File must belong to a folder.")

        if not self.content_type:
            guessed_type, _ = mimetypes.guess_type(self.file.path)
            self.content_type = guessed_type or 'application/octet-stream'

        super().save(*args, **kwargs)

class AppToken(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='app_tokens')
    name = models.CharField(max_length=255)
    token = models.CharField(max_length=128, unique=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    def save(self, *args, **kwargs):
        if not self.token:
            self.token = secrets.token_urlsafe(64)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.user.username} - {self.name}"


class LoginToken(models.Model):
    token = models.CharField(max_length=128, unique=True)
    user = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    validated = models.BooleanField(default=False)

    def is_expired(self):
        return timezone.now() - self.created_at > timezone.timedelta(minutes=10)


class SharedFolder(models.Model):
    name = models.CharField(max_length=255, unique=True)
    root_folder = models.OneToOneField(
        Folder, on_delete=models.CASCADE, related_name='shared_folder_ref')
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='created_shared_folders')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        if not self.root_folder_id:
            root = Folder(owner=None, name=None, parent=None)
            root.full_path = f"/__shared__/{self.name}/"
            root.save()
            self.root_folder = root
        super().save(*args, **kwargs)


class SharedFolderMembership(models.Model):
    PERMISSION_CHOICES = [
        ('read', 'Read only'),
        ('write', 'Read & Write'),
        ('admin', 'Admin'),
    ]

    shared_folder = models.ForeignKey(
        SharedFolder, on_delete=models.CASCADE, related_name='memberships')
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='shared_folder_memberships')
    permission = models.CharField(max_length=10, choices=PERMISSION_CHOICES, default='read')
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [('shared_folder', 'user')]

    def __str__(self):
        return f"{self.user.username} -> {self.shared_folder.name} ({self.permission})"
