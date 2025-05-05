from django.db import models
from django.core.exceptions import ValidationError
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
            self.full_path = "/"
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
                self.full_path = f"/{self.file.name}"

        if not self.content_type:
            guessed_type, _ = mimetypes.guess_type(self.file.path)
            self.content_type = guessed_type or 'application/octet-stream'

        super().save(*args, **kwargs)



    # @property
    # def content_type(self):
    #     if self.content:
    #         return mimetypes.guess_type(self.content.path)

    # @property
    # def content_length(self):
    #     if self.content:
    #         len(self.read())
    #     return 0

    # def read(self):
    #     if self.content:
    #         with open(self.content.path) as f:
    #             return f.read()

