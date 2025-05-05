from django.contrib import admin
from . import models


class FileAdmin(admin.ModelAdmin):
    list_display = ('file', 'full_path',
                    'created_at', 'updated_at', 'content_type')


class FolderAdmin(admin.ModelAdmin):
    list_display = ('name', 'full_path',
                    'created_at', 'updated_at')


admin.site.register(models.File, FileAdmin)
admin.site.register(models.Folder, FolderAdmin)
