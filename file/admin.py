from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from . import models
from .models import User


class FileAdmin(admin.ModelAdmin):
    list_display = ('file', 'full_path',
                    'created_at', 'updated_at', 'content_type')


class FolderAdmin(admin.ModelAdmin):
    list_display = ('name', 'full_path',
                    'created_at', 'updated_at')


class AppTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'name', 'created_at', 'last_used_at')
    readonly_fields = ('token',)


class SharedFolderMembershipInline(admin.TabularInline):
    model = models.SharedFolderMembership
    extra = 1


class SharedFolderAdmin(admin.ModelAdmin):
    list_display = ('name', 'created_by', 'created_at')
    exclude = ('root_folder',)
    inlines = [SharedFolderMembershipInline]


class CustomUserAdmin(UserAdmin):
    fieldsets = UserAdmin.fieldsets + (
        ('Role', {'fields': ('role',)}),
    )
    add_fieldsets = UserAdmin.add_fieldsets + (
        ('Role', {'fields': ('role',)}),
    )
    list_display = UserAdmin.list_display + ('role',)


admin.site.register(User, CustomUserAdmin)
admin.site.register(models.File, FileAdmin)
admin.site.register(models.Folder, FolderAdmin)
admin.site.register(models.AppToken, AppTokenAdmin)
admin.site.register(models.SharedFolder, SharedFolderAdmin)
