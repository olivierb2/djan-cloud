# Generated manually for user-specific root folder migration

from django.db import migrations, models
from django.conf import settings
import django.db.models.deletion

def create_user_specific_roots(apps, schema_editor):
    """
    Create user-specific root folders and migrate existing data structure
    """
    User = apps.get_model(settings.AUTH_USER_MODEL)
    File = apps.get_model('file', 'File')
    Folder = apps.get_model('file', 'Folder')
    db_alias = schema_editor.connection.alias
    
    # Get all users
    users = User.objects.using(db_alias).all()
    
    print(f"\nMigrating to user-specific root folders for {users.count()} users...")
    
    for user in users:
        print(f"Processing user: {user.username}")
        
        # Check if user already has a proper root folder
        existing_root = Folder.objects.using(db_alias).filter(
            owner=user,
            parent__isnull=True,
            name__isnull=True
        ).first()
        
        if existing_root:
            # Update existing root folder path
            existing_root.full_path = f"/{user.username}/"
            existing_root.save(using=db_alias)
            print(f"  Updated existing root folder path to: {existing_root.full_path}")
        else:
            # Create new root folder for user
            root_folder = Folder.objects.using(db_alias).create(
                owner=user,
                parent=None,
                name=None,
                full_path=f"/{user.username}/"
            )
            print(f"  Created new root folder: {root_folder.full_path}")
        
        # Update all folders for this user to ensure proper paths
        user_folders = Folder.objects.using(db_alias).filter(owner=user).exclude(parent__isnull=True, name__isnull=True)
        for folder in user_folders:
            # Trigger save to recalculate path with new logic
            folder.save(using=db_alias)
        
        # Update all files for this user to ensure proper paths  
        user_files = File.objects.using(db_alias).filter(owner=user)
        for file in user_files:
            # Trigger save to recalculate path
            file.save(using=db_alias)
        
        print(f"  Updated {user_folders.count()} folders and {user_files.count()} files")

def reverse_migration(apps, schema_editor):
    """
    Reverse the migration - this is complex and may cause data loss
    """
    print("\nReversing user-specific root folder migration...")
    print("Warning: This may cause data loss or inconsistencies.")
    # For now, we'll just print a warning as reversing this migration is complex

class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('file', '0006_populate_owners'),
    ]

    operations = [
        # First run the data migration
        migrations.RunPython(create_user_specific_roots, reverse_migration),
        
        # Then add the constraints and indexes
        migrations.AddConstraint(
            model_name='folder',
            constraint=models.UniqueConstraint(
                fields=['owner', 'parent', 'name'],
                name='unique_folder_per_parent_per_user'
            ),
        ),
        migrations.AddConstraint(
            model_name='folder',
            constraint=models.UniqueConstraint(
                condition=models.Q(('name__isnull', True), ('parent__isnull', True)),
                fields=['owner'],
                name='unique_root_folder_per_user'
            ),
        ),
        migrations.AddIndex(
            model_name='folder',
            index=models.Index(fields=['owner', 'parent'], name='folder_owner_parent_idx'),
        ),
        migrations.AddIndex(
            model_name='folder',
            index=models.Index(fields=['owner', 'full_path'], name='folder_owner_path_idx'),
        ),
    ]