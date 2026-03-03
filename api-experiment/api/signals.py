from django.db.models.signals import post_save
from django.dispatch import receiver
from django.conf import settings


@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_user_root_folder(sender, instance, created, **kwargs):
    if created:
        from file.models import Folder
        Folder.objects.create(owner=instance, name=None, parent=None)
