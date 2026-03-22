from django.db import models
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.conf import settings
from django.contrib.auth.models import AbstractUser
import mimetypes
import secrets


class User(AbstractUser):
    ROLE_CHOICES = [('user', 'User'), ('admin', 'Admin')]
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='user')

    def save(self, *args, **kwargs):
        if self.is_superuser and self.role != 'admin':
            self.role = 'admin'
        super().save(*args, **kwargs)

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
                if self.full_path and (self.full_path.startswith('/__shared__/') or self.full_path.startswith('/__contacts__/')):
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
    display_name = models.CharField(max_length=255, blank=True)

    def save(self, *args, **kwargs):
        if self.parent:
            filename = self.file.name.split('/')[-1] if '/' in self.file.name else self.file.name
            self.full_path = f"{self.parent.full_path}{filename}"

            # Set display_name if not already set
            if not self.display_name:
                self.display_name = filename
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
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
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


# CalDAV Models

class Calendar(models.Model):
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='calendars')
    name = models.CharField(max_length=255)
    display_name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    timezone = models.CharField(max_length=100, default='UTC')
    color = models.CharField(max_length=9, default='#3498db')  # Hex color with #
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    sync_token = models.CharField(max_length=128, unique=True, db_index=True, editable=False)

    class Meta:
        unique_together = [('owner', 'name')]
        indexes = [
            models.Index(fields=['owner', 'name'], name='calendar_owner_name_idx'),
        ]

    def save(self, *args, **kwargs):
        if not self.sync_token:
            self.sync_token = secrets.token_urlsafe(32)
        super().save(*args, **kwargs)

    def update_sync_token(self):
        """Generate new sync token when calendar content changes"""
        self.sync_token = secrets.token_urlsafe(32)
        self.save(update_fields=['sync_token', 'updated_at'])

    def __str__(self):
        return f"{self.owner.username}/{self.display_name}"


class CalendarShare(models.Model):
    PERMISSION_CHOICES = [
        ('read', 'Read only'),
        ('write', 'Read & Write'),
        ('admin', 'Admin'),
    ]

    calendar = models.ForeignKey(
        Calendar, on_delete=models.CASCADE, related_name='shares')
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='shared_calendars')
    permission = models.CharField(max_length=10, choices=PERMISSION_CHOICES, default='read')
    shared_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [('calendar', 'user')]

    def __str__(self):
        return f"{self.user.username} -> {self.calendar.display_name} ({self.permission})"


class Event(models.Model):
    calendar = models.ForeignKey(
        Calendar, on_delete=models.CASCADE, related_name='events')
    uid = models.CharField(max_length=255, db_index=True)  # iCalendar UID
    ical_data = models.TextField()  # Full iCalendar data (VEVENT component)

    # Extracted fields for querying (from iCalendar data)
    summary = models.CharField(max_length=500, blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    location = models.CharField(max_length=500, blank=True, null=True)
    dtstart = models.DateTimeField(db_index=True, null=True, blank=True)
    dtend = models.DateTimeField(null=True, blank=True)
    all_day = models.BooleanField(default=False)

    # Recurrence
    recurrence_rule = models.TextField(blank=True, null=True)  # RRULE

    # Metadata
    etag = models.CharField(max_length=64, db_index=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [('calendar', 'uid')]
        indexes = [
            models.Index(fields=['calendar', 'dtstart'], name='event_calendar_start_idx'),
            models.Index(fields=['calendar', 'uid'], name='event_calendar_uid_idx'),
        ]

    def save(self, *args, **kwargs):
        if not self.etag:
            import hashlib
            self.etag = hashlib.md5(f"{self.uid}-{timezone.now().timestamp()}".encode()).hexdigest()
        super().save(*args, **kwargs)
        # Update parent calendar sync token
        self.calendar.update_sync_token()

    def delete(self, *args, **kwargs):
        calendar = self.calendar
        super().delete(*args, **kwargs)
        calendar.update_sync_token()

    def __str__(self):
        return f"{self.calendar.owner.username}/{self.calendar.name}/{self.summary or self.uid}"


# CardDAV Models

class AddressBook(models.Model):
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='addressbooks')
    name = models.CharField(max_length=255)
    display_name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    sync_token = models.CharField(max_length=128, unique=True, db_index=True, editable=False)

    class Meta:
        unique_together = [('owner', 'name')]
        indexes = [
            models.Index(fields=['owner', 'name'], name='addressbook_owner_name_idx'),
        ]

    def save(self, *args, **kwargs):
        if not self.sync_token:
            self.sync_token = secrets.token_urlsafe(32)
        super().save(*args, **kwargs)

    def update_sync_token(self):
        """Generate new sync token when addressbook content changes"""
        self.sync_token = secrets.token_urlsafe(32)
        self.save(update_fields=['sync_token', 'updated_at'])

    def __str__(self):
        return f"{self.owner.username}/{self.display_name}"


class AddressBookShare(models.Model):
    PERMISSION_CHOICES = [
        ('read', 'Read only'),
        ('write', 'Read & Write'),
        ('admin', 'Admin'),
    ]

    addressbook = models.ForeignKey(
        AddressBook, on_delete=models.CASCADE, related_name='shares')
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='shared_addressbooks')
    permission = models.CharField(max_length=10, choices=PERMISSION_CHOICES, default='read')
    shared_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [('addressbook', 'user')]

    def __str__(self):
        return f"{self.user.username} -> {self.addressbook.display_name} ({self.permission})"


class Contact(models.Model):
    addressbook = models.ForeignKey(
        AddressBook, on_delete=models.CASCADE, related_name='contacts')
    uid = models.CharField(max_length=255, db_index=True)  # vCard UID
    vcard_data = models.TextField()  # Full vCard data

    # Extracted fields for querying (from vCard data)
    fn = models.CharField(max_length=500, blank=True, null=True)  # Formatted Name (FN)
    n = models.CharField(max_length=500, blank=True, null=True)  # Structured Name (N)
    email = models.CharField(max_length=255, blank=True, null=True)  # Primary email
    tel = models.CharField(max_length=100, blank=True, null=True)  # Primary telephone
    org = models.CharField(max_length=255, blank=True, null=True)  # Organization

    # Metadata
    etag = models.CharField(max_length=64, db_index=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [('addressbook', 'uid')]
        indexes = [
            models.Index(fields=['addressbook', 'fn'], name='contact_addressbook_fn_idx'),
            models.Index(fields=['addressbook', 'uid'], name='contact_addressbook_uid_idx'),
        ]

    def save(self, *args, **kwargs):
        if not self.etag:
            import hashlib
            self.etag = hashlib.md5(f"{self.uid}-{timezone.now().timestamp()}".encode()).hexdigest()
        super().save(*args, **kwargs)
        # Update parent addressbook sync token
        self.addressbook.update_sync_token()

    def delete(self, *args, **kwargs):
        addressbook = self.addressbook
        super().delete(*args, **kwargs)
        addressbook.update_sync_token()

    def __str__(self):
        return f"{self.addressbook.owner.username}/{self.addressbook.name}/{self.fn or self.uid}"


class ContactFolder(models.Model):
    contact = models.OneToOneField(
        Contact, on_delete=models.CASCADE, related_name='contact_folder')
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='contact_folders')
    folder = models.OneToOneField(
        Folder, on_delete=models.CASCADE, related_name='contact_folder_ref')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [('owner', 'contact')]

    def __str__(self):
        return f"{self.owner.username} -> {self.contact.fn or self.contact.uid}"

    def save(self, *args, **kwargs):
        if not self.folder_id:
            root = Folder(owner=None, name=None, parent=None)
            root.full_path = f"/__contacts__/{self.owner.username}/{self.contact.id}/"
            root.save()
            self.folder = root
        super().save(*args, **kwargs)


# Email Models

SYSTEM_MAILBOXES = ['INBOX', 'Sent', 'Drafts', 'Trash', 'Junk']


class SharedMailbox(models.Model):
    name = models.CharField(max_length=255, unique=True)
    email_alias = models.EmailField(unique=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True,
        related_name='created_shared_mailboxes')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return f"{self.name} <{self.email_alias}>"

    def ensure_defaults(self):
        existing = set(Mailbox.objects.filter(
            shared_mailbox=self, name__in=SYSTEM_MAILBOXES
        ).values_list('name', flat=True))
        missing = [name for name in SYSTEM_MAILBOXES if name not in existing]
        if missing:
            Mailbox.objects.bulk_create([
                Mailbox(shared_mailbox=self, owner=None, name=name, system=True)
                for name in missing
            ], ignore_conflicts=True)


class SharedMailboxMembership(models.Model):
    PERMISSION_CHOICES = [
        ('read', 'Read only'),
        ('write', 'Read & Write'),
        ('admin', 'Admin'),
    ]

    shared_mailbox = models.ForeignKey(
        SharedMailbox, on_delete=models.CASCADE, related_name='memberships')
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
        related_name='shared_mailbox_memberships')
    permission = models.CharField(max_length=10, choices=PERMISSION_CHOICES, default='read')
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [('shared_mailbox', 'user')]

    def __str__(self):
        return f"{self.user.username} -> {self.shared_mailbox.name} ({self.permission})"


class Mailbox(models.Model):
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
        related_name='mailboxes', null=True, blank=True)
    shared_mailbox = models.ForeignKey(
        SharedMailbox, on_delete=models.CASCADE,
        related_name='mailboxes', null=True, blank=True)
    name = models.CharField(max_length=255, default='INBOX')
    system = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['owner', 'name'],
                condition=models.Q(owner__isnull=False),
                name='unique_owner_mailbox'),
            models.UniqueConstraint(
                fields=['shared_mailbox', 'name'],
                condition=models.Q(shared_mailbox__isnull=False),
                name='unique_shared_mailbox'),
        ]
        ordering = ['name']

    @property
    def is_system(self):
        return self.system

    def __str__(self):
        if self.owner:
            return f"{self.owner.username}/{self.name}"
        if self.shared_mailbox:
            return f"[shared:{self.shared_mailbox.name}]/{self.name}"
        return self.name

    @staticmethod
    def ensure_defaults(user):
        existing = set(Mailbox.objects.filter(
            owner=user, name__in=SYSTEM_MAILBOXES
        ).values_list('name', flat=True))
        missing = [name for name in SYSTEM_MAILBOXES if name not in existing]
        if missing:
            Mailbox.objects.bulk_create([
                Mailbox(owner=user, name=name, system=True)
                for name in missing
            ], ignore_conflicts=True)


class Email(models.Model):
    mailbox = models.ForeignKey(
        Mailbox, on_delete=models.CASCADE, related_name='emails')
    message_id = models.CharField(max_length=512, blank=True, db_index=True)
    from_address = models.CharField(max_length=500)
    to_addresses = models.TextField()  # Comma-separated
    cc_addresses = models.TextField(blank=True)
    subject = models.CharField(max_length=1000, blank=True)
    body_text = models.TextField(blank=True)
    body_html = models.TextField(blank=True)
    raw_data = models.TextField()  # Full raw email
    is_read = models.BooleanField(default=False)
    flagged = models.BooleanField(default=False)
    answered = models.BooleanField(default=False)
    deleted = models.BooleanField(default=False)
    draft = models.BooleanField(default=False)
    imap_uid = models.PositiveIntegerField(null=True, blank=True, db_index=True)
    received_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-received_at']
        indexes = [
            models.Index(fields=['mailbox', '-received_at'], name='email_mailbox_date_idx'),
            models.Index(fields=['mailbox', 'imap_uid'], name='email_mailbox_uid_idx'),
        ]

    def save(self, *args, **kwargs):
        if not self.imap_uid:
            last = Email.objects.filter(mailbox=self.mailbox).order_by('-imap_uid').values_list('imap_uid', flat=True).first()
            self.imap_uid = (last or 0) + 1
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.subject or '(no subject)'} - {self.from_address}"


class EmailAttachment(models.Model):
    email = models.ForeignKey(
        Email, on_delete=models.CASCADE, related_name='attachments')
    filename = models.CharField(max_length=255)
    content_type = models.CharField(max_length=100)
    data = models.BinaryField()
    size = models.PositiveIntegerField()

    def __str__(self):
        return self.filename


class EmailSignature(models.Model):
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
        related_name='email_signatures')
    name = models.CharField(max_length=100)
    html_content = models.TextField(blank=True, default='')
    is_default = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-is_default', 'name']
        constraints = [
            models.UniqueConstraint(
                fields=['owner', 'name'], name='unique_signature_per_user'),
        ]

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        # If this signature is set as default, unset others
        if self.is_default:
            EmailSignature.objects.filter(
                owner=self.owner, is_default=True
            ).exclude(pk=self.pk).update(is_default=False)
        super().save(*args, **kwargs)


class OutOfOffice(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
        related_name='out_of_office')
    enabled = models.BooleanField(default=False)
    subject = models.CharField(max_length=255, default='Out of office')
    body = models.TextField(blank=True, default='I am currently out of the office and will reply when I return.')
    start_date = models.DateField(null=True, blank=True)
    end_date = models.DateField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"OOO:{self.user.username} ({'on' if self.enabled else 'off'})"

    def is_active(self):
        if not self.enabled:
            return False
        from datetime import date
        today = date.today()
        if self.start_date and today < self.start_date:
            return False
        if self.end_date and today > self.end_date:
            return False
        return True


class OutOfOfficeReply(models.Model):
    """Track sent auto-replies to avoid spamming the same sender."""
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
        related_name='ooo_replies')
    sender_email = models.CharField(max_length=500)
    replied_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ['user', 'sender_email']


class AllowedDomain(models.Model):
    domain = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['domain']

    def __str__(self):
        return self.domain
