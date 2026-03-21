from typing import Optional, Union
from django.conf import settings
from django.core.cache import cache
from djangodav.base.resources import MetaEtagMixIn, BaseDavResource
from .models import File, Folder, FileSystemItem, SharedFolder, SharedFolderMembership, ContactFolder
from django.core.files.base import ContentFile
import logging
import mimetypes

logger = logging.getLogger(__name__)

DAV_CACHE_TTL = 10  # seconds

OC_NS = "http://owncloud.org/ns"
NC_NS = "http://nextcloud.org/ns"


class VirtualSharedRoot:
    """Virtual folder representing the __shared__/ listing for a user."""
    is_collection = True
    is_object = False
    pk = 0

    def __init__(self, user):
        from django.utils import timezone
        self.user = user
        self.full_path = '/__shared__/'
        self.created_at = timezone.now()
        self.updated_at = timezone.now()

    def __str__(self):
        return '/__shared__/'


class VirtualContactsRoot:
    """Virtual folder representing the __contacts__/ listing for a user."""
    is_collection = True
    is_object = False
    pk = 0

    def __init__(self, user):
        from django.utils import timezone
        self.user = user
        self.full_path = '/__contacts__/'
        self.created_at = timezone.now()
        self.updated_at = timezone.now()

    def __str__(self):
        return '/__contacts__/'


class MyDavResource(MetaEtagMixIn, BaseDavResource):

    ALL_PROPS = BaseDavResource.ALL_PROPS + ['getcontenttype', 'getetag']

    _object = None
    _shared_folder_cache = None
    _display_name = None

    def __init__(self, path, user, create=False):
        self.db_path = path.strip("/")
        self.user = user
        self.is_shared = self.db_path == '__shared__' or self.db_path.startswith('__shared__/')
        self.is_contact = self.db_path == '__contacts__' or self.db_path.startswith('__contacts__/')
        super().__init__(path)

    @property
    def _shared_folder(self):
        """Extract and cache the SharedFolder from the path."""
        if self._shared_folder_cache is None and self.is_shared:
            parts = self.db_path.split('/')
            if len(parts) >= 2:
                share_name = parts[1]
                try:
                    self._shared_folder_cache = SharedFolder.objects.select_related('root_folder').get(name=share_name)
                except SharedFolder.DoesNotExist:
                    self._shared_folder_cache = False
            else:
                self._shared_folder_cache = False
        return self._shared_folder_cache if self._shared_folder_cache is not False else None

    def _user_has_shared_access(self, permission='read'):
        sf = self._shared_folder
        if not sf:
            return False
        if permission == 'read':
            levels = ['read', 'write', 'admin']
        elif permission == 'write':
            levels = ['write', 'admin']
        else:
            levels = ['admin']
        return sf.memberships.filter(user=self.user, permission__in=levels).exists()

    def _get_shared_permission(self):
        sf = self._shared_folder
        if not sf:
            return None
        membership = sf.memberships.filter(user=self.user).first()
        return membership.permission if membership else None

    @property
    def object(self):
        if self._object is None:
            if self.db_path == '__shared__':
                self._object = VirtualSharedRoot(self.user)
                return self._object

            if self.db_path == '__contacts__':
                self._object = VirtualContactsRoot(self.user)
                return self._object

            # Try cache first
            cache_key = f"dav_obj:{self.user.pk}:{self.db_path}"
            cached = cache.get(cache_key)
            if cached is not None:
                self._object = cached if cached != '__none__' else None
                return self._object

            if self.is_shared or self.is_contact:
                if self.is_contact:
                    parts = self.db_path.split('/')
                    db_path = f"/__contacts__/{self.user.username}/{'/'.join(parts[1:])}"
                else:
                    db_path = f"/{self.db_path}"
                if db_path.endswith('/'):
                    db_path = db_path[:-1]
                try:
                    self._object = File.objects.get(full_path=db_path)
                except File.DoesNotExist:
                    try:
                        if not db_path.endswith('/'):
                            db_path += '/'
                        self._object = Folder.objects.get(full_path=db_path)
                    except Folder.DoesNotExist:
                        self._object = None
            else:
                db_path = f"/{self.user.username}/{self.db_path}"
                if db_path.endswith('/'):
                    db_path = db_path[:-1]
                try:
                    self._object = File.objects.get(full_path=db_path, owner=self.user)
                except File.DoesNotExist:
                    try:
                        if not db_path.endswith('/'):
                            db_path += '/'
                        self._object = Folder.objects.get(full_path=db_path, owner=self.user)
                    except Folder.DoesNotExist:
                        logger.debug(f"Resource not found: {self.db_path} for user {self.user.username}")
                        self._object = None

            cache.set(cache_key, self._object if self._object is not None else '__none__', DAV_CACHE_TTL)

        return self._object

    @property
    def full_path(self) -> str:
        if self.is_shared:
            return f"/{self.db_path}"
        if self.is_contact:
            parts = self.db_path.split('/')
            return f"/__contacts__/{self.user.username}/{'/'.join(parts[1:])}"
        return f"/{self.user.username}/{self.db_path}"

    def __repr__(self):
        return self.full_path

    def clone(self, *args, **kwargs):
        return self.__class__(user=self.user, *args, **kwargs)

    def obj_to_resource(self, obj: FileSystemItem = None):
        if obj.full_path.startswith('/__shared__/'):
            dav_path = obj.full_path.lstrip('/').rstrip('/')
            return MyDavResource(dav_path, self.user)
        if obj.full_path.startswith('/__contacts__/'):
            # /__contacts__/username/contact_id/... -> __contacts__/contact_id/...
            parts = obj.full_path.strip('/').split('/')
            dav_path = '__contacts__/' + '/'.join(parts[2:])
            return MyDavResource(dav_path.rstrip('/'), self.user)
        if obj.full_path == f"/{self.user.username}/":
            dav_path = ""
        elif obj.full_path.startswith(f"/{self.user.username}/"):
            dav_path = obj.full_path[len(f"/{self.user.username}/"):].rstrip('/')
        else:
            dav_path = obj.full_path
        return MyDavResource(dav_path, self.user)

    @property
    def displayname(self):
        if self._display_name:
            return self._display_name
        if not self.path:
            return 'Root'
        return self.path[-1]

    @property
    def dirname(self) -> str:
        if self.path:
            return "/".join(self.path[:-1])

    @property
    def getcontentlength(self):
        if self.object and isinstance(self.object, File):
            return self.object.file.size

    @property
    def getcontenttype(self):
        if self.object and isinstance(self.object, File):
            return self.object.content_type or 'application/octet-stream'
        if self.object and isinstance(self.object, (Folder, VirtualSharedRoot, VirtualContactsRoot)):
            return 'httpd/unix-directory'

    @property
    def getetag(self):
        if not self.object:
            return None

        # For files, etag is cheap - no cache needed
        if isinstance(self.object, File):
            return f'"{self.object.pk}-{int(self.object.updated_at.timestamp())}"'

        # For folders and virtual roots, use cache to avoid expensive aggregate queries
        cache_key = f"dav_etag:{self.user.pk}:{self.db_path}"
        cached_etag = cache.get(cache_key)
        if cached_etag is not None:
            return cached_etag

        from django.db.models import Max

        if isinstance(self.object, VirtualSharedRoot):
            latest_membership = SharedFolderMembership.objects.filter(
                user=self.user
            ).aggregate(m=Max('joined_at'))['m']
            latest_file = File.objects.filter(full_path__startswith='/__shared__/').aggregate(m=Max('updated_at'))['m']
            latest_folder = Folder.objects.filter(full_path__startswith='/__shared__/').aggregate(m=Max('updated_at'))['m']
            timestamps = [t for t in [latest_membership, latest_file, latest_folder] if t]
            ts = int(max(timestamps).timestamp()) if timestamps else 0
            etag = f'"shared-{ts}"'
        elif isinstance(self.object, VirtualContactsRoot):
            prefix = f"/__contacts__/{self.user.username}/"
            latest_file = File.objects.filter(full_path__startswith=prefix).aggregate(m=Max('updated_at'))['m']
            latest_folder = Folder.objects.filter(full_path__startswith=prefix).aggregate(m=Max('updated_at'))['m']
            timestamps = [t for t in [latest_file, latest_folder] if t]
            ts = int(max(timestamps).timestamp()) if timestamps else 0
            etag = f'"contacts-{ts}"'
        elif isinstance(self.object, Folder):
            prefix = self.object.full_path
            latest_file = File.objects.filter(full_path__startswith=prefix).aggregate(m=Max('updated_at'))['m']
            latest_subfolder = Folder.objects.filter(full_path__startswith=prefix).exclude(pk=self.object.pk).aggregate(m=Max('updated_at'))['m']
            timestamps = [self.object.updated_at]
            if latest_file:
                timestamps.append(latest_file)
            if latest_subfolder:
                timestamps.append(latest_subfolder)
            latest = max(timestamps)
            etag = f'"{self.object.pk}-{int(latest.timestamp())}"'
        else:
            return None

        cache.set(cache_key, etag, DAV_CACHE_TTL)
        return etag

    @property
    def oc_permissions(self):
        if isinstance(self.object, (VirtualSharedRoot, VirtualContactsRoot)):
            return "RG"
        if self.is_contact:
            if isinstance(self.object, Folder):
                return "RGDNVCK"
            return "RGDNVW"
        if self.is_shared:
            perm = self._get_shared_permission()
            if perm in ('write', 'admin'):
                if isinstance(self.object, Folder):
                    return "RGDNVCK"
                return "RGDNVW"
            return "RG"
        if isinstance(self.object, Folder):
            return "RGDNVCK"
        return "RGDNVW"

    @property
    def oc_fileid(self):
        if self.object and hasattr(self.object, 'pk') and self.object.pk:
            return str(self.object.pk)

    @property
    def oc_size(self):
        if self.object and isinstance(self.object, File):
            return str(self.object.file.size)
        return "0"

    @property
    def oc_id(self):
        if self.object and hasattr(self.object, 'pk') and self.object.pk:
            return f"{self.object.pk:08d}ocdjancloud"

    def get_oc_properties(self):
        import lxml.builder as lb
        props = []
        oc_maker = lb.ElementMaker(namespace=OC_NS)
        if isinstance(self.object, (VirtualSharedRoot, VirtualContactsRoot)):
            props.append(oc_maker.id('00000000ocdjancloud'))
            props.append(oc_maker.fileid('0'))
            props.append(oc_maker.permissions(self.oc_permissions))
            props.append(oc_maker.size('0'))
        elif self.object and hasattr(self.object, 'pk') and self.object.pk:
            props.append(oc_maker.id(self.oc_id))
            props.append(oc_maker.fileid(self.oc_fileid))
            props.append(oc_maker.permissions(self.oc_permissions))
            props.append(oc_maker.size(self.oc_size))
        return props

    def get_created(self):
        if self.object and hasattr(self.object, 'created_at'):
            return self.object.created_at

    def get_modified(self):
        if self.object and hasattr(self.object, 'updated_at'):
            return self.object.updated_at

    def copy_collection(self, destination, depth=-1):
        raise NotImplementedError()

    def copy_object(self, destination: 'MyDavResource'):
        dest_parent = destination.parent
        if not dest_parent:
            raise FileNotFoundError("Destination parent folder does not exist.")
        from django.core.files.base import ContentFile as CF
        original = self.object
        content = original.file.read()
        original.file.seek(0)
        File.objects.create(
            parent=dest_parent,
            file=CF(content, name=destination.displayname),
            owner=self.user
        )

    def move_collection(self, destination):
        raise NotImplementedError()

    def move_object(self, destination: 'MyDavResource'):
        import os
        from django.conf import settings as django_settings
        dest_parent = destination.parent
        if not dest_parent:
            raise FileNotFoundError("Destination folder does not exist.")

        obj = self.object
        obj.parent = dest_parent

        old_path = obj.file.path
        new_name = destination.displayname
        new_file_name = f"uploads/{new_name}"
        new_path = os.path.join(django_settings.MEDIA_ROOT, new_file_name)

        if old_path != new_path:
            os.makedirs(os.path.dirname(new_path), exist_ok=True)
            os.rename(old_path, new_path)
            obj.file.name = new_file_name

        obj.save()
        self._invalidate_cache()

    @property
    def parent(self) -> Optional[Folder]:
        parent_path = self.get_parent_path().strip("/")

        if self.is_shared:
            if parent_path and parent_path != '__shared__':
                db_path = f"/{parent_path}/"
                try:
                    return Folder.objects.get(full_path=db_path)
                except Folder.DoesNotExist:
                    logger.warning(f"Shared parent folder {db_path} not found")
                    return None
            return None

        if self.is_contact:
            if parent_path and parent_path != '__contacts__':
                parts = parent_path.split('/')
                db_path = f"/__contacts__/{self.user.username}/{'/'.join(parts[1:])}/"
                try:
                    return Folder.objects.get(full_path=db_path)
                except Folder.DoesNotExist:
                    logger.warning(f"Contact parent folder {db_path} not found")
                    return None
            return None

        if parent_path:
            db_path = f"/{self.user.username}/{parent_path}/"
        else:
            db_path = f"/{self.user.username}/"
        try:
            return Folder.objects.get(full_path=db_path, owner=self.user)
        except Folder.DoesNotExist:
            logger.warning(f"Parent folder {db_path} not found for user {self.user.username}")
            return None

    def _invalidate_cache(self):
        """Invalidate cached object and etag for this resource and its parents."""
        cache.delete(f"dav_obj:{self.user.pk}:{self.db_path}")
        cache.delete(f"dav_etag:{self.user.pk}:{self.db_path}")
        # Invalidate parent etags up the tree
        parts = self.db_path.split('/')
        for i in range(len(parts)):
            parent_path = '/'.join(parts[:i])
            cache.delete(f"dav_etag:{self.user.pk}:{parent_path}")
            cache.delete(f"dav_obj:{self.user.pk}:{parent_path}")

    def write(self, content):
        try:
            chunks = []
            total_size = 0
            chunk_size = 8192

            logger.debug(f"Starting file upload for {self.displayname} by user {self.user.username}")

            while True:
                try:
                    chunk = content.read(chunk_size)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total_size += len(chunk)
                    if total_size % (1024 * 1024) == 0:
                        logger.debug(f"Uploaded {total_size // (1024 * 1024)}MB of {self.displayname}")
                except IOError as e:
                    logger.error(f"IO error while reading upload content for {self.displayname}: {e}")
                    raise

            file_content = b''.join(chunks)
            file_obj = ContentFile(file_content, name=self.displayname)

            expected_path = f"{self.parent.full_path}{self.displayname}"
            existing_file = File.objects.filter(full_path=expected_path).first()

            if existing_file:
                logger.info(f"Overwriting existing file {self.displayname} for user {self.user.username}")
                if existing_file.file and hasattr(existing_file.file, 'delete'):
                    existing_file.file.delete(save=False)
                existing_file.file = file_obj
                existing_file.save()
                self._object = existing_file
            else:
                logger.info(f"Creating new file {self.displayname} for user {self.user.username}")
                file_owner = None if (self.is_shared or self.is_contact) else self.user
                new_file = File.objects.create(
                    parent=self.parent,
                    file=file_obj,
                    owner=file_owner
                )
                self._object = new_file

            self._invalidate_cache()
        except Exception as e:
            logger.error(f"Error writing file {self.displayname} for user {self.user.username}: {e}")
            raise

    def read(self):
        if isinstance(self.object, File):
            return self.object.file.read()

    @property
    def is_collection(self):
        return isinstance(self.object, (Folder, VirtualSharedRoot, VirtualContactsRoot))

    @property
    def content_type(self):
        if self.object and hasattr(self.object, 'content_type'):
            return self.object.content_type

    @property
    def is_object(self):
        return isinstance(self.object, File)

    @property
    def exists(self):
        return self.object is not None

    def get_children(self):
        if isinstance(self.object, VirtualSharedRoot):
            memberships = SharedFolderMembership.objects.filter(
                user=self.user
            ).select_related('shared_folder__root_folder')
            for m in memberships:
                sf = m.shared_folder
                res = self.obj_to_resource(sf.root_folder)
                res._object = sf.root_folder
                yield res
            return

        if isinstance(self.object, VirtualContactsRoot):
            contact_folders = ContactFolder.objects.filter(
                owner=self.user
            ).select_related('contact', 'folder')
            for cf in contact_folders:
                res = self.obj_to_resource(cf.folder)
                res._object = cf.folder
                res._display_name = cf.contact.fn or cf.contact.uid
                yield res
            return

        if isinstance(self.object, Folder):
            if self.is_shared or self.is_contact:
                for child in File.objects.filter(parent=self.object).select_related('parent'):
                    res = self.obj_to_resource(child)
                    res._object = child
                    yield res
                for child in self.object.subfolders.all().select_related('parent'):
                    res = self.obj_to_resource(child)
                    res._object = child
                    yield res
            else:
                for child in File.objects.filter(parent=self.object, owner=self.user).select_related('parent'):
                    res = self.obj_to_resource(child)
                    res._object = child
                    yield res
                for child in self.object.subfolders.filter(owner=self.user).select_related('parent'):
                    res = self.obj_to_resource(child)
                    res._object = child
                    yield res

                # If root folder, yield virtual folders
                if not self.db_path:
                    has_shares = SharedFolderMembership.objects.filter(user=self.user).exists()
                    if has_shares:
                        yield MyDavResource('__shared__', self.user)
                    has_contacts = ContactFolder.objects.filter(owner=self.user).exists()
                    if has_contacts:
                        yield MyDavResource('__contacts__', self.user)

    def delete(self):
        self._invalidate_cache()
        self.object.delete()

    def create_collection(self):
        parent_folder = self.parent
        if not parent_folder:
            logger.error(f"Cannot create collection {self.displayname}, parent not found")
            raise FileNotFoundError("Parent directory does not exist.")

        folder_owner = None if (self.is_shared or self.is_contact) else self.user
        Folder.objects.create(
            parent=parent_folder,
            name=self.displayname,
            owner=folder_owner
        )
        self._invalidate_cache()
