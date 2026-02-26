from typing import Optional, Union
from django.conf import settings
from djangodav.base.resources import MetaEtagMixIn, BaseDavResource
from .models import File, Folder, FileSystemItem, SharedFolder, SharedFolderMembership
from django.core.files.base import ContentFile
import logging
import mimetypes

logger = logging.getLogger(__name__)

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


class MyDavResource(MetaEtagMixIn, BaseDavResource):

    ALL_PROPS = BaseDavResource.ALL_PROPS + ['getcontenttype', 'getetag']

    _object = None
    _shared_folder_cache = None

    def __init__(self, path, user, create=False):
        self.db_path = path.strip("/")
        self.user = user
        self.is_shared = self.db_path == '__shared__' or self.db_path.startswith('__shared__/')
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

            if self.is_shared:
                db_path = f"/{self.db_path}"
                if db_path.endswith('/'):
                    db_path = db_path[:-1]
                try:
                    self._object = File.objects.get(full_path=db_path)
                    return self._object
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
                    return self._object
                except File.DoesNotExist:
                    try:
                        if not db_path.endswith('/'):
                            db_path += '/'
                        self._object = Folder.objects.get(full_path=db_path, owner=self.user)
                    except Folder.DoesNotExist:
                        logger.debug(f"Resource not found: {self.db_path} for user {self.user.username}")
                        self._object = None

        return self._object

    @property
    def full_path(self) -> str:
        if self.is_shared:
            return f"/{self.db_path}"
        return f"/{self.user.username}/{self.db_path}"

    def __repr__(self):
        return self.full_path

    def clone(self, *args, **kwargs):
        return self.__class__(user=self.user, *args, **kwargs)

    def obj_to_resource(self, obj: FileSystemItem = None):
        if obj.full_path.startswith('/__shared__/'):
            dav_path = obj.full_path.lstrip('/').rstrip('/')
            return MyDavResource(dav_path, self.user)
        if obj.full_path == f"/{self.user.username}/":
            dav_path = ""
        elif obj.full_path.startswith(f"/{self.user.username}/"):
            dav_path = obj.full_path[len(f"/{self.user.username}/"):].rstrip('/')
        else:
            dav_path = obj.full_path
        return MyDavResource(dav_path, self.user)

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
        if self.object and isinstance(self.object, (Folder, VirtualSharedRoot)):
            return 'httpd/unix-directory'

    @property
    def getetag(self):
        if isinstance(self.object, VirtualSharedRoot):
            from django.db.models import Max
            # Include latest file/folder change across all shared folders the user has access to
            latest_membership = SharedFolderMembership.objects.filter(
                user=self.user
            ).aggregate(m=Max('joined_at'))['m']
            latest_file = File.objects.filter(full_path__startswith='/__shared__/').aggregate(m=Max('updated_at'))['m']
            latest_folder = Folder.objects.filter(full_path__startswith='/__shared__/').aggregate(m=Max('updated_at'))['m']
            timestamps = []
            if latest_membership:
                timestamps.append(latest_membership)
            if latest_file:
                timestamps.append(latest_file)
            if latest_folder:
                timestamps.append(latest_folder)
            ts = int(max(timestamps).timestamp()) if timestamps else 0
            return f'"shared-{ts}"'
        if self.object:
            if isinstance(self.object, Folder):
                from django.db.models import Max
                prefix = self.object.full_path
                latest_file = File.objects.filter(full_path__startswith=prefix).aggregate(m=Max('updated_at'))['m']
                latest_subfolder = Folder.objects.filter(full_path__startswith=prefix).exclude(pk=self.object.pk).aggregate(m=Max('updated_at'))['m']
                timestamps = [self.object.updated_at]
                if latest_file:
                    timestamps.append(latest_file)
                if latest_subfolder:
                    timestamps.append(latest_subfolder)
                latest = max(timestamps)
                return f'"{self.object.pk}-{int(latest.timestamp())}"'
            return f'"{self.object.pk}-{int(self.object.updated_at.timestamp())}"'

    @property
    def oc_permissions(self):
        if isinstance(self.object, VirtualSharedRoot):
            return "RG"
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
        if isinstance(self.object, VirtualSharedRoot):
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
            # Parent of __shared__/ShareName is the virtual root — not a real folder
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
                new_file = File.objects.create(
                    parent=self.parent,
                    file=file_obj,
                    owner=self.user
                )
                self._object = new_file

        except Exception as e:
            logger.error(f"Error writing file {self.displayname} for user {self.user.username}: {e}")
            raise

    def read(self):
        if isinstance(self.object, File):
            return self.object.file.read()

    @property
    def is_collection(self):
        return isinstance(self.object, (Folder, VirtualSharedRoot))

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
            # List all shared folders the user has access to
            memberships = SharedFolderMembership.objects.filter(
                user=self.user
            ).select_related('shared_folder__root_folder')
            for m in memberships:
                sf = m.shared_folder
                yield self.obj_to_resource(sf.root_folder)
            return

        if isinstance(self.object, Folder):
            if self.is_shared:
                # Shared folder: no owner filter
                for child in File.objects.filter(parent=self.object):
                    yield self.obj_to_resource(child)
                for child in self.object.subfolders.all():
                    yield self.obj_to_resource(child)
            else:
                # Personal folder: filter by owner
                for child in File.objects.filter(parent=self.object, owner=self.user):
                    yield self.obj_to_resource(child)
                for child in self.object.subfolders.filter(owner=self.user):
                    yield self.obj_to_resource(child)

                # If root folder, also yield __shared__ virtual folder if user has memberships
                if not self.db_path:
                    has_shares = SharedFolderMembership.objects.filter(user=self.user).exists()
                    if has_shares:
                        yield MyDavResource('__shared__', self.user)

    def delete(self):
        self.object.delete()

    def create_collection(self):
        parent_folder = self.parent
        if not parent_folder:
            logger.error(f"Cannot create collection {self.displayname}, parent not found")
            raise FileNotFoundError("Parent directory does not exist.")

        Folder.objects.create(
            parent=parent_folder,
            name=self.displayname,
            owner=self.user
        )
