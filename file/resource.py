from typing import Optional, Union
from django.conf import settings
from djangodav.base.resources import MetaEtagMixIn, BaseDavResource
from .models import File, Folder, FileSystemItem
from django.core.files.base import ContentFile
import logging
import mimetypes

logger = logging.getLogger(__name__)

OC_NS = "http://owncloud.org/ns"
NC_NS = "http://nextcloud.org/ns"

class MyDavResource(MetaEtagMixIn, BaseDavResource):

    ALL_PROPS = BaseDavResource.ALL_PROPS + ['getcontenttype', 'getetag']

    _object: Optional[Union[File, Folder]] = None

    def __init__(self, path, user, create=False):
        self.db_path = path.strip("/")
        self.user = user
        logger.debug(f"Initializing MyDavResource: path='{self.db_path}', user='{user}'")

        super().__init__(path)
        
    @property
    def object(self) -> Optional[Union[File, Folder]]:

        if self._object == None:
            db_path = f"/{self.user.username}/{self.db_path}"

            if db_path.endswith('/'):
                db_path = db_path[:-1]

            try:
                # Try to find as file first
                self._object = File.objects.get(
                    full_path=db_path,
                    owner=self.user
                )
                return self._object
            except File.DoesNotExist:
                try:
                    # Try to find as folder - ensure trailing slash for folders
                    if not db_path.endswith('/'):
                        db_path += '/'
                        
                    self._object = Folder.objects.get(
                        full_path=db_path,
                        owner=self.user
                    )
                except Folder.DoesNotExist:
                    # If it's the root path and doesn't exist, create it implicitly?
                    # Or rely on explicit creation/handling elsewhere.
                    # For now, just log warning and set object to None
                    logger.debug(f"Resource not found: {self.db_path} for user {self.user.username}")
                    self._object = None

        return self._object

    @property
    def full_path(self) -> str:
        return f"/{self.user.username}/{self.db_path}"

    def __repr__(self):
        return f"/{self.user.username}/{self.db_path}"

    def clone(self, *args, **kwargs):
        return self.__class__(user=self.user, *args, **kwargs)

    def obj_to_resource(self, obj: FileSystemItem = None):
        # Convert database path back to DAV path (remove username prefix)
        if obj.full_path == f"/{self.user.username}/":
            dav_path = ""
        elif obj.full_path.startswith(f"/{self.user.username}/"):
            # Remove username prefix and trailing slash for DAV path
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
        if self.object and isinstance(self.object, Folder):
            return 'httpd/unix-directory'

    @property
    def getetag(self):
        if self.object:
            if isinstance(self.object, Folder):
                # For folders, ETag must change when contents change
                from django.db.models import Max
                latest_file = File.objects.filter(parent=self.object).aggregate(m=Max('updated_at'))['m']
                latest_subfolder = self.object.subfolders.aggregate(m=Max('updated_at'))['m']
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
        # RGDNVW = Read, Get, Delete, reNname, moVe, Write
        if isinstance(self.object, Folder):
            return "RGDNVCK"
        return "RGDNVW"

    @property
    def oc_fileid(self):
        if self.object:
            return str(self.object.pk)

    @property
    def oc_size(self):
        if self.object and isinstance(self.object, File):
            return str(self.object.file.size)
        return "0"

    @property
    def oc_id(self):
        if self.object:
            # Format: zero-padded fileid + "oc" + instance identifier
            return f"{self.object.pk:08d}ocdjancloud"

    def get_oc_properties(self):
        import lxml.builder as lb
        props = []
        oc_maker = lb.ElementMaker(namespace=OC_NS)
        if self.object:
            props.append(oc_maker.id(self.oc_id))
            props.append(oc_maker.fileid(self.oc_fileid))
            props.append(oc_maker.permissions(self.oc_permissions))
            props.append(oc_maker.size(self.oc_size))
        return props

    def get_created(self):
        """Return the create time as datetime object."""
        if self.object:
            return self.object.created_at

    def get_modified(self):
        """Return the modified time as datetime object."""
        if self.object:
            return self.object.updated_at

    def copy_collection(self, destination, depth=-1):
        raise NotImplementedError()

    def copy_object(self, destination: 'MyDavResource'):
        dest_parent = destination.parent
        if not dest_parent:
            raise FileNotFoundError("Destination parent folder does not exist.")
        import shutil
        from django.core.files.base import ContentFile as CF
        original = self.object
        content = original.file.read()
        original.file.seek(0)
        new_file = File.objects.create(
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

        # Rename the physical file if the name changed
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
        # Convert relative DAV path to absolute user path
        parent_path = self.get_parent_path().strip("/")
        if parent_path:
            db_path = f"/{self.user.username}/{parent_path}/"
        else:
            # Root folder for this user
            db_path = f"/{self.user.username}/"
        try:
            return Folder.objects.get(full_path=db_path, owner=self.user)
        except Folder.DoesNotExist:
            logger.warning(f"Parent folder {db_path} not found for user {self.user.username}")
            return None

    def write(self, content):
        try:
            # Read content in chunks to handle large files better
            chunks = []
            total_size = 0
            chunk_size = 8192  # 8KB chunks
            
            logger.debug(f"Starting file upload for {self.displayname} by user {self.user.username}")
            
            while True:
                try:
                    chunk = content.read(chunk_size)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total_size += len(chunk)
                    
                    # Log progress for large files
                    if total_size % (1024 * 1024) == 0:  # Every MB
                        logger.debug(f"Uploaded {total_size // (1024 * 1024)}MB of {self.displayname}")
                        
                except IOError as e:
                    logger.error(f"IO error while reading upload content for {self.displayname}: {e}")
                    raise
                except Exception as e:
                    logger.error(f"Unexpected error while reading upload content for {self.displayname}: {e}")
                    raise
            
            # Combine all chunks
            file_content = b''.join(chunks)
            logger.debug(f"Successfully read {total_size} bytes for {self.displayname}")
            
            file_obj = ContentFile(
                file_content,
                name=self.displayname
            )

            # Check if file already exists by full_path (unique and reliable)
            expected_path = f"{self.parent.full_path}{self.displayname}"
            existing_file = File.objects.filter(
                owner=self.user,
                full_path=expected_path
            ).first()
            
            if existing_file:
                logger.info(f"Overwriting existing file {self.displayname} for user {self.user.username}")
                # Delete old file
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
                
            logger.info(f"Successfully uploaded {self.displayname} ({total_size} bytes) for user {self.user.username}")
            
        except Exception as e:
            logger.error(f"Error writing file {self.displayname} for user {self.user.username}: {e}")
            raise

    def read(self):
        if isinstance(self.object, File):
            return self.object.file.read()

    @property
    def is_collection(self):
        return isinstance(self.object, Folder)

    @property
    def content_type(self):
        if self.object:
            return self.object.content_type

    @property
    def is_object(self):
        return isinstance(self.object, File)

    @property
    def exists(self):
        return self.object != None

    def get_children(self):
        if isinstance(self.object, Folder):
            # Filter children by owner
            for child in File.objects.filter(parent=self.object, owner=self.user):
                yield self.obj_to_resource(child)
            for child in self.object.subfolders.filter(owner=self.user): # Filter subfolders by owner too
                yield self.obj_to_resource(child)

    def delete(self):
        self.object.delete()

    def create_collection(self):
        parent_folder = self.parent
        if not parent_folder:
            logger.error(f"Cannot create collection {self.displayname}, parent folder {self.dirname} not found for user {self.user.username}")
            raise FileNotFoundError("Parent directory does not exist for user.")

        Folder.objects.create(
            parent=parent_folder,
            name=self.displayname,
            owner=self.user # Set owner
        )
