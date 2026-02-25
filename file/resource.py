from typing import Optional, Union
from django.conf import settings
from djangodav.base.resources import MetaEtagMixIn, BaseDavResource
from .models import File, Folder, FileSystemItem
from django.core.files.base import ContentFile
import logging
import mimetypes

logger = logging.getLogger(__name__)

class MyDavResource(MetaEtagMixIn, BaseDavResource):

    _object: Optional[Union[File, Folder]] = None

    def __init__(self, path, user, create=False):
        logger.debug(f"Initializing MyDavResource: path='{path}', user='{user}'")
        self.db_path = path
        self.user = user

        super().__init__(path)
        
    @property
    def object(self) -> Optional[Union[File, Folder]]:

        if self._object == None:
        # Convert relative DAV path to absolute user path
            # if self.path == "":
            #     # Root folder for this user
            #     db_path = f"/{self.user.username}/"
            # else:
            #     # Subfolder or file - prepend username
            
            db_path = f"/{self.user.username}/{self.db_path}"

            if db_path.endswith('/'):
                db_path = db_path[:-1]

            try:
                # Try to find as file first
                self._object = File.objects.get(
                    full_path=db_path,
                    owner=self.user
                )
                return
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

    def copy(self, obj: FileSystemItem = None):
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
            return "/" + "/".join(self.path[:-1])

    @property
    def getcontentlength(self):
        if self.object and isinstance(self.object, File):
            return self.object.file.size

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

    def copy_object(self, destination):
        raise NotImplementedError()

    def move_collection(self, destination):
        raise NotImplementedError()

    def move_object(self, destination: 'MyDavResource'):
        # Ensure destination owner is the same
        if destination.user != self.user:
             logger.error(f"Attempt to move object across users: {self.user} -> {destination.user}")
             raise PermissionError("Cannot move objects between different users.")
        # Ensure the destination folder belongs to the user
        dest_parent_resource = MyDavResource(destination.dirname, self.user)
        if not dest_parent_resource.exists or not isinstance(dest_parent_resource._object, Folder):
            logger.error(f"Destination parent folder {destination.dirname} does not exist for user {self.user}")
            raise FileNotFoundError("Destination folder does not exist.")

        self.object.parent = dest_parent_resource._object
        self.object.full_path = destination.full_path
        self.object.save()

    @property
    def parent(self) -> Optional[Folder]:
        # Convert relative DAV path to absolute user path
        try:
            return Folder.objects.get(full_path=self.get_parent_path(), owner=self.user)
        except Folder.DoesNotExist:
            logger.warning(f"Parent folder {self.get_parent_path()} not found for user {self.user.username}")
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

            # Check if file already exists
            existing_file = File.objects.filter(
                parent=self.parent,
                owner=self.user,
                file__icontains=self.displayname
            ).first()
            
            if existing_file:
                logger.info(f"Overwriting existing file {self.displayname} for user {self.user.username}")
                # Delete old file
                if existing_file.file and hasattr(existing_file.file, 'delete'):
                    existing_file.file.delete(save=False)
                existing_file.file = file_obj
                existing_file.save()
                self.object = existing_file
            else:
                logger.info(f"Creating new file {self.displayname} for user {self.user.username}")
                new_file = File.objects.create(
                    parent=self.parent,
                    file=file_obj,
                    owner=self.user
                )
                self.object = new_file
                
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
                yield self.copy(child)
            for child in self.object.subfolders.filter(owner=self.user): # Filter subfolders by owner too
                yield self.copy(child)

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
