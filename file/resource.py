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
    user = None # Store the user associated with this request

    def __init__(self, path, user):
        self.full_path = path
        self.user = user
        self.original_path = path
        
        # Convert DAV path to user-specific database path
        if path.endswith("/"):
            path = path[:-1]
        super().__init__(path)

        if not self.user or not self.user.is_authenticated:
            # Prevent access if user is not provided or not authenticated
            self._object = None
            logger.warning(f"Attempt to access resource {path} without authenticated user.")
            return

        # Convert relative DAV path to absolute user path
        if path == "":
            # Root folder for this user
            db_path = f"/{self.user.username}/"
        else:
            # Subfolder or file - prepend username
            db_path = f"/{self.user.username}/{path}"

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
                 # For now, just log warning.
                logger.warning(f"Unable to find {path} for user {self.user.username}")

    def __repr__(self):
        return f"<MyDavResource path:{'/'.join(self.path)}>"

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
        if self._object and isinstance(self._object, File):
            return self._object.file.size

    def get_created(self):
        """Return the create time as datetime object."""
        if self._object:
            return self._object.created_at

    def get_modified(self):
        """Return the modified time as datetime object."""
        if self._object:
            return self._object.updated_at

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

        self._object.folder = dest_parent_resource._object
        self._object.full_path = destination.full_path
        self._object.save()

    @property
    def parent(self):
        # Convert DAV dirname to user-specific database path
        if self.dirname == "/":
            # Parent of root is None
            return None
        elif self.dirname == "":
            # Current is root, parent is None  
            return None
        else:
            # Convert relative DAV path to absolute user path
            parent_db_path = f"/{self.user.username}{self.dirname}/"
            try:
                return Folder.objects.get(full_path=parent_db_path, owner=self.user)
            except Folder.DoesNotExist:
                logger.warning(f"Parent folder {parent_db_path} not found for user {self.user.username}")
                return None

    def write(self, content):
        parent_folder = self.parent
        if not parent_folder:
             logger.error(f"Cannot write file {self.displayname}, parent folder {self.dirname} not found for user {self.user.username}")
             raise FileNotFoundError("Parent directory does not exist for user.")

        file_obj = ContentFile(
            content.read(),
            name=self.displayname
        )
        File.objects.create(
            folder=parent_folder,
            file=file_obj,
            owner=self.user # Set owner
        )

    def read(self):
        if isinstance(self._object, File):
            return self._object.file.read()

    @property
    def is_collection(self):
        return isinstance(self._object, Folder)

    @property
    def content_type(self):
        if self._object:
            return self._object.content_type

    @property
    def is_object(self):
        return isinstance(self._object, File)

    @property
    def exists(self):
        return self._object != None

    def get_children(self):
        if isinstance(self._object, Folder):
            # Filter children by owner
            for child in File.objects.filter(folder=self._object, owner=self.user):
                yield self.copy(child)
            for child in self._object.subfolders.filter(owner=self.user): # Filter subfolders by owner too
                yield self.copy(child)

    def delete(self):
        self._object.delete()

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
