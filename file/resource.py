from typing import Optional, Union
from django.conf import settings
from djangodav.base.resources import MetaEtagMixIn, BaseDavResource
from .models import File, Folder, FileSystemItem
from django.core.files.base import ContentFile
import mimetypes

class MyDavResource(MetaEtagMixIn, BaseDavResource):

    _object: Optional[Union[File, Folder]] = None

    def __init__(self, path):
        self.full_path = path
        if path.endswith("/"):
            path = path[:-1]
        super().__init__(path)
        try:
            self._object = File.objects.get(
                full_path=path
            )
            return
        except File.DoesNotExist:
            try:
                if path == "":
                    self._object = Folder.objects.get(
                        name__isnull=True
                    )
                else:
                    self._object = Folder.objects.get(
                        full_path=path
                    )
            except Folder.DoesNotExist:
                pass

    def __repr__(self):
        return f"<MyDavResource path:{'/'.join(self.path)}>"

    def copy(self, obj: FileSystemItem = None):
        return MyDavResource(obj.full_path)

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
        self._object.folder = MyDavResource(destination.dirname)._object
        self._object.full_path = destination.full_path
        self._object.save()

    @property
    def parent(self):
        return Folder.objects.get(full_path=self.dirname)

    def write(self, content):
        file_obj = ContentFile(
            content.read(),
            name=self.displayname
        )
        File.objects.create(
            folder=self.parent,
            file=file_obj,
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
            for child in File.objects.filter(folder=self._object):
                yield self.copy(child)
            for child in self._object.subfolders.all():
                yield self.copy(child)

    def delete(self):
        self._object.delete()

    def create_collection(self):
        Folder.objects.create(
            parent=self.parent,
            name=self.displayname
        )
