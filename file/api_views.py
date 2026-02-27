from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.shortcuts import get_object_or_404
from django.contrib.auth import authenticate
from django.db import transaction
from django.http import FileResponse
from django.core.files.base import ContentFile
import os
import json

from .models import User, Folder, File, SharedFolder, SharedFolderMembership, AppToken, LoginToken
from .serializers import UserSerializer, UserCreateSerializer, FolderSerializer, FileSerializer


# --- Auth views ---

class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email', '')
        password = request.data.get('password', '')
        user = authenticate(email=email, password=password)
        if not user:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        refresh = RefreshToken.for_user(user)
        return Response({
            'access': str(refresh.access_token),
            'refresh': str(refresh),
        })


class CurrentUserView(APIView):
    def get(self, request):
        user = request.user
        return Response({
            'id': user.id,
            'email': user.email,
            'username': user.username,
            'role': user.role,
            'is_active': user.is_active,
            'is_admin': user.role == 'admin',
        })


# --- Helper functions ---

def _get_shared_membership(user, obj):
    if not obj.full_path.startswith('/__shared__/'):
        return None
    parts = obj.full_path.split('/')
    if len(parts) < 3:
        return None
    share_name = parts[2]
    return SharedFolderMembership.objects.filter(
        shared_folder__name=share_name, user=user
    ).select_related('shared_folder').first()


def get_accessible_file(user, file_id, permission='read'):
    try:
        return File.objects.get(id=file_id, owner=user), True
    except File.DoesNotExist:
        pass
    file_obj = get_object_or_404(File, id=file_id)
    membership = _get_shared_membership(user, file_obj)
    if not membership:
        return None, False
    if permission == 'write' and membership.permission not in ('write', 'admin'):
        return None, False
    return file_obj, membership.permission in ('write', 'admin')


def get_accessible_folder(user, folder_id, permission='read'):
    try:
        return Folder.objects.get(id=folder_id, owner=user), True
    except Folder.DoesNotExist:
        pass
    folder = get_object_or_404(Folder, id=folder_id)
    membership = _get_shared_membership(user, folder)
    if not membership:
        return None, False
    if permission == 'write' and membership.permission not in ('write', 'admin'):
        return None, False
    return folder, membership.permission in ('write', 'admin')


def _folder_url_path(user, folder):
    if folder.full_path.startswith('/__shared__/'):
        return folder.full_path.lstrip('/').rstrip('/')
    if folder.full_path == f"/{user.username}/":
        return ''
    return folder.full_path.replace(f"/{user.username}/", "", 1).rstrip('/')


# --- Browse view ---

class BrowseView(APIView):
    def _resolve_folder(self, user, path):
        stripped = path.strip('/')
        if stripped == '__shared__':
            return None, True, False, True
        if stripped.startswith('__shared__/'):
            parts = stripped.split('/')
            share_name = parts[1]
            sf = get_object_or_404(SharedFolder, name=share_name)
            membership = get_object_or_404(
                SharedFolderMembership, shared_folder=sf, user=user)
            can_write = membership.permission in ('write', 'admin')
            if len(parts) == 2:
                return sf.root_folder, True, can_write, False
            sub_path = '/'.join(parts[2:])
            full_path = f"/__shared__/{share_name}/{sub_path}/"
            folder = get_object_or_404(Folder, full_path=full_path)
            return folder, True, can_write, False
        normalized_path = '/' + stripped
        if normalized_path == '/':
            folder = Folder.objects.filter(
                owner=user, parent__isnull=True, name__isnull=True).first()
            if not folder:
                folder = Folder.objects.create(owner=user, name=None, parent=None)
        else:
            user_path = f"/{user.username}{normalized_path}/"
            folder = get_object_or_404(Folder, owner=user, full_path=user_path)
        return folder, False, True, False

    def get(self, request, path=''):
        user = request.user
        folder, is_shared, can_write, is_shared_root = self._resolve_folder(user, path)

        if is_shared_root:
            memberships = SharedFolderMembership.objects.filter(
                user=user
            ).select_related('shared_folder__root_folder')
            shared_folders = []
            for m in memberships:
                sf = m.shared_folder
                shared_folders.append({
                    'id': sf.id,
                    'name': sf.name,
                    'url_path': f"__shared__/{sf.name}",
                    'permission': m.permission,
                })
            return Response({
                'current_folder': None,
                'current_path': '__shared__',
                'is_shared_root': True,
                'shared_folders': shared_folders,
                'subfolders': [],
                'files': [],
                'parent_path': '',
                'breadcrumb_parts': [{'name': 'Shared', 'path': '__shared__'}],
                'is_shared': True,
                'can_write': False,
            })

        if is_shared:
            subfolders = folder.subfolders.all().order_by('name')
            files = folder.files.all().order_by('file')
        else:
            subfolders = folder.subfolders.filter(owner=user).order_by('name')
            files = folder.files.filter(owner=user).order_by('file')

        subfolder_data = []
        for sf in subfolders:
            subfolder_data.append({
                'id': sf.id,
                'name': sf.name,
                'url_path': _folder_url_path(user, sf),
            })

        file_data = []
        for f in files:
            file_data.append({
                'id': f.id,
                'display_name': os.path.basename(f.file.name) if f.file else '',
                'content_type': f.content_type or '',
                'size': f.file.size if f.file else 0,
                'created_at': f.created_at.isoformat() if f.created_at else None,
                'updated_at': f.updated_at.isoformat() if f.updated_at else None,
            })

        # Parent path
        parent_path = None
        stripped = path.strip('/')
        if is_shared:
            parts = stripped.split('/')
            if len(parts) == 2:
                parent_path = '__shared__'
            elif len(parts) > 2:
                parent_path = '/'.join(parts[:-1])
        elif folder.parent:
            parent_full_path = folder.parent.full_path
            if parent_full_path == f"/{user.username}/":
                parent_path = ''
            else:
                parent_path = parent_full_path.replace(f"/{user.username}/", "", 1).rstrip('/')

        # Breadcrumbs
        breadcrumb_parts = []
        if path:
            parts = path.strip('/').split('/')
            for i, part in enumerate(parts):
                breadcrumb_parts.append({
                    'name': part,
                    'path': '/'.join(parts[:i + 1]),
                })

        return Response({
            'current_folder': {'id': folder.id, 'name': folder.name or 'Root'} if folder else None,
            'current_path': path,
            'subfolders': subfolder_data,
            'files': file_data,
            'parent_path': parent_path,
            'breadcrumb_parts': breadcrumb_parts,
            'is_shared': is_shared,
            'can_write': can_write,
        })

    def post(self, request, path=''):
        user = request.user
        folder, is_shared, can_write, is_shared_root = self._resolve_folder(user, path)

        if is_shared_root or not can_write:
            return Response({'error': 'No write access'}, status=status.HTTP_403_FORBIDDEN)

        action = request.data.get('action', '')

        # Upload file
        if action == 'upload' or 'file' in request.FILES:
            uploaded_file = request.FILES.get('file')
            if not uploaded_file:
                return Response({'error': 'No file provided'}, status=status.HTTP_400_BAD_REQUEST)
            if File.objects.filter(parent=folder, full_path=f"{folder.full_path}{uploaded_file.name}").exists():
                return Response({'error': f'File "{uploaded_file.name}" already exists'}, status=status.HTTP_400_BAD_REQUEST)
            new_file = File(owner=user, parent=folder, file=uploaded_file)
            new_file.save()
            return Response({
                'id': new_file.id,
                'display_name': os.path.basename(new_file.file.name),
                'content_type': new_file.content_type,
            }, status=status.HTTP_201_CREATED)

        # Create folder
        if action == 'create_folder':
            folder_name = request.data.get('name', '').strip()
            if not folder_name:
                return Response({'error': 'Folder name is required'}, status=status.HTTP_400_BAD_REQUEST)
            if '/' in folder_name:
                return Response({'error': 'Folder name cannot contain /'}, status=status.HTTP_400_BAD_REQUEST)
            if Folder.objects.filter(parent=folder, name=folder_name).exists():
                return Response({'error': f'Folder "{folder_name}" already exists'}, status=status.HTTP_400_BAD_REQUEST)
            new_folder = Folder(owner=user, parent=folder, name=folder_name)
            new_folder.save()
            return Response({
                'id': new_folder.id,
                'name': new_folder.name,
                'url_path': _folder_url_path(user, new_folder),
            }, status=status.HTTP_201_CREATED)

        # Create text file
        if action == 'create_file':
            filename = request.data.get('name', '').strip()
            if not filename:
                return Response({'error': 'Filename is required'}, status=status.HTTP_400_BAD_REQUEST)
            if '/' in filename:
                return Response({'error': 'Filename cannot contain /'}, status=status.HTTP_400_BAD_REQUEST)
            if File.objects.filter(parent=folder, full_path=f"{folder.full_path}{filename}").exists():
                return Response({'error': f'File "{filename}" already exists'}, status=status.HTTP_400_BAD_REQUEST)
            file_obj = ContentFile(b'', name=filename)
            new_file = File(owner=user, parent=folder, file=file_obj)
            new_file.save()
            return Response({
                'id': new_file.id,
                'display_name': filename,
                'content_type': new_file.content_type,
            }, status=status.HTTP_201_CREATED)

        return Response({'error': 'Unknown action'}, status=status.HTTP_400_BAD_REQUEST)


# --- File operations ---

class FileDownloadView(APIView):
    def get(self, request, file_id):
        file_obj, _ = get_accessible_file(request.user, file_id, permission='read')
        if not file_obj:
            return Response({'error': 'Not found'}, status=status.HTTP_404_NOT_FOUND)
        if not file_obj.file or not os.path.exists(file_obj.file.path):
            return Response({'error': 'File not found'}, status=status.HTTP_404_NOT_FOUND)
        response = FileResponse(
            open(file_obj.file.path, 'rb'),
            content_type=file_obj.content_type or 'application/octet-stream'
        )
        response['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_obj.file.name)}"'
        return response


class FilePreviewView(APIView):
    def get(self, request, file_id):
        file_obj, _ = get_accessible_file(request.user, file_id, permission='read')
        if not file_obj:
            return Response({'error': 'Not found'}, status=status.HTTP_404_NOT_FOUND)
        if not file_obj.file or not os.path.exists(file_obj.file.path):
            return Response({'error': 'File not found'}, status=status.HTTP_404_NOT_FOUND)

        content_type = file_obj.content_type or ''
        display_name = os.path.basename(file_obj.file.name)

        if content_type.startswith('image/') or content_type == 'application/pdf':
            response = FileResponse(
                open(file_obj.file.path, 'rb'),
                content_type=content_type
            )
            response['Content-Disposition'] = f'inline; filename="{display_name}"'
            return response

        if content_type.startswith('text/') or content_type in ('application/json', 'application/xml', 'application/javascript'):
            try:
                with open(file_obj.file.path, 'r', errors='replace') as f:
                    text_content = f.read(1024 * 512)
            except Exception:
                return Response({'error': 'Cannot read file'}, status=status.HTTP_404_NOT_FOUND)
            return Response({
                'type': 'text',
                'display_name': display_name,
                'content': text_content,
                'content_type': content_type,
            })

        # Fallback: return metadata only
        return Response({
            'type': 'download',
            'display_name': display_name,
            'content_type': content_type,
        })


class FileDeleteView(APIView):
    def delete(self, request, file_id):
        file_obj, _ = get_accessible_file(request.user, file_id, permission='write')
        if not file_obj:
            return Response({'error': 'Not found'}, status=status.HTTP_404_NOT_FOUND)
        if file_obj.file and os.path.exists(file_obj.file.path):
            os.remove(file_obj.file.path)
        file_obj.delete()
        return Response({'ok': True})


class FolderDeleteView(APIView):
    def delete(self, request, folder_id):
        folder, can_write = get_accessible_folder(request.user, folder_id, permission='write')
        if not folder:
            return Response({'error': 'Not found'}, status=status.HTTP_404_NOT_FOUND)
        if folder.parent is None:
            return Response({'error': 'Cannot delete root folder'}, status=status.HTTP_400_BAD_REQUEST)
        self._delete_recursive(folder)
        return Response({'ok': True})

    def _delete_recursive(self, folder):
        for file_obj in folder.files.all():
            if file_obj.file and os.path.exists(file_obj.file.path):
                os.remove(file_obj.file.path)
            file_obj.delete()
        for subfolder in folder.subfolders.all():
            self._delete_recursive(subfolder)
        folder.delete()


# --- Move & Rename ---

class MoveItemView(APIView):
    def post(self, request, item_type, item_id):
        user = request.user
        destination_folder_id = request.data.get('destination_folder_id')
        if not destination_folder_id:
            return Response({'error': 'No destination folder'}, status=status.HTTP_400_BAD_REQUEST)

        if item_type == 'file':
            item, _ = get_accessible_file(user, item_id, permission='write')
        elif item_type == 'folder':
            item, _ = get_accessible_folder(user, item_id, permission='write')
        else:
            return Response({'error': 'Invalid item type'}, status=status.HTTP_400_BAD_REQUEST)

        if not item:
            return Response({'error': 'Not found'}, status=status.HTTP_404_NOT_FOUND)

        destination_folder, _ = get_accessible_folder(user, int(destination_folder_id), permission='write')
        if not destination_folder:
            return Response({'error': 'Destination not found'}, status=status.HTTP_404_NOT_FOUND)

        try:
            with transaction.atomic():
                if item_type == 'file':
                    self._move_file(item, destination_folder)
                else:
                    self._move_folder(item, destination_folder)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'ok': True})

    def _move_file(self, file, destination_folder):
        if file.parent == destination_folder:
            raise Exception('File is already in the destination folder.')
        existing = File.objects.filter(
            parent=destination_folder,
            file__icontains=os.path.basename(file.file.name)
        ).exclude(id=file.id).first()
        if existing:
            raise Exception('A file with this name already exists in the destination.')
        file.parent = destination_folder
        file.save()

    def _move_folder(self, folder, destination_folder):
        if folder.parent == destination_folder:
            raise Exception('Folder is already in the destination.')
        if folder == destination_folder:
            raise Exception('Cannot move folder into itself.')
        if self._is_subfolder_of(destination_folder, folder):
            raise Exception('Cannot move folder into its own subfolder.')
        existing = Folder.objects.filter(
            parent=destination_folder, name=folder.name
        ).exclude(id=folder.id).first()
        if existing:
            raise Exception('A folder with this name already exists in the destination.')
        folder.parent = destination_folder
        folder.save()
        self._update_paths_recursive(folder)

    def _is_subfolder_of(self, potential_subfolder, parent_folder):
        current = potential_subfolder
        while current and current.parent:
            current = current.parent
            if current == parent_folder:
                return True
        return False

    def _update_paths_recursive(self, folder):
        for subfolder in folder.subfolders.all():
            subfolder.save()
            self._update_paths_recursive(subfolder)
        for f in folder.files.all():
            f.save()


class RenameItemView(APIView):
    def post(self, request, item_type, item_id):
        user = request.user
        new_name = request.data.get('new_name', '').strip()
        if not new_name:
            return Response({'error': 'Name is required'}, status=status.HTTP_400_BAD_REQUEST)
        if '/' in new_name:
            return Response({'error': 'Name cannot contain /'}, status=status.HTTP_400_BAD_REQUEST)

        if item_type == 'folder':
            item, _ = get_accessible_folder(user, item_id, permission='write')
            if not item:
                return Response({'error': 'Not found'}, status=status.HTTP_404_NOT_FOUND)
            if item.parent is None:
                return Response({'error': 'Cannot rename root folder'}, status=status.HTTP_400_BAD_REQUEST)
            if Folder.objects.filter(parent=item.parent, name=new_name).exclude(id=item.id).exists():
                return Response({'error': f'A folder named "{new_name}" already exists'}, status=status.HTTP_400_BAD_REQUEST)
            item.name = new_name
            item.save()
            self._update_paths_recursive(item)
            return Response({'ok': True, 'name': new_name})

        elif item_type == 'file':
            item, _ = get_accessible_file(user, item_id, permission='write')
            if not item:
                return Response({'error': 'Not found'}, status=status.HTTP_404_NOT_FOUND)
            if File.objects.filter(parent=item.parent, full_path=f"{item.parent.full_path}{new_name}").exclude(id=item.id).exists():
                return Response({'error': f'A file named "{new_name}" already exists'}, status=status.HTTP_400_BAD_REQUEST)
            old_path = item.file.path
            new_file_path = os.path.join(os.path.dirname(old_path), new_name)
            if os.path.exists(old_path):
                os.rename(old_path, new_file_path)
            item.file.name = os.path.join(os.path.dirname(item.file.name), new_name)
            item.content_type = None
            item.save()
            return Response({'ok': True, 'name': new_name})

        return Response({'error': 'Invalid item type'}, status=status.HTTP_400_BAD_REQUEST)

    def _update_paths_recursive(self, folder):
        for subfolder in folder.subfolders.all():
            subfolder.save()
            self._update_paths_recursive(subfolder)
        for f in folder.files.all():
            f.save()


# --- Folder tree & selector ---

class FolderTreeView(APIView):
    def get(self, request):
        user = request.user
        root = Folder.objects.filter(
            owner=user, parent__isnull=True, name__isnull=True
        ).first()

        def build_tree(folder, is_shared=False):
            if is_shared:
                children = folder.subfolders.all().order_by('name')
            else:
                children = folder.subfolders.filter(owner=user).order_by('name')
            return {
                'id': folder.id,
                'name': folder.name or 'Home',
                'url_path': _folder_url_path(user, folder),
                'children': [build_tree(c, is_shared=is_shared) for c in children],
            }

        personal_tree = build_tree(root) if root else None

        memberships = SharedFolderMembership.objects.filter(
            user=user
        ).select_related('shared_folder__root_folder')
        shared_trees = []
        for m in memberships:
            sf = m.shared_folder
            tree = build_tree(sf.root_folder, is_shared=True)
            tree['name'] = sf.name
            tree['sf_id'] = sf.id
            tree['url_path'] = f"__shared__/{sf.name}"
            shared_trees.append(tree)

        return Response({
            'tree': personal_tree,
            'shared': shared_trees,
            'is_admin': user.role == 'admin',
        })


class FolderSelectorView(APIView):
    def get(self, request, folder_id=None):
        user = request.user
        if folder_id:
            folder, _ = get_accessible_folder(user, folder_id, permission='read')
            if not folder:
                return Response({'error': 'Not found'}, status=status.HTTP_404_NOT_FOUND)
        else:
            folder = get_object_or_404(Folder, owner=user, full_path=f"/{user.username}/")

        is_shared = folder.full_path.startswith('/__shared__/')

        breadcrumbs = []
        current = folder
        while current:
            if current.full_path == f"/{user.username}/":
                breadcrumbs.insert(0, {'name': 'Root', 'id': current.id, 'path': ''})
            else:
                breadcrumbs.insert(0, {
                    'name': current.name or current.full_path.strip('/').split('/')[-1],
                    'id': current.id,
                    'path': _folder_url_path(user, current),
                })
            current = current.parent

        if is_shared:
            children = folder.subfolders.all().order_by('name')
        else:
            children = folder.subfolders.filter(owner=user).order_by('name')

        subfolders = [{
            'id': sf.id,
            'name': sf.name,
            'path': _folder_url_path(user, sf),
        } for sf in children]

        response_data = {
            'folder': {
                'id': folder.id,
                'name': folder.name or 'Root',
                'path': _folder_url_path(user, folder),
            },
            'breadcrumbs': breadcrumbs,
            'subfolders': subfolders,
        }

        if not folder_id or folder.full_path == f"/{user.username}/":
            memberships = SharedFolderMembership.objects.filter(
                user=user, permission__in=['write', 'admin']
            ).select_related('shared_folder__root_folder')
            response_data['shared_folders'] = [{
                'id': m.shared_folder.root_folder.id,
                'name': m.shared_folder.name,
                'path': _folder_url_path(user, m.shared_folder.root_folder),
            } for m in memberships]

        return Response(response_data)


# --- Shared folders ---

class SharedFolderCreateView(APIView):
    def post(self, request):
        if request.user.role != 'admin':
            return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
        name = request.data.get('name', '').strip()
        if not name:
            return Response({'error': 'Name is required'}, status=status.HTTP_400_BAD_REQUEST)
        if '/' in name:
            return Response({'error': 'Name cannot contain /'}, status=status.HTTP_400_BAD_REQUEST)
        if SharedFolder.objects.filter(name=name).exists():
            return Response({'error': 'A shared folder with this name already exists'}, status=status.HTTP_400_BAD_REQUEST)
        sf = SharedFolder(name=name, created_by=request.user)
        sf.save()
        SharedFolderMembership.objects.create(
            shared_folder=sf, user=request.user, permission='admin')
        return Response({'id': sf.id, 'name': sf.name}, status=status.HTTP_201_CREATED)


class SharedFolderMembersView(APIView):
    def _can_manage(self, user, sf):
        if user.role == 'admin':
            return True
        return sf.memberships.filter(user=user, permission='admin').exists()

    def get(self, request, sf_id):
        sf = get_object_or_404(SharedFolder, id=sf_id)
        if not self._can_manage(request.user, sf):
            return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
        members = [{
            'user_id': m.user.id,
            'email': m.user.email,
            'permission': m.permission,
        } for m in sf.memberships.select_related('user').order_by('user__email')]
        return Response({'members': members})

    def post(self, request, sf_id):
        sf = get_object_or_404(SharedFolder, id=sf_id)
        if not self._can_manage(request.user, sf):
            return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
        user_id = request.data.get('user_id')
        permission = request.data.get('permission', 'read')
        if permission not in ('read', 'write', 'admin'):
            return Response({'error': 'Invalid permission'}, status=status.HTTP_400_BAD_REQUEST)
        user = get_object_or_404(User, id=user_id)
        membership, created = SharedFolderMembership.objects.update_or_create(
            shared_folder=sf, user=user,
            defaults={'permission': permission})
        return Response({
            'user_id': user.id,
            'email': user.email,
            'permission': membership.permission,
            'created': created,
        })


class SharedFolderMemberDeleteView(APIView):
    def delete(self, request, sf_id, user_id):
        sf = get_object_or_404(SharedFolder, id=sf_id)
        if request.user.role != 'admin':
            if not sf.memberships.filter(user=request.user, permission='admin').exists():
                return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
        deleted, _ = SharedFolderMembership.objects.filter(
            shared_folder=sf, user_id=user_id).delete()
        if not deleted:
            return Response({'error': 'Membership not found'}, status=status.HTTP_404_NOT_FOUND)
        return Response({'ok': True})


# --- User management ---

class UserListView(APIView):
    def get(self, request):
        users = User.objects.order_by('email').values('id', 'email', 'username', 'role', 'is_active')
        return Response({'users': list(users)})


class UserCreateView(APIView):
    def post(self, request):
        if request.user.role != 'admin':
            return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
        email = request.data.get('email', '').strip()
        password = request.data.get('password', '').strip()
        role = request.data.get('role', 'user')
        if not email or not password:
            return Response({'error': 'Email and password are required'}, status=status.HTTP_400_BAD_REQUEST)
        if User.objects.filter(email=email).exists():
            return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)
        if role not in ('user', 'admin'):
            role = 'user'
        username = email.split('@')[0]
        user = User.objects.create_user(username=username, email=email, password=password, role=role)
        return Response({'id': user.id, 'email': user.email, 'role': user.role}, status=status.HTTP_201_CREATED)


class UserDeleteView(APIView):
    def delete(self, request, user_id):
        if request.user.role != 'admin':
            return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
        if user_id == request.user.id:
            return Response({'error': 'Cannot delete yourself'}, status=status.HTTP_400_BAD_REQUEST)
        user = get_object_or_404(User, id=user_id)
        user.delete()
        return Response({'ok': True})
