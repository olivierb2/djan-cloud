from django.contrib.auth import authenticate, login
from django.http import HttpResponse, JsonResponse, FileResponse, Http404
from django.shortcuts import render, get_object_or_404, redirect
from django.urls import reverse
from django.contrib import messages
from django.db import transaction
from django.conf import settings
import base64
import secrets
import os
from django.contrib.auth.mixins import LoginRequiredMixin
from .models import LoginToken, Folder, File
from django.views import View
from djangodav.views.views import DavView
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.contrib.auth.forms import AuthenticationForm
from .resource import MyDavResource


class BasicAuthMixin:
    def dispatch(self, request, *args, **kwargs):
        auth = request.META.get('HTTP_AUTHORIZATION')

        if auth:
            try:
                auth_type, credentials = auth.split(' ')
                if auth_type.lower() == 'basic':
                    decoded = base64.b64decode(credentials).decode('utf-8')
                    username, password = decoded.split(':')
                    user = authenticate(
                        request, username=username, password=password)
                    if user:
                        login(request, user)
                        return super().dispatch(request, *args, **kwargs)
            except Exception:
                pass  # handle any decoding/auth errors silently

        response = HttpResponse('Unauthorized', status=401)
        response['WWW-Authenticate'] = 'Basic realm="Restricted Area"'
        return response


@method_decorator(csrf_exempt, name='dispatch')
class MyDavView(BasicAuthMixin, DavView):
    
    def dispatch(self, request, *args, **kwargs):
        """Override to handle username validation from URL"""
        # Extract username from URL kwargs
        username = kwargs.get('username')
        
        # Call parent dispatch to handle authentication first
        response = super().dispatch(request, *args, **kwargs)
        
        # If authentication failed, return the response (usually 401)
        if hasattr(response, 'status_code') and response.status_code == 401:
            return response
        
        # Validate that authenticated user matches URL username
        if not request.user.is_authenticated:
            response = HttpResponse('Unauthorized', status=401)
            response['WWW-Authenticate'] = 'Basic realm="Restricted Area"'
            return response
            
        if request.user.username != username:
            return HttpResponse('Forbidden: Access denied for this user path', status=403)
        
        # If we get here, authentication and username validation passed
        return response
    
    def get_resource(self, path=None):
        """Override to pass the user to the resource"""
        if path is None:
            path = self.path
        # Pass request.user to the resource constructor
        return self.resource_class(path, user=self.request.user)


class StatusView(View):
    def get(self, *args, **kwargs):
        json_response = {"installed": True,
            "maintenance": False,
            "needsDbUpgrade": False,
            "version": "30.0.2.2",
            "versionstring": "30.0.2",
            "edition": "",
            "productname": "Nextcloud",
            "extendedSupport": False
        }
        return JsonResponse(json_response)


@method_decorator(csrf_exempt, name='dispatch')
class Login(View):

    def post(self, request, *args, **kwargs):
        token = secrets.token_urlsafe(64)
        LoginToken.objects.create(token=token)
        base = request.build_absolute_uri('/index.php/login/v2')

        return JsonResponse({
            "poll": {
                "token": token,
                "endpoint": f"{base}/poll"
            },
            "login": f"{base}/flow/{token}"
        })

class LoginForm(View):

    def get(self, request, token):
        try:
            login_token = LoginToken.objects.get(token=token)
        except LoginToken.DoesNotExist:
            return HttpResponse("Invalid token", status=404)

        form = AuthenticationForm()

        return render(request, 'login_flow.html', {'form': form})

    def post(self, request, token):
        try:
            login_token = LoginToken.objects.get(token=token)
        except LoginToken.DoesNotExist:
            return HttpResponse("Invalid token", status=404)
        
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login_token.user = user
            login_token.validated = True
            login_token.save()
            login(request, user)
            return HttpResponse("Login successful! You can close this window.")


@method_decorator(csrf_exempt, name='dispatch')
class LoginPoll(View):
    def post(self, request):
        data = request.json() if hasattr(request, 'json') else request.POST
        token = data.get('token')
        
        try:
            login_token = LoginToken.objects.get(token=token)
        except LoginToken.DoesNotExist:
            return JsonResponse({"error": "Invalid token"}, status=404)

        if not login_token.validated or login_token.is_expired():
            return JsonResponse({"error": "Not authorized yet"}, status=404)
        
        protocol = "https" if request.is_secure() else "http"

        json_content = {
            "server": f"{protocol}://{request.get_host()}/{settings.ROOT_DAV}{login_token.user.username}",
            "loginName": login_token.user.username,
            "appPassword": "fake-app-password",
        }

        print(json_content)

        return JsonResponse(json_content)


class FileBrowseView(LoginRequiredMixin, View):
    template_name = 'file/browse.html'

    def get(self, request, path=''):
        # Normalize path: remove leading/trailing slashes for consistency internally
        normalized_path = '/' + path.strip('/')
        if normalized_path == '/': # User root
            # Look for user-specific root folder
            folder = get_object_or_404(Folder, owner=request.user, full_path=f"/{request.user.username}/")
        else:
            # Prepend username to path for lookup and ensure trailing slash
            user_path = f"/{request.user.username}{normalized_path}/"
            folder = get_object_or_404(Folder, owner=request.user, full_path=user_path)

        subfolders = folder.subfolders.filter(owner=request.user).order_by('name')
        files = folder.files.filter(owner=request.user).order_by('file')
        
        # Pre-calculate URL paths for subfolders (removing username prefix)
        for subfolder in subfolders:
            if subfolder.full_path == f"/{request.user.username}/":
                subfolder.url_path = ''
            else:
                subfolder.url_path = subfolder.full_path.replace(f"/{request.user.username}/", "", 1).rstrip('/')

        # Calculate parent path for "up" link
        parent_path = None
        if folder.parent:
            parent_full_path = folder.parent.full_path
            # Handle root parent representation
            if parent_full_path == f"/{request.user.username}/":
                 parent_path = '' # Root path represented by empty string in URL
            else:
                 # Remove username prefix from path for URL
                 parent_path = parent_full_path.replace(f"/{request.user.username}/", "", 1).rstrip('/')

        context = {
            'current_folder': folder,
            'current_path': path, # Use original path for display/URLs
            'subfolders': subfolders,
            'files': files,
            'parent_path': parent_path,
        }
        return render(request, self.template_name, context)

    def post(self, request, path=''):
        # Get current folder
        normalized_path = '/' + path.strip('/')
        if normalized_path == '/': # User root
            # Look for user-specific root folder
            folder = get_object_or_404(Folder, owner=request.user, full_path=f"/{request.user.username}/")
        else:
            # Prepend username to path for lookup and ensure trailing slash
            user_path = f"/{request.user.username}{normalized_path}/"
            folder = get_object_or_404(Folder, owner=request.user, full_path=user_path)

        # Handle file upload
        if 'file' in request.FILES:
            uploaded_file = request.FILES.get('file')
            if not uploaded_file:
                messages.error(request, 'No file selected for upload.')
                return redirect(request.path)

            # Check if file already exists
            existing_file = File.objects.filter(
                owner=request.user, 
                folder=folder,
                file__icontains=uploaded_file.name
            ).first()
            
            if existing_file:
                messages.error(request, f'File "{uploaded_file.name}" already exists in this folder.')
                return redirect(request.path)

            # Create new file
            try:
                new_file = File(
                    owner=request.user,
                    folder=folder,
                    file=uploaded_file
                )
                new_file.save()
                messages.success(request, f'File "{uploaded_file.name}" uploaded successfully.')
            except Exception as e:
                messages.error(request, f'Error uploading file: {str(e)}')

        # Handle folder creation
        elif 'folder_name' in request.POST:
            folder_name = request.POST.get('folder_name', '').strip()
            if not folder_name:
                messages.error(request, 'Folder name cannot be empty.')
                return redirect(request.path)

            # Check if folder name contains invalid characters
            if '/' in folder_name:
                messages.error(request, 'Folder name cannot contain slash (/) characters.')
                return redirect(request.path)

            # Check if folder already exists
            existing_folder = Folder.objects.filter(
                owner=request.user,
                parent=folder,
                name=folder_name
            ).first()
            
            if existing_folder:
                messages.error(request, f'Folder "{folder_name}" already exists.')
                return redirect(request.path)

            # Create new folder
            try:
                new_folder = Folder(
                    owner=request.user,
                    parent=folder,
                    name=folder_name
                )
                new_folder.save()
                messages.success(request, f'Folder "{folder_name}" created successfully.')
            except Exception as e:
                messages.error(request, f'Error creating folder: {str(e)}')

        return redirect(request.path)


class FileDownloadView(LoginRequiredMixin, View):
    def get(self, request, file_id):
        file_obj = get_object_or_404(File, id=file_id, owner=request.user)
        
        if not file_obj.file or not os.path.exists(file_obj.file.path):
            raise Http404("File not found")
        
        response = FileResponse(
            open(file_obj.file.path, 'rb'),
            content_type=file_obj.content_type or 'application/octet-stream'
        )
        response['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_obj.file.name)}"'
        return response


class FileDeleteView(LoginRequiredMixin, View):
    def post(self, request, file_id):
        file_obj = get_object_or_404(File, id=file_id, owner=request.user)
        
        try:
            # Delete the physical file if it exists
            if file_obj.file and os.path.exists(file_obj.file.path):
                os.remove(file_obj.file.path)
            
            # Delete the database record
            filename = file_obj.file.name
            file_obj.delete()
            
            messages.success(request, f'File "{filename}" deleted successfully.')
        except Exception as e:
            messages.error(request, f'Error deleting file: {str(e)}')
        
        # Redirect back to the folder view  
        if file_obj.folder.full_path == f"/{request.user.username}/":
            return redirect('browse_files_root')
        else:
            # Remove username prefix from path for URL
            folder_path = file_obj.folder.full_path.replace(f"/{request.user.username}/", "", 1).rstrip('/')
            return redirect('browse_files', path=folder_path)


class FolderDeleteView(LoginRequiredMixin, View):
    def post(self, request, folder_id):
        folder = get_object_or_404(Folder, id=folder_id, owner=request.user)
        
        # Prevent deletion of root folder
        if folder.full_path == f"/{request.user.username}/":
            messages.error(request, 'Cannot delete root folder.')
            return redirect('browse_files_root')
        
        try:
            # Check if folder has content
            if folder.subfolders.exists() or folder.files.exists():
                messages.error(request, f'Folder "{folder.name}" is not empty. Delete contents first.')
                return redirect(request.META.get('HTTP_REFERER', 'browse_files_root'))
            
            folder_name = folder.name
            parent_folder = folder.parent
            folder.delete()
            
            messages.success(request, f'Folder "{folder_name}" deleted successfully.')
        except Exception as e:
            messages.error(request, f'Error deleting folder: {str(e)}')
        
        # Redirect back to parent folder
        if parent_folder and parent_folder.full_path != f"/{request.user.username}/":
            # Remove username prefix from path for URL
            parent_path = parent_folder.full_path.replace(f"/{request.user.username}/", "", 1).rstrip('/')
            return redirect('browse_files', path=parent_path)
        else:
            return redirect('browse_files_root')


class MoveItemView(LoginRequiredMixin, View):
    template_name = 'file/move_picker.html'
    
    def get(self, request, item_type, item_id):
        # Get the item to be moved
        if item_type == 'file':
            item = get_object_or_404(File, id=item_id, owner=request.user)
            current_folder = item.folder
        elif item_type == 'folder':
            item = get_object_or_404(Folder, id=item_id, owner=request.user)
            current_folder = item.parent
        else:
            messages.error(request, 'Invalid item type.')
            return redirect('browse_files_root')
        
        # Start at root folder for destination selection
        root_folder = get_object_or_404(Folder, owner=request.user, full_path=f"/{request.user.username}/")
        
        # Get breadcrumb path
        breadcrumbs = [{'name': 'Root', 'folder': root_folder}]
        
        context = {
            'item': item,
            'item_type': item_type,
            'current_folder': root_folder,
            'subfolders': root_folder.subfolders.filter(owner=request.user).order_by('name'),
            'breadcrumbs': breadcrumbs,
            'current_path': '',
        }
        return render(request, self.template_name, context)
    
    def post(self, request, item_type, item_id):
        # Get the item to move
        if item_type == 'file':
            item = get_object_or_404(File, id=item_id, owner=request.user)
        elif item_type == 'folder':
            item = get_object_or_404(Folder, id=item_id, owner=request.user)
        else:
            messages.error(request, 'Invalid item type.')
            return redirect('browse_files_root')
        
        # Get destination folder
        destination_folder_id = request.POST.get('destination_folder_id')
        if not destination_folder_id:
            messages.error(request, 'No destination folder selected.')
            return redirect(request.META.get('HTTP_REFERER', 'browse_files_root'))
        
        destination_folder = get_object_or_404(Folder, id=destination_folder_id, owner=request.user)
        
        try:
            with transaction.atomic():
                if item_type == 'file':
                    self._move_file(item, destination_folder)
                    messages.success(request, f'File "{item.file.name}" moved successfully.')
                else:  # folder
                    self._move_folder(item, destination_folder)
                    messages.success(request, f'Folder "{item.name}" moved successfully.')
        except Exception as e:
            messages.error(request, f'Error moving {item_type}: {str(e)}')
        
        # Redirect back to the destination folder
        if destination_folder.full_path == f"/{request.user.username}/":
            return redirect('browse_files_root')
        else:
            # Remove username prefix from path for URL
            dest_path = destination_folder.full_path.replace(f"/{request.user.username}/", "", 1)
            if dest_path and not dest_path.endswith('/'):
                dest_path = dest_path.rstrip('/')
            return redirect('browse_files', path=dest_path)
    
    def _move_file(self, file, destination_folder):
        """Move a file to a new folder"""
        if file.folder == destination_folder:
            raise Exception('File is already in the destination folder.')
        
        # Check for name conflicts
        existing_file = File.objects.filter(
            owner=file.owner,
            folder=destination_folder,
            file__icontains=os.path.basename(file.file.name)
        ).exclude(id=file.id).first()
        
        if existing_file:
            raise Exception(f'A file with this name already exists in the destination folder.')
        
        file.folder = destination_folder
        file.full_path = f"{destination_folder.full_path}/{os.path.basename(file.file.name)}"
        file.save()
    
    def _move_folder(self, folder, destination_folder):
        """Move a folder to a new parent folder"""
        if folder.parent == destination_folder:
            raise Exception('Folder is already in the destination folder.')
        
        if folder == destination_folder:
            raise Exception('Cannot move folder into itself.')
        
        # Check if destination is a subfolder of the item being moved (prevent circular reference)
        if self._is_subfolder_of(destination_folder, folder):
            raise Exception('Cannot move folder into its own subfolder.')
        
        # Check for name conflicts
        existing_folder = Folder.objects.filter(
            owner=folder.owner,
            parent=destination_folder,
            name=folder.name
        ).exclude(id=folder.id).first()
        
        if existing_folder:
            raise Exception(f'A folder with this name already exists in the destination folder.')
        
        # Update folder parent and recalculate paths
        folder.parent = destination_folder
        folder.save()  # This will trigger path recalculation
        
        # Update paths for all subfolders and files recursively
        self._update_paths_recursive(folder)
    
    def _is_subfolder_of(self, potential_subfolder, parent_folder):
        """Check if potential_subfolder is a subfolder of parent_folder"""
        current = potential_subfolder
        while current and current.parent:
            current = current.parent
            if current == parent_folder:
                return True
        return False
    
    def _update_paths_recursive(self, folder):
        """Recursively update full_path for all subfolders and files"""
        # Update subfolders
        for subfolder in folder.subfolders.all():
            subfolder.save()  # Triggers path recalculation
            self._update_paths_recursive(subfolder)
        
        # Update files
        for file in folder.files.all():
            file.full_path = f"{folder.full_path}/{os.path.basename(file.file.name)}"
            file.save()


class FolderSelectorView(LoginRequiredMixin, View):
    def get(self, request, folder_id=None):
        """AJAX endpoint to get folder contents for the move picker"""
        if folder_id:
            folder = get_object_or_404(Folder, id=folder_id, owner=request.user)
        else:
            # Root folder
            folder = get_object_or_404(Folder, owner=request.user, full_path=f"/{request.user.username}/")
        
        # Build breadcrumbs
        breadcrumbs = []
        current = folder
        while current:
            if current.full_path == f"/{request.user.username}/":
                breadcrumbs.insert(0, {'name': 'Root', 'id': current.id, 'path': ''})
            else:
                # Remove username prefix from path for URL
                path = current.full_path.replace(f"/{request.user.username}/", "", 1).rstrip('/')
                breadcrumbs.insert(0, {'name': current.name, 'id': current.id, 'path': path})
            current = current.parent
        
        # Get subfolders
        subfolders = []
        for subfolder in folder.subfolders.filter(owner=request.user).order_by('name'):
            # Remove username prefix from path for URL
            path = subfolder.full_path.replace(f"/{request.user.username}/", "", 1).rstrip('/')
            subfolders.append({
                'id': subfolder.id,
                'name': subfolder.name,
                'path': path,
            })
        
        # Remove username prefix from folder path for URL
        folder_path = ''
        if folder.full_path != f"/{request.user.username}/":
            folder_path = folder.full_path.replace(f"/{request.user.username}/", "", 1).rstrip('/')
        
        return JsonResponse({
            'folder': {
                'id': folder.id,
                'name': folder.name or 'Root',
                'path': folder_path,
            },
            'breadcrumbs': breadcrumbs,
            'subfolders': subfolders,
        })
