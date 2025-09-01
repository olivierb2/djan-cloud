from django.contrib.auth import authenticate, login
from django.http import HttpResponse, JsonResponse, FileResponse, Http404
from django.shortcuts import render, get_object_or_404, redirect
from django.urls import reverse
from django.contrib import messages
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
            "server": f"{protocol}://{request.get_host()}",
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
            folder = get_object_or_404(Folder, owner=request.user, parent__isnull=True, name__isnull=True)
        else:
            folder = get_object_or_404(Folder, owner=request.user, full_path=normalized_path)

        subfolders = folder.subfolders.filter(owner=request.user).order_by('name')
        files = folder.files.filter(owner=request.user).order_by('file')

        # Calculate parent path for "up" link
        parent_path = None
        if folder.parent:
            parent_full_path = folder.parent.full_path
            # Handle root parent representation
            if folder.parent.parent is None and folder.parent.name is None:
                 parent_path = '' # Root path represented by empty string in URL
            else:
                 parent_path = parent_full_path.strip('/')

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
            folder = get_object_or_404(Folder, owner=request.user, parent__isnull=True, name__isnull=True)
        else:
            folder = get_object_or_404(Folder, owner=request.user, full_path=normalized_path)

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
        folder_path = file_obj.folder.full_path.strip('/')
        if folder_path.startswith('userroot_'):
            return redirect('browse_files_root')
        else:
            return redirect('browse_files', path=folder_path)


class FolderDeleteView(LoginRequiredMixin, View):
    def post(self, request, folder_id):
        folder = get_object_or_404(Folder, id=folder_id, owner=request.user)
        
        # Prevent deletion of root folder
        if folder.parent is None and folder.name is None:
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
        if parent_folder and parent_folder.parent is not None:
            parent_path = parent_folder.full_path.strip('/')
            return redirect('browse_files', path=parent_path)
        else:
            return redirect('browse_files_root')
