from django.contrib.auth import authenticate, login, logout
from django.http import HttpResponse, HttpResponseBadRequest, JsonResponse, FileResponse, Http404
from django.shortcuts import render, get_object_or_404, redirect
from django.urls import reverse
from django.contrib import messages
from django.db import transaction
from django.conf import settings
from django.utils import timezone
from django.core.files.base import ContentFile
import base64
import json
import secrets
import os
from django.contrib.auth.mixins import LoginRequiredMixin
from .models import AppToken, LoginToken, Folder, File
from django.views import View
from djangodav.views.views import DavView
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.contrib.auth.forms import AuthenticationForm
import logging

logger = logging.getLogger(__name__)

class BasicAuthMixin:
    """A mixin to protect a view with HTTP Basic Authentication."""

    def dispatch(self, request, *args, **kwargs):
        # Check if user is already authenticated in Django session
        if request.user.is_authenticated:
            return super().dispatch(request, *args, **kwargs)

        # Check the Authorization header
        auth_header = request.META.get("HTTP_AUTHORIZATION")
        if auth_header and auth_header.startswith("Basic "):

            # Decode credentials
            encoded_credentials = auth_header.split(" ")[1]
            decoded_credentials = base64.b64decode(encoded_credentials).decode("utf-8")
            username, password = decoded_credentials.split(":", 1)

            # Try app token authentication first
            try:
                app_token = AppToken.objects.select_related('user').get(
                    token=password, user__username=username)
                app_token.last_used_at = timezone.now()
                app_token.save(update_fields=['last_used_at'])
                request.user = app_token.user
                return super().dispatch(request, *args, **kwargs)
            except AppToken.DoesNotExist:
                pass

            # Fall back to Django's auth backend
            user = authenticate(username=username, password=password)
            if user:
                request.user = user
                return super().dispatch(request, *args, **kwargs)

        # If authentication fails -> return 401 with WWW-Authenticate header
        response = HttpResponse("Unauthorized", status=401)
        response["WWW-Authenticate"] = 'Basic realm="Restricted"'
        return response

@method_decorator(csrf_exempt, name='dispatch')
class MyDavView(BasicAuthMixin, DavView):

    def dispatch(self, request, *args, **kwargs):
        kwargs.pop('username', None)
        return super().dispatch(request, *args, **kwargs)

    def get_resource(self, path=None):
        if path is None:
            path = self.path
        return self.resource_class(path, user=self.request.user)

    def relocate(self, request, path, method, *args, **kwargs):
        from urllib import parse as urlparse
        # Log destination for debugging
        dst_header = request.META.get('HTTP_DESTINATION', '')
        logger.debug("MOVE/COPY destination header: %s, base_url: %s", dst_header, self.base_url)
        dst_url = urlparse.unquote(dst_header)
        if not dst_url:
            return HttpResponseBadRequest('Destination header missing.')
        dparts = urlparse.urlparse(dst_url)
        # Only compare netloc (ignore scheme difference http vs https)
        sparts = urlparse.urlparse(request.build_absolute_uri())
        if dparts.netloc and sparts.netloc != dparts.netloc:
            from djangodav.responses import HttpResponseBadGateway
            return HttpResponseBadGateway('Source and destination must have the same host.')
        # Extract the relative path from the destination
        dst_path = dparts.path
        if dst_path.startswith(self.base_url):
            dst_path = dst_path[len(self.base_url):]
        dst_resource = self.get_resource(path=dst_path)
        if not dst_resource.get_parent().exists:
            from djangodav.responses import HttpResponseConflict
            return HttpResponseConflict()
        if not self.has_access(self.resource, 'write'):
            return self.no_access()
        overwrite = request.META.get('HTTP_OVERWRITE', 'T')
        if overwrite not in ('T', 'F'):
            return HttpResponseBadRequest('Overwrite header must be T or F.')
        overwrite = (overwrite == 'T')
        if not overwrite and dst_resource.exists:
            from djangodav.responses import HttpResponsePreconditionFailed
            return HttpResponsePreconditionFailed('Destination exists and overwrite False.')
        dst_exists = dst_resource.exists
        if dst_exists:
            self.lock_class(self.resource).del_locks()
            self.lock_class(dst_resource).del_locks()
            dst_resource.delete()
        errors = getattr(self.resource, method)(dst_resource, *args, **kwargs)
        if errors:
            from djangodav.responses import HttpResponseMultiStatus
            return self.build_xml_response(response_class=HttpResponseMultiStatus)
        if dst_exists:
            from djangodav.responses import HttpResponseNoContent
            return HttpResponseNoContent()
        from djangodav.responses import HttpResponseCreated
        return HttpResponseCreated()

    def put(self, request, path, *args, **kwargs):
        response = super().put(request, path, *args, **kwargs)
        # Nextcloud client requires ETag and OC-ETag headers after upload
        if response.status_code in (201, 204):
            # Re-fetch resource to get updated etag after write
            resource = self.get_resource(path=self.path)
            if resource.exists and resource.getetag:
                response['ETag'] = resource.getetag
                response['OC-ETag'] = resource.getetag
                if hasattr(resource, 'oc_fileid') and resource.oc_fileid:
                    response['OC-FileId'] = resource.oc_fileid
        return response

    def propfind(self, request, path, xbody=None, *args, **kwargs):
        from djangodav.utils import url_join, get_property_tag_list, WEBDAV_NS
        from djangodav.responses import HttpResponseMultiStatus
        from file.resource import OC_NS, NC_NS
        import lxml.builder as lb

        logger.debug("PROPFIND Content-Type: %s, body length: %s, xbody: %s",
                     request.META.get('CONTENT_TYPE'), request.META.get('CONTENT_LENGTH'), xbody is not None)

        if not self.has_access(self.resource, 'read'):
            return self.no_access()
        if not self.resource.exists:
            raise Http404("Resource doesn't exists")
        if not self.get_access(self.resource):
            return self.no_access()

        get_all_props, get_prop, get_prop_names = True, False, False
        if xbody:
            get_prop = [p.xpath('local-name()') for p in xbody('/d:propfind/d:prop/*')]
            get_all_props = xbody('/d:propfind/d:allprop')
            get_prop_names = xbody('/d:propfind/d:propname')
            if int(bool(get_prop)) + int(bool(get_all_props)) + int(bool(get_prop_names)) != 1:
                return HttpResponseBadRequest()

        nsmap = {'d': WEBDAV_NS, 'oc': OC_NS, 'nc': NC_NS}
        DAV = lb.ElementMaker(namespace=WEBDAV_NS, nsmap=nsmap)

        children = self.resource.get_descendants(depth=self.get_depth())

        responses = []
        for child in children:
            dav_props = get_property_tag_list(child, *(get_prop if get_prop else child.ALL_PROPS))
            oc_props = child.get_oc_properties() if hasattr(child, 'get_oc_properties') else []
            responses.append(
                DAV.response(
                    DAV.href(url_join(self.base_url, child.get_escaped_path())),
                    DAV.propstat(
                        DAV.prop(*(dav_props + oc_props)),
                        DAV.status('HTTP/1.1 200 OK'),
                    ),
                )
            )

        body = DAV.multistatus(*responses)
        from lxml import etree
        logger.debug("PROPFIND response XML: %s", etree.tostring(body, pretty_print=True).decode())
        return self.build_xml_response(body, HttpResponseMultiStatus)

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


class OcsUserView(BasicAuthMixin, View):
    def get(self, request, *args, **kwargs):
        return JsonResponse({
            "ocs": {
                "meta": {"status": "ok", "statuscode": 100, "message": "OK"},
                "data": {
                    "id": request.user.username,
                    "display-name": request.user.get_full_name() or request.user.username,
                    "email": request.user.email or "",
                }
            }
        })


class OcsCapabilitiesView(BasicAuthMixin, View):
    def get(self, request, *args, **kwargs):
        return JsonResponse({
            "ocs": {
                "meta": {"status": "ok", "statuscode": 100, "message": "OK"},
                "data": {
                    "version": {
                        "major": 30, "minor": 0, "micro": 2,
                        "string": "30.0.2", "edition": "", "extendedSupport": False
                    },
                    "capabilities": {
                        "core": {
                            "pollinterval": 60,
                            "webdav-root": "remote.php/dav",
                        },
                        "dav": {
                            "chunking": "1.0",
                        },
                        "files": {
                            "bigfilechunking": True,
                            "versioning": False,
                        },
                    }
                }
            }
        })


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

        return render(request, 'login_flow.html', {'form': form})


@method_decorator(csrf_exempt, name='dispatch')
class LoginPoll(View):
    def post(self, request):
        try:
            data = json.loads(request.body)
        except (json.JSONDecodeError, ValueError):
            data = request.POST
        token = data.get('token')
        
        try:
            login_token = LoginToken.objects.get(token=token)
        except LoginToken.DoesNotExist:
            return JsonResponse({"error": "Invalid token"}, status=404)

        if not login_token.validated or login_token.is_expired():
            return JsonResponse({"error": "Not authorized yet"}, status=404)
        
        protocol = "https" if request.is_secure() else "http"

        app_token = AppToken(
            user=login_token.user,
            name=f"Login flow {login_token.token[:8]}",
        )
        app_token.save()

        json_content = {
            "server": f"{protocol}://{request.get_host()}",
            "loginName": login_token.user.username,
            "appPassword": app_token.token,
        }

        logger.debug("LoginPoll response: %s", json_content)

        return JsonResponse(json_content)


class WebLoginView(View):
    def get(self, request):
        if request.user.is_authenticated:
            return redirect('browse_files_root')
        form = AuthenticationForm()
        return render(request, 'file/login.html', {'form': form})

    def post(self, request):
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            next_url = request.GET.get('next', 'browse_files_root')
            return redirect(next_url)
        return render(request, 'file/login.html', {'form': form})


class WebLogoutView(View):
    def get(self, request):
        logout(request)
        return redirect('login')


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

        # Add display_name to files (strip the uploads/ prefix)
        for f in files:
            f.display_name = os.path.basename(f.file.name)

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

        # Build breadcrumb parts for the navbar
        breadcrumb_parts = []
        if path:
            parts = path.strip('/').split('/')
            for i, part in enumerate(parts):
                breadcrumb_parts.append({
                    'name': part,
                    'path': '/'.join(parts[:i + 1]),
                })

        context = {
            'current_folder': folder,
            'current_path': path,
            'subfolders': subfolders,
            'files': files,
            'parent_path': parent_path,
            'breadcrumb_parts': breadcrumb_parts,
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
                parent=folder,
                file__icontains=uploaded_file.name
            ).first()
            
            if existing_file:
                messages.error(request, f'File "{uploaded_file.name}" already exists in this folder.')
                return redirect(request.path)

            # Create new file
            try:
                new_file = File(
                    owner=request.user,
                    parent=folder,
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

            if '/' in folder_name:
                messages.error(request, 'Folder name cannot contain slash (/) characters.')
                return redirect(request.path)

            existing_folder = Folder.objects.filter(
                owner=request.user,
                parent=folder,
                name=folder_name
            ).first()

            if existing_folder:
                messages.error(request, f'Folder "{folder_name}" already exists.')
                return redirect(request.path)

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

        # Handle text file creation
        elif 'text_filename' in request.POST:
            filename = request.POST.get('text_filename', '').strip()
            if not filename:
                messages.error(request, 'Filename cannot be empty.')
                return redirect(request.path)

            if '/' in filename:
                messages.error(request, 'Filename cannot contain slash (/) characters.')
                return redirect(request.path)

            existing = File.objects.filter(
                owner=request.user,
                parent=folder,
                full_path=f"{folder.full_path}{filename}"
            ).first()

            if existing:
                messages.error(request, f'File "{filename}" already exists.')
                return redirect(request.path)

            try:
                file_obj = ContentFile(b'', name=filename)
                new_file = File(
                    owner=request.user,
                    parent=folder,
                    file=file_obj
                )
                new_file.save()
                messages.success(request, f'File "{filename}" created successfully.')
            except Exception as e:
                messages.error(request, f'Error creating file: {str(e)}')

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
        if file_obj.parent.full_path == f"/{request.user.username}/":
            return redirect('browse_files_root')
        else:
            # Remove username prefix from path for URL
            folder_path = file_obj.parent.full_path.replace(f"/{request.user.username}/", "", 1).rstrip('/')
            return redirect('browse_files', path=folder_path)


class FolderDeleteView(LoginRequiredMixin, View):
    def post(self, request, folder_id):
        folder = get_object_or_404(Folder, id=folder_id, owner=request.user)

        # Prevent deletion of root folder
        if folder.full_path == f"/{request.user.username}/":
            messages.error(request, 'Cannot delete root folder.')
            return redirect('browse_files_root')

        try:
            folder_name = folder.name
            parent_folder = folder.parent
            self._delete_recursive(folder)
            messages.success(request, f'Folder "{folder_name}" deleted successfully.')
        except Exception as e:
            messages.error(request, f'Error deleting folder: {str(e)}')

        # Redirect back to parent folder
        if parent_folder and parent_folder.full_path != f"/{request.user.username}/":
            parent_path = parent_folder.full_path.replace(f"/{request.user.username}/", "", 1).rstrip('/')
            return redirect('browse_files', path=parent_path)
        else:
            return redirect('browse_files_root')

    def _delete_recursive(self, folder):
        """Delete a folder and all its contents recursively."""
        # Delete all files in this folder
        for file_obj in folder.files.all():
            if file_obj.file and os.path.exists(file_obj.file.path):
                os.remove(file_obj.file.path)
            file_obj.delete()

        # Recurse into subfolders
        for subfolder in folder.subfolders.all():
            self._delete_recursive(subfolder)

        folder.delete()


class MoveItemView(LoginRequiredMixin, View):
    template_name = 'file/move_picker.html'
    
    def get(self, request, item_type, item_id):
        # Get the item to be moved
        if item_type == 'file':
            item = get_object_or_404(File, id=item_id, owner=request.user)
            current_folder = item.parent
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
        if file.parent == destination_folder:
            raise Exception('File is already in the destination folder.')

        # Check for name conflicts
        existing_file = File.objects.filter(
            owner=file.owner,
            parent=destination_folder,
            file__icontains=os.path.basename(file.file.name)
        ).exclude(id=file.id).first()

        if existing_file:
            raise Exception(f'A file with this name already exists in the destination folder.')

        file.parent = destination_folder
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
            file.save()  # Triggers path recalculation


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


class RenameItemView(LoginRequiredMixin, View):
    def post(self, request, item_type, item_id):
        new_name = request.POST.get('new_name', '').strip()
        if not new_name:
            messages.error(request, 'Name cannot be empty.')
            return redirect(request.META.get('HTTP_REFERER', 'browse_files_root'))

        if '/' in new_name:
            messages.error(request, 'Name cannot contain slash (/) characters.')
            return redirect(request.META.get('HTTP_REFERER', 'browse_files_root'))

        if item_type == 'folder':
            item = get_object_or_404(Folder, id=item_id, owner=request.user)
            if item.parent is None:
                messages.error(request, 'Cannot rename root folder.')
                return redirect('browse_files_root')

            # Check for name conflicts
            if Folder.objects.filter(owner=request.user, parent=item.parent, name=new_name).exclude(id=item.id).exists():
                messages.error(request, f'A folder named "{new_name}" already exists here.')
                return redirect(request.META.get('HTTP_REFERER', 'browse_files_root'))

            item.name = new_name
            item.save()
            self._update_paths_recursive(item)
            messages.success(request, f'Folder renamed to "{new_name}".')

        elif item_type == 'file':
            item = get_object_or_404(File, id=item_id, owner=request.user)

            # Check for name conflicts
            if File.objects.filter(owner=request.user, parent=item.parent, full_path=f"{item.parent.full_path}{new_name}").exclude(id=item.id).exists():
                messages.error(request, f'A file named "{new_name}" already exists here.')
                return redirect(request.META.get('HTTP_REFERER', 'browse_files_root'))

            # Rename the physical file
            old_path = item.file.path
            new_file_path = os.path.join(os.path.dirname(old_path), new_name)
            if os.path.exists(old_path):
                os.rename(old_path, new_file_path)
            item.file.name = os.path.join(os.path.dirname(item.file.name), new_name)
            item.content_type = None  # Will be recalculated on save
            item.save()
            messages.success(request, f'File renamed to "{new_name}".')
        else:
            messages.error(request, 'Invalid item type.')

        return redirect(request.META.get('HTTP_REFERER', 'browse_files_root'))

    def _update_paths_recursive(self, folder):
        for subfolder in folder.subfolders.all():
            subfolder.save()
            self._update_paths_recursive(subfolder)
        for f in folder.files.all():
            f.save()


class FilePreviewView(LoginRequiredMixin, View):
    def get(self, request, file_id):
        file_obj = get_object_or_404(File, id=file_id, owner=request.user)

        if not file_obj.file or not os.path.exists(file_obj.file.path):
            raise Http404("File not found")

        content_type = file_obj.content_type or ''
        display_name = os.path.basename(file_obj.file.name)

        # Serve the file inline for previewable types
        if content_type.startswith('image/') or content_type == 'application/pdf':
            response = FileResponse(
                open(file_obj.file.path, 'rb'),
                content_type=content_type
            )
            response['Content-Disposition'] = f'inline; filename="{display_name}"'
            return response

        # For text files, read content and show in a template
        if content_type.startswith('text/') or content_type in ('application/json', 'application/xml', 'application/javascript'):
            try:
                with open(file_obj.file.path, 'r', errors='replace') as f:
                    text_content = f.read(1024 * 512)  # 512KB max
            except Exception:
                raise Http404("Cannot read file")

            return render(request, 'file/preview_text.html', {
                'file': file_obj,
                'display_name': display_name,
                'text_content': text_content,
            })

        # Fallback: download
        return redirect('download_file', file_id=file_id)


class FolderTreeView(LoginRequiredMixin, View):
    """API endpoint returning the full folder tree for the sidebar."""
    def get(self, request):
        root = Folder.objects.filter(
            owner=request.user, parent__isnull=True, name__isnull=True
        ).first()
        if not root:
            return JsonResponse({'tree': []})

        def build_tree(folder):
            children = folder.subfolders.filter(owner=request.user).order_by('name')
            url_path = ''
            if folder.full_path != f"/{request.user.username}/":
                url_path = folder.full_path.replace(f"/{request.user.username}/", "", 1).rstrip('/')
            return {
                'id': folder.id,
                'name': folder.name or 'Home',
                'url_path': url_path,
                'children': [build_tree(c) for c in children],
            }

        return JsonResponse({'tree': build_tree(root)})
