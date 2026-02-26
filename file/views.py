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
from .models import User, AppToken, LoginToken, Folder, File, SharedFolder, SharedFolderMembership
from django.views import View
from djangodav.views.views import DavView
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.contrib.auth.forms import AuthenticationForm
import logging

logger = logging.getLogger(__name__)


def _get_shared_membership(user, obj):
    """Check if an object (File or Folder) is in a shared folder the user has access to."""
    if not obj.full_path.startswith('/__shared__/'):
        return None
    parts = obj.full_path.split('/')
    if len(parts) < 3:
        return None
    share_name = parts[2]
    return SharedFolderMembership.objects.filter(
        shared_folder__name=share_name, user=user
    ).select_related('shared_folder').first()


def get_accessible_file(request, file_id, permission='read'):
    """Get a file the user can access (personal or shared)."""
    try:
        return File.objects.get(id=file_id, owner=request.user), True
    except File.DoesNotExist:
        pass
    file_obj = get_object_or_404(File, id=file_id)
    membership = _get_shared_membership(request.user, file_obj)
    if not membership:
        raise Http404
    if permission == 'write' and membership.permission not in ('write', 'admin'):
        raise Http404
    can_write = membership.permission in ('write', 'admin')
    return file_obj, can_write


def get_accessible_folder(request, folder_id, permission='read'):
    """Get a folder the user can access (personal or shared)."""
    try:
        return Folder.objects.get(id=folder_id, owner=request.user), True
    except Folder.DoesNotExist:
        pass
    folder = get_object_or_404(Folder, id=folder_id)
    membership = _get_shared_membership(request.user, folder)
    if not membership:
        raise Http404
    if permission == 'write' and membership.permission not in ('write', 'admin'):
        raise Http404
    can_write = membership.permission in ('write', 'admin')
    return folder, can_write


def _redirect_to_folder(request, folder):
    """Redirect to the browse view for a given folder."""
    if folder.full_path.startswith('/__shared__/'):
        folder_path = folder.full_path.lstrip('/').rstrip('/')
        return redirect('browse_files', path=folder_path)
    if folder.full_path == f"/{request.user.username}/":
        return redirect('browse_files_root')
    folder_path = folder.full_path.replace(f"/{request.user.username}/", "", 1).rstrip('/')
    return redirect('browse_files', path=folder_path)


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

@method_decorator(csrf_exempt, name='dispatch')
class RootView(View):
    def get(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect('browse_files_root')
        return redirect('login')


@method_decorator(csrf_exempt, name='dispatch')
class DavEntryView(BasicAuthMixin, DavView):
    """WebDAV entry point at /dav/ that auto-injects the authenticated user's username."""

    def get_resource(self, path=None):
        if path is None:
            path = self.path
        return self.resource_class(path, user=self.request.user)

    def dispatch(self, request, *args, **kwargs):
        kwargs.pop('username', None)
        return super().dispatch(request, *args, **kwargs)

    def relocate(self, request, path, method, *args, **kwargs):
        from urllib import parse as urlparse
        dst_header = request.META.get('HTTP_DESTINATION', '')
        logger.debug("MOVE/COPY destination header: %s, base_url: %s", dst_header, self.base_url)
        dst_url = urlparse.unquote(dst_header)
        if not dst_url:
            return HttpResponseBadRequest('Destination header missing.')
        dparts = urlparse.urlparse(dst_url)
        sparts = urlparse.urlparse(request.build_absolute_uri())
        if dparts.netloc and sparts.netloc != dparts.netloc:
            from djangodav.responses import HttpResponseBadGateway
            return HttpResponseBadGateway('Source and destination must have the same host.')
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
        if response.status_code in (201, 204):
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

    def _validate_token(self, token):
        try:
            login_token = LoginToken.objects.get(token=token)
        except LoginToken.DoesNotExist:
            return None
        if login_token.validated:
            return None
        if login_token.is_expired():
            return None
        return login_token

    def _success_response(self, request):
        return render(request, 'login_flow_success.html')

    def get(self, request, token):
        login_token = self._validate_token(token)
        if not login_token:
            return render(request, 'login_flow_error.html', {
                'title': 'Invalid link',
                'message': 'This authorization link is invalid or has expired. Please try again from your application.',
            }, status=404)

        context = {
            'form': AuthenticationForm(),
            'already_logged_in': request.user.is_authenticated,
        }
        return render(request, 'login_flow.html', context)

    def post(self, request, token):
        login_token = self._validate_token(token)
        if not login_token:
            return render(request, 'login_flow_error.html', {
                'title': 'Invalid link',
                'message': 'This authorization link is invalid or has expired. Please try again from your application.',
            }, status=404)

        # If user has an active session and clicked "Authorize device"
        if request.POST.get('use_session') and request.user.is_authenticated:
            login_token.user = request.user
            login_token.validated = True
            login_token.save()
            return self._success_response(request)

        # Otherwise, authenticate with username/password
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login_token.user = user
            login_token.validated = True
            login_token.save()
            login(request, user)
            return self._success_response(request)

        return render(request, 'login_flow.html', {
            'form': form,
            'already_logged_in': request.user.is_authenticated,
        })


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

    def _resolve_folder(self, request, path):
        """Resolve path to (folder, is_shared, can_write, is_shared_root).
        Returns the folder object and context flags."""
        stripped = path.strip('/')

        # Shared folders listing
        if stripped == '__shared__':
            return None, True, False, True

        # Inside a shared folder
        if stripped.startswith('__shared__/'):
            parts = stripped.split('/')
            share_name = parts[1]
            sf = get_object_or_404(SharedFolder, name=share_name)
            membership = get_object_or_404(
                SharedFolderMembership, shared_folder=sf, user=request.user)
            can_write = membership.permission in ('write', 'admin')

            if len(parts) == 2:
                return sf.root_folder, True, can_write, False
            sub_path = '/'.join(parts[2:])
            full_path = f"/__shared__/{share_name}/{sub_path}/"
            folder = get_object_or_404(Folder, full_path=full_path)
            return folder, True, can_write, False

        # Personal folder
        normalized_path = '/' + stripped
        if normalized_path == '/':
            folder = get_object_or_404(
                Folder, owner=request.user, full_path=f"/{request.user.username}/")
        else:
            user_path = f"/{request.user.username}{normalized_path}/"
            folder = get_object_or_404(Folder, owner=request.user, full_path=user_path)
        return folder, False, True, False

    def _folder_url_path(self, request, subfolder):
        """Convert a folder's full_path to a browse URL path."""
        if subfolder.full_path.startswith('/__shared__/'):
            return subfolder.full_path.lstrip('/').rstrip('/')
        if subfolder.full_path == f"/{request.user.username}/":
            return ''
        return subfolder.full_path.replace(f"/{request.user.username}/", "", 1).rstrip('/')

    def get(self, request, path=''):
        folder, is_shared, can_write, is_shared_root = self._resolve_folder(request, path)

        # Special case: listing all shared folders
        if is_shared_root:
            memberships = SharedFolderMembership.objects.filter(
                user=request.user
            ).select_related('shared_folder__root_folder')
            shared_folders = []
            for m in memberships:
                sf = m.shared_folder
                sf.url_path = f"__shared__/{sf.name}"
                sf.permission = m.permission
                shared_folders.append(sf)

            context = {
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
            }
            return render(request, self.template_name, context)

        if is_shared:
            subfolders = folder.subfolders.all().order_by('name')
            files = folder.files.all().order_by('file')
        else:
            subfolders = folder.subfolders.filter(owner=request.user).order_by('name')
            files = folder.files.filter(owner=request.user).order_by('file')

        for f in files:
            f.display_name = os.path.basename(f.file.name)

        for subfolder in subfolders:
            subfolder.url_path = self._folder_url_path(request, subfolder)

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
            if parent_full_path == f"/{request.user.username}/":
                parent_path = ''
            else:
                parent_path = parent_full_path.replace(f"/{request.user.username}/", "", 1).rstrip('/')

        # Breadcrumbs
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
            'is_shared': is_shared,
            'can_write': can_write,
        }
        return render(request, self.template_name, context)

    def post(self, request, path=''):
        folder, is_shared, can_write, is_shared_root = self._resolve_folder(request, path)

        if is_shared_root or not can_write:
            messages.error(request, 'You do not have write access here.')
            return redirect(request.path)

        # Handle file upload
        if 'file' in request.FILES:
            uploaded_file = request.FILES.get('file')
            if not uploaded_file:
                messages.error(request, 'No file selected for upload.')
                return redirect(request.path)

            existing_file = File.objects.filter(
                parent=folder,
                full_path=f"{folder.full_path}{uploaded_file.name}"
            ).first()

            if existing_file:
                messages.error(request, f'File "{uploaded_file.name}" already exists in this folder.')
                return redirect(request.path)

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
        file_obj, _ = get_accessible_file(request, file_id, permission='read')
        
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
        file_obj, _ = get_accessible_file(request, file_id, permission='write')
        
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
        
        return _redirect_to_folder(request, file_obj.parent)


class FolderDeleteView(LoginRequiredMixin, View):
    def post(self, request, folder_id):
        folder, can_write = get_accessible_folder(request, folder_id, permission='write')

        # Prevent deletion of root folders
        if folder.parent is None:
            messages.error(request, 'Cannot delete root folder.')
            return redirect('browse_files_root')

        try:
            folder_name = folder.name
            parent_folder = folder.parent
            self._delete_recursive(folder)
            messages.success(request, f'Folder "{folder_name}" deleted successfully.')
        except Exception as e:
            messages.error(request, f'Error deleting folder: {str(e)}')

        if parent_folder:
            return _redirect_to_folder(request, parent_folder)
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
        if item_type == 'file':
            item, _ = get_accessible_file(request, item_id, permission='write')
        elif item_type == 'folder':
            item, _ = get_accessible_folder(request, item_id, permission='write')
        else:
            messages.error(request, 'Invalid item type.')
            return redirect('browse_files_root')

        root_folder = get_object_or_404(Folder, owner=request.user, full_path=f"/{request.user.username}/")
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
        if item_type == 'file':
            item, _ = get_accessible_file(request, item_id, permission='write')
        elif item_type == 'folder':
            item, _ = get_accessible_folder(request, item_id, permission='write')
        else:
            messages.error(request, 'Invalid item type.')
            return redirect('browse_files_root')

        destination_folder_id = request.POST.get('destination_folder_id')
        if not destination_folder_id:
            messages.error(request, 'No destination folder selected.')
            return redirect(request.META.get('HTTP_REFERER', 'browse_files_root'))

        destination_folder, _ = get_accessible_folder(request, int(destination_folder_id), permission='write')

        try:
            with transaction.atomic():
                if item_type == 'file':
                    self._move_file(item, destination_folder)
                    messages.success(request, f'File moved successfully.')
                else:
                    self._move_folder(item, destination_folder)
                    messages.success(request, f'Folder "{item.name}" moved successfully.')
        except Exception as e:
            messages.error(request, f'Error moving {item_type}: {str(e)}')

        return _redirect_to_folder(request, destination_folder)
    
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
    def _folder_path(self, request, folder):
        """Convert a folder's full_path to a browse URL path."""
        if folder.full_path.startswith('/__shared__/'):
            return folder.full_path.lstrip('/').rstrip('/')
        if folder.full_path == f"/{request.user.username}/":
            return ''
        return folder.full_path.replace(f"/{request.user.username}/", "", 1).rstrip('/')

    def get(self, request, folder_id=None):
        """AJAX endpoint to get folder contents for the move picker"""
        if folder_id:
            folder, _ = get_accessible_folder(request, folder_id, permission='read')
        else:
            folder = get_object_or_404(Folder, owner=request.user, full_path=f"/{request.user.username}/")

        is_shared = folder.full_path.startswith('/__shared__/')

        # Build breadcrumbs
        breadcrumbs = []
        current = folder
        while current:
            if current.full_path == f"/{request.user.username}/":
                breadcrumbs.insert(0, {'name': 'Root', 'id': current.id, 'path': ''})
            else:
                breadcrumbs.insert(0, {
                    'name': current.name or current.full_path.strip('/').split('/')[-1],
                    'id': current.id,
                    'path': self._folder_path(request, current),
                })
            current = current.parent

        # Get subfolders
        if is_shared:
            children = folder.subfolders.all().order_by('name')
        else:
            children = folder.subfolders.filter(owner=request.user).order_by('name')

        subfolders = []
        for subfolder in children:
            subfolders.append({
                'id': subfolder.id,
                'name': subfolder.name,
                'path': self._folder_path(request, subfolder),
            })

        return JsonResponse({
            'folder': {
                'id': folder.id,
                'name': folder.name or 'Root',
                'path': self._folder_path(request, folder),
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
            item, can_write = get_accessible_folder(request, item_id, permission='write')
            if item.parent is None:
                messages.error(request, 'Cannot rename root folder.')
                return redirect('browse_files_root')

            # Check for name conflicts
            if Folder.objects.filter(parent=item.parent, name=new_name).exclude(id=item.id).exists():
                messages.error(request, f'A folder named "{new_name}" already exists here.')
                return redirect(request.META.get('HTTP_REFERER', 'browse_files_root'))

            item.name = new_name
            item.save()
            self._update_paths_recursive(item)
            messages.success(request, f'Folder renamed to "{new_name}".')

        elif item_type == 'file':
            item, can_write = get_accessible_file(request, item_id, permission='write')

            # Check for name conflicts
            if File.objects.filter(parent=item.parent, full_path=f"{item.parent.full_path}{new_name}").exclude(id=item.id).exists():
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
        file_obj, _ = get_accessible_file(request, file_id, permission='read')

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

        def build_tree(folder, is_shared=False):
            if is_shared:
                children = folder.subfolders.all().order_by('name')
            else:
                children = folder.subfolders.filter(owner=request.user).order_by('name')
            if folder.full_path.startswith('/__shared__/'):
                url_path = folder.full_path.lstrip('/').rstrip('/')
            elif folder.full_path == f"/{request.user.username}/":
                url_path = ''
            else:
                url_path = folder.full_path.replace(f"/{request.user.username}/", "", 1).rstrip('/')
            return {
                'id': folder.id,
                'name': folder.name or 'Home',
                'url_path': url_path,
                'children': [build_tree(c, is_shared=is_shared) for c in children],
            }

        personal_tree = build_tree(root) if root else None

        # Shared folders
        from .models import SharedFolderMembership
        memberships = SharedFolderMembership.objects.filter(
            user=request.user
        ).select_related('shared_folder__root_folder')
        shared_trees = []
        for m in memberships:
            sf = m.shared_folder
            tree = build_tree(sf.root_folder, is_shared=True)
            tree['name'] = sf.name
            tree['sf_id'] = sf.id
            tree['url_path'] = f"__shared__/{sf.name}"
            shared_trees.append(tree)

        is_admin = request.user.role == 'admin'
        return JsonResponse({'tree': personal_tree, 'shared': shared_trees, 'is_admin': is_admin})


class SharedFolderCreateView(LoginRequiredMixin, View):
    def post(self, request):
        if request.user.role != 'admin':
            return JsonResponse({'error': 'Forbidden'}, status=403)
        try:
            data = json.loads(request.body)
        except (json.JSONDecodeError, ValueError):
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        name = data.get('name', '').strip()
        if not name:
            return JsonResponse({'error': 'Name is required'}, status=400)
        if '/' in name:
            return JsonResponse({'error': 'Name cannot contain /'}, status=400)
        if SharedFolder.objects.filter(name=name).exists():
            return JsonResponse({'error': 'A shared folder with this name already exists'}, status=400)
        sf = SharedFolder(name=name, created_by=request.user)
        sf.save()
        SharedFolderMembership.objects.create(
            shared_folder=sf, user=request.user, permission='admin')
        return JsonResponse({'id': sf.id, 'name': sf.name})


class SharedFolderMembersView(LoginRequiredMixin, View):
    def _can_manage(self, request, sf):
        if request.user.role == 'admin':
            return True
        return sf.memberships.filter(user=request.user, permission='admin').exists()

    def get(self, request, sf_id):
        sf = get_object_or_404(SharedFolder, id=sf_id)
        if not self._can_manage(request, sf):
            return JsonResponse({'error': 'Forbidden'}, status=403)
        members = []
        for m in sf.memberships.select_related('user').order_by('user__username'):
            members.append({
                'user_id': m.user.id,
                'username': m.user.username,
                'permission': m.permission,
            })
        return JsonResponse({'members': members})

    def post(self, request, sf_id):
        sf = get_object_or_404(SharedFolder, id=sf_id)
        if not self._can_manage(request, sf):
            return JsonResponse({'error': 'Forbidden'}, status=403)
        try:
            data = json.loads(request.body)
        except (json.JSONDecodeError, ValueError):
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        user_id = data.get('user_id')
        permission = data.get('permission', 'read')
        if permission not in ('read', 'write', 'admin'):
            return JsonResponse({'error': 'Invalid permission'}, status=400)
        user = get_object_or_404(User, id=user_id)
        membership, created = SharedFolderMembership.objects.update_or_create(
            shared_folder=sf, user=user,
            defaults={'permission': permission})
        return JsonResponse({
            'user_id': user.id,
            'username': user.username,
            'permission': membership.permission,
            'created': created,
        })


class SharedFolderMemberDeleteView(LoginRequiredMixin, View):
    def delete(self, request, sf_id, user_id):
        sf = get_object_or_404(SharedFolder, id=sf_id)
        if request.user.role != 'admin':
            if not sf.memberships.filter(user=request.user, permission='admin').exists():
                return JsonResponse({'error': 'Forbidden'}, status=403)
        deleted, _ = SharedFolderMembership.objects.filter(
            shared_folder=sf, user_id=user_id).delete()
        if not deleted:
            return JsonResponse({'error': 'Membership not found'}, status=404)
        return JsonResponse({'ok': True})


class UserListView(LoginRequiredMixin, View):
    def get(self, request):
        users = User.objects.order_by('username').values_list('id', 'username', flat=False)
        return JsonResponse({'users': [{'id': u[0], 'username': u[1]} for u in users]})
