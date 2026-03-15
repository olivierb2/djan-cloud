from django.contrib.auth import authenticate, login, logout
from django.http import HttpResponse, HttpResponseBadRequest, JsonResponse, FileResponse, Http404
from django.shortcuts import render, get_object_or_404, redirect
from django.urls import reverse
from django.contrib import messages
from django.db import transaction
from django.conf import settings
from django.db import models
from django.utils import timezone
from django.core.files.base import ContentFile
import base64
import json
import secrets
import os
from django.contrib.auth.mixins import LoginRequiredMixin
from .models import (
    User, AppToken, LoginToken, Folder, File, SharedFolder, SharedFolderMembership,
    Calendar, CalendarShare, Event,
    AddressBook, AddressBookShare, Contact,
    Mailbox, Email, EmailAttachment, EmailSignature,
)
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

        # Also check Bearer token (some clients use OAuth-style flow)
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]
            try:
                app_token = AppToken.objects.select_related('user').get(token=token)
                app_token.last_used_at = timezone.now()
                app_token.save(update_fields=['last_used_at'])
                request.user = app_token.user
                return super().dispatch(request, *args, **kwargs)
            except AppToken.DoesNotExist:
                pass

        # If authentication fails -> return 401 with WWW-Authenticate header
        response = HttpResponse("Unauthorized", status=401)
        response["WWW-Authenticate"] = 'Basic realm="Djancloud"'
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
                            "calendars": True,
                            "contacts": True,
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
                    file=uploaded_file,
                    display_name=uploaded_file.name
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
                    file=file_obj,
                    display_name=filename
                )
                new_file.save()
                messages.success(request, f'File "{filename}" created successfully.')
            except Exception as e:
                messages.error(request, f'Error creating file: {str(e)}')

        return redirect(request.path)


class SearchView(LoginRequiredMixin, View):
    def get(self, request):
        query = request.GET.get('q', '').strip()
        if not query or len(query) < 2:
            return JsonResponse({'results': []})

        results = []

        # Search in personal files
        personal_files = File.objects.filter(
            owner=request.user,
            display_name__icontains=query
        ).select_related('parent')[:20]

        for file in personal_files:
            path_display = file.full_path.replace(f"/{request.user.username}/", "", 1)
            # Navigate to parent folder with file highlight
            parent_path = file.parent.full_path.replace(f"/{request.user.username}/", "", 1).rstrip('/')
            folder_url = reverse('browse_files', kwargs={'path': parent_path}) if parent_path else reverse('browse_files_root')
            folder_url += f'#file-{file.id}'
            results.append({
                'type': 'file',
                'id': file.id,
                'name': file.display_name,
                'path': path_display,
                'url': folder_url,
                'location': 'Personal',
                'content_type': file.content_type
            })

        # Search in personal folders
        personal_folders = Folder.objects.filter(
            owner=request.user,
            name__icontains=query
        ).exclude(name__isnull=True)[:20]

        for folder in personal_folders:
            path_display = folder.full_path.replace(f"/{request.user.username}/", "", 1).rstrip('/')
            browse_path = path_display if path_display else ''
            results.append({
                'type': 'folder',
                'id': folder.id,
                'name': folder.name,
                'path': path_display,
                'url': reverse('browse_files', kwargs={'path': browse_path}) if browse_path else reverse('browse_files_root'),
                'location': 'Personal'
            })

        # Search in shared folders
        shared_memberships = SharedFolderMembership.objects.filter(
            user=request.user
        ).select_related('shared_folder__root_folder')

        for membership in shared_memberships:
            root = membership.shared_folder.root_folder

            # Search files in this shared folder
            shared_files = File.objects.filter(
                full_path__startswith=root.full_path,
                display_name__icontains=query
            ).select_related('parent')[:20]

            for file in shared_files:
                path_display = file.full_path.lstrip('/')
                # Navigate to parent folder with file highlight
                parent_path = file.parent.full_path.lstrip('/').rstrip('/')
                folder_url = reverse('browse_files', kwargs={'path': parent_path})
                folder_url += f'#file-{file.id}'
                results.append({
                    'type': 'file',
                    'id': file.id,
                    'name': file.display_name,
                    'path': path_display,
                    'url': folder_url,
                    'location': f'Shared: {membership.shared_folder.name}',
                    'content_type': file.content_type
                })

            # Search folders in this shared folder
            shared_folders = Folder.objects.filter(
                full_path__startswith=root.full_path,
                name__icontains=query
            ).exclude(name__isnull=True)[:20]

            for folder in shared_folders:
                path_display = folder.full_path.lstrip('/').rstrip('/')
                results.append({
                    'type': 'folder',
                    'id': folder.id,
                    'name': folder.name,
                    'path': path_display,
                    'url': reverse('browse_files', kwargs={'path': path_display}),
                    'location': f'Shared: {membership.shared_folder.name}'
                })

        return JsonResponse({'results': results[:50]})


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

        # Shared folders with write access
        memberships = SharedFolderMembership.objects.filter(
            user=request.user, permission__in=['write', 'admin']
        ).select_related('shared_folder__root_folder')
        shared_folders = [{'id': m.shared_folder.root_folder.id, 'name': m.shared_folder.name} for m in memberships]

        context = {
            'item': item,
            'item_type': item_type,
            'current_folder': root_folder,
            'subfolders': root_folder.subfolders.filter(owner=request.user).order_by('name'),
            'shared_folders': shared_folders,
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

        response = {
            'folder': {
                'id': folder.id,
                'name': folder.name or 'Root',
                'path': self._folder_path(request, folder),
            },
            'breadcrumbs': breadcrumbs,
            'subfolders': subfolders,
        }

        # When at user root, also include writable shared folders
        if not folder_id or folder.full_path == f"/{request.user.username}/":
            memberships = SharedFolderMembership.objects.filter(
                user=request.user, permission__in=['write', 'admin']
            ).select_related('shared_folder__root_folder')
            shared = []
            for m in memberships:
                sf = m.shared_folder
                shared.append({
                    'id': sf.root_folder.id,
                    'name': sf.name,
                    'path': self._folder_path(request, sf.root_folder),
                })
            response['shared_folders'] = shared

        return JsonResponse(response)


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
            item.display_name = new_name
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
        users = User.objects.order_by('username')
        return JsonResponse({'users': [
            {'id': u.id, 'username': u.username, 'first_name': u.first_name,
             'last_name': u.last_name, 'full_name': u.get_full_name(),
             'email': u.email, 'role': u.role, 'is_active': u.is_active}
            for u in users
        ]})


class UserCreateView(LoginRequiredMixin, View):
    def post(self, request):
        if request.user.role != 'admin':
            return JsonResponse({'error': 'Forbidden'}, status=403)
        data = json.loads(request.body)
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        email = data.get('email', '').strip()
        first_name = data.get('first_name', '').strip()
        last_name = data.get('last_name', '').strip()
        role = data.get('role', 'user')
        if not username or not password:
            return JsonResponse({'error': 'Username and password are required.'}, status=400)
        if User.objects.filter(username=username).exists():
            return JsonResponse({'error': 'Username already exists.'}, status=400)
        if email and User.objects.filter(email=email).exists():
            return JsonResponse({'error': 'Email already in use.'}, status=400)
        if role not in ('user', 'admin'):
            role = 'user'
        user = User.objects.create_user(
            username=username, password=password, email=email,
            first_name=first_name, last_name=last_name, role=role,
        )
        return JsonResponse({
            'id': user.id, 'username': user.username, 'email': user.email,
            'first_name': user.first_name, 'last_name': user.last_name, 'role': user.role,
        })


class UserUpdateView(LoginRequiredMixin, View):
    def post(self, request, user_id):
        if request.user.role != 'admin':
            return JsonResponse({'error': 'Forbidden'}, status=403)
        user = get_object_or_404(User, id=user_id)
        data = json.loads(request.body)

        if 'first_name' in data:
            user.first_name = data['first_name'].strip()

        if 'last_name' in data:
            user.last_name = data['last_name'].strip()

        if 'email' in data:
            email_val = data['email'].strip()
            if email_val and User.objects.filter(email=email_val).exclude(id=user.id).exists():
                return JsonResponse({'error': 'Email already in use.'}, status=400)
            user.email = email_val

        if 'role' in data and data['role'] in ('user', 'admin'):
            user.role = data['role']

        if 'password' in data and data['password'].strip():
            user.set_password(data['password'].strip())

        if 'is_active' in data:
            user.is_active = bool(data['is_active'])

        user.save()
        return JsonResponse({
            'id': user.id, 'username': user.username,
            'first_name': user.first_name, 'last_name': user.last_name,
            'email': user.email, 'role': user.role,
            'is_active': user.is_active,
        })


class UserDeleteView(LoginRequiredMixin, View):
    def delete(self, request, user_id):
        if request.user.role != 'admin':
            return JsonResponse({'error': 'Forbidden'}, status=403)
        if user_id == request.user.id:
            return JsonResponse({'error': 'Cannot delete yourself.'}, status=400)
        user = get_object_or_404(User, id=user_id)
        user.delete()
        return JsonResponse({'ok': True})


class UserManagementView(LoginRequiredMixin, View):
    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated or request.user.role != 'admin':
            return redirect('browse_files_root')
        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        users = User.objects.order_by('username')
        users_json = json.dumps([
            {'id': u.id, 'username': u.username, 'first_name': u.first_name,
             'last_name': u.last_name, 'full_name': u.get_full_name(),
             'email': u.email, 'role': u.role, 'is_active': u.is_active}
            for u in users
        ])
        return render(request, 'file/users.html', {'users': users, 'users_json': users_json})


class FileEditorView(LoginRequiredMixin, View):
    def get(self, request, file_id):
        file_obj, is_owner = get_accessible_file(request, file_id, permission='read')

        if not file_obj.file or not os.path.exists(file_obj.file.path):
            raise Http404("File not found")

        display_name = os.path.basename(file_obj.file.name)

        try:
            with open(file_obj.file.path, 'r', errors='replace') as f:
                content = f.read()
        except Exception:
            raise Http404("Cannot read file")

        can_write = is_owner
        if not is_owner:
            membership = _get_shared_membership(request.user, file_obj)
            if membership:
                can_write = membership.permission in ('write', 'admin')

        return render(request, 'file/editor.html', {
            'file': file_obj,
            'display_name': display_name,
            'initial_content': json.dumps(content),
            'can_write': can_write,
        })


class FileSaveView(LoginRequiredMixin, View):
    def post(self, request, file_id):
        file_obj, is_owner = get_accessible_file(request, file_id, permission='write')

        if not file_obj.file or not os.path.exists(file_obj.file.path):
            return JsonResponse({'error': 'File not found'}, status=404)

        try:
            data = json.loads(request.body)
        except (json.JSONDecodeError, ValueError):
            return JsonResponse({'error': 'Invalid JSON'}, status=400)

        content = data.get('content', '')

        try:
            with open(file_obj.file.path, 'w', encoding='utf-8') as f:
                f.write(content)
            file_obj.size = os.path.getsize(file_obj.file.path)
            file_obj.save()
            return JsonResponse({'ok': True})
        except Exception as e:
            logger.error(f"Error saving file {file_id}: {e}")
            return JsonResponse({'error': 'Failed to save file'}, status=500)


# ─── Calendar Web Views ──────────────────────────────────────

class CalendarWebView(LoginRequiredMixin, View):
    def get(self, request):
        from .caldav_views import ensure_defaults_for_user
        ensure_defaults_for_user(request.user)

        all_own = list(Calendar.objects.filter(owner=request.user).order_by('display_name'))
        # Personal = default 'personal' calendar; shareable = all others created by user
        own_calendars = [c for c in all_own if c.name == 'personal']
        shareable_calendars = [c for c in all_own if c.name != 'personal']
        shared_ids = CalendarShare.objects.filter(user=request.user).values_list('calendar_id', flat=True)
        shared_calendars = list(Calendar.objects.filter(id__in=shared_ids).select_related('owner').order_by('display_name'))

        selected_calendar = None
        events = []
        shares = []
        can_write = False

        cal_id = request.GET.get('calendar')
        if not cal_id and all_own:
            cal_id = all_own[0].id
        if cal_id:
            try:
                selected_calendar = Calendar.objects.select_related('owner').get(id=cal_id)
                is_owner = selected_calendar.owner_id == request.user.id
                if not is_owner:
                    share = CalendarShare.objects.filter(calendar=selected_calendar, user=request.user).first()
                    if not share:
                        raise Calendar.DoesNotExist
                    can_write = share.permission in ('write', 'admin')
                else:
                    can_write = True
                events = selected_calendar.events.order_by('-dtstart')
                if is_owner:
                    shares = selected_calendar.shares.select_related('user').all()
            except Calendar.DoesNotExist:
                selected_calendar = None

        return render(request, 'file/calendars.html', {
            'calendars': own_calendars,
            'shareable_calendars': shareable_calendars,
            'shared_calendars': shared_calendars,
            'selected_calendar': selected_calendar,
            'events': events,
            'shares': shares,
            'can_write': can_write,
        })


class CalendarCreateView(LoginRequiredMixin, View):
    def post(self, request):
        if request.user.role != 'admin':
            return redirect('calendars')
        display_name = request.POST.get('display_name', '').strip()
        if not display_name:
            messages.error(request, 'Calendar name is required.')
            return redirect('calendars')
        name = display_name.lower().replace(' ', '-')
        # Ensure unique name
        base_name = name
        counter = 1
        while Calendar.objects.filter(owner=request.user, name=name).exists():
            name = f"{base_name}-{counter}"
            counter += 1
        Calendar.objects.create(
            owner=request.user,
            name=name,
            display_name=display_name,
            description=request.POST.get('description', '').strip() or None,
            color=request.POST.get('color', '#0082c9'),
        )
        messages.success(request, f'Calendar "{display_name}" created.')
        return redirect('calendars')


class CalendarDeleteView(LoginRequiredMixin, View):
    def post(self, request, calendar_id):
        cal = get_object_or_404(Calendar, id=calendar_id, owner=request.user)
        name = cal.display_name
        cal.delete()
        messages.success(request, f'Calendar "{name}" deleted.')
        return redirect('calendars')


class CalendarShareAddView(LoginRequiredMixin, View):
    def get(self, request, calendar_id):
        cal = get_object_or_404(Calendar, id=calendar_id, owner=request.user)
        shares = CalendarShare.objects.filter(calendar=cal).select_related('user')
        return JsonResponse({'shares': [
            {'user_id': s.user_id, 'username': s.user.username, 'permission': s.permission}
            for s in shares
        ]})

    def post(self, request, calendar_id):
        cal = get_object_or_404(Calendar, id=calendar_id, owner=request.user)
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        if is_ajax:
            data = json.loads(request.body)
            username = data.get('username', '').strip()
            permission = data.get('permission', 'read')
        else:
            username = request.POST.get('username', '').strip()
            permission = request.POST.get('permission', 'read')
        try:
            target_user = User.objects.get(username=username)
        except User.DoesNotExist:
            if is_ajax:
                return JsonResponse({'error': f'User "{username}" not found.'}, status=400)
            messages.error(request, f'User "{username}" not found.')
            return redirect(f'/calendars/?calendar={calendar_id}')
        if target_user == request.user:
            if is_ajax:
                return JsonResponse({'error': 'Cannot share with yourself.'}, status=400)
            messages.error(request, 'Cannot share with yourself.')
            return redirect(f'/calendars/?calendar={calendar_id}')
        CalendarShare.objects.update_or_create(
            calendar=cal, user=target_user,
            defaults={'permission': permission},
        )
        if is_ajax:
            return JsonResponse({'ok': True})
        messages.success(request, f'Shared with {username}.')
        return redirect(f'/calendars/?calendar={calendar_id}')


class CalendarShareDeleteView(LoginRequiredMixin, View):
    def post(self, request, calendar_id, user_id):
        cal = get_object_or_404(Calendar, id=calendar_id, owner=request.user)
        CalendarShare.objects.filter(calendar=cal, user_id=user_id).delete()
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'ok': True})
        messages.success(request, 'Share removed.')
        return redirect(f'/calendars/?calendar={calendar_id}')


class CalendarEventsApiView(LoginRequiredMixin, View):
    def get(self, request, calendar_id):
        cal = get_object_or_404(Calendar, id=calendar_id)
        is_owner = cal.owner_id == request.user.id
        if not is_owner:
            share = CalendarShare.objects.filter(calendar=cal, user=request.user).first()
            if not share:
                raise Http404

        from datetime import datetime as dt
        start = request.GET.get('start', '')
        end = request.GET.get('end', '')
        events = cal.events.all()
        if start:
            try:
                events = events.filter(dtstart__gte=dt.fromisoformat(start.replace('Z', '+00:00')))
            except ValueError:
                pass
        if end:
            try:
                events = events.filter(dtstart__lte=dt.fromisoformat(end.replace('Z', '+00:00')))
            except ValueError:
                pass

        can_write = is_owner or (share and share.permission in ('write', 'admin'))
        data = []
        for ev in events:
            entry = {
                'id': ev.id,
                'title': ev.summary or '(No title)',
                'start': ev.dtstart.isoformat() if ev.dtstart else None,
                'end': ev.dtend.isoformat() if ev.dtend else None,
                'allDay': ev.all_day,
                'extendedProps': {
                    'description': ev.description or '',
                    'location': ev.location or '',
                },
            }
            if can_write:
                entry['extendedProps']['deleteUrl'] = reverse('event_delete', kwargs={'event_id': ev.id})
            data.append(entry)
        return JsonResponse(data, safe=False)


class EventCreateView(LoginRequiredMixin, View):
    def post(self, request, calendar_id):
        cal = get_object_or_404(Calendar, id=calendar_id)
        # Check access
        is_owner = cal.owner_id == request.user.id
        if not is_owner:
            share = CalendarShare.objects.filter(calendar=cal, user=request.user, permission__in=['write', 'admin']).first()
            if not share:
                raise Http404

        import uuid
        from datetime import datetime as dt
        summary = request.POST.get('summary', '').strip()
        description = request.POST.get('description', '').strip() or None
        location = request.POST.get('location', '').strip() or None
        all_day = 'all_day' in request.POST
        dtstart_str = request.POST.get('dtstart', '')
        dtend_str = request.POST.get('dtend', '')

        try:
            if all_day:
                dtstart = dt.strptime(dtstart_str, '%Y-%m-%d')
                dtend = dt.strptime(dtend_str, '%Y-%m-%d') if dtend_str else None
            else:
                dtstart = dt.strptime(dtstart_str, '%Y-%m-%dT%H:%M')
                dtend = dt.strptime(dtend_str, '%Y-%m-%dT%H:%M') if dtend_str else None
        except (ValueError, TypeError):
            messages.error(request, 'Invalid date format.')
            return redirect(f'/calendars/?calendar={calendar_id}')

        uid = str(uuid.uuid4())
        # Generate iCal data
        lines = [
            'BEGIN:VCALENDAR',
            'VERSION:2.0',
            'PRODID:-//Djancloud//CalDAV//EN',
            'BEGIN:VEVENT',
            f'UID:{uid}',
            f'SUMMARY:{summary}',
        ]
        if description:
            lines.append(f'DESCRIPTION:{description}')
        if location:
            lines.append(f'LOCATION:{location}')
        if all_day:
            lines.append(f'DTSTART;VALUE=DATE:{dtstart.strftime("%Y%m%d")}')
            if dtend:
                lines.append(f'DTEND;VALUE=DATE:{dtend.strftime("%Y%m%d")}')
        else:
            lines.append(f'DTSTART:{dtstart.strftime("%Y%m%dT%H%M%S")}')
            if dtend:
                lines.append(f'DTEND:{dtend.strftime("%Y%m%dT%H%M%S")}')
        lines.extend(['END:VEVENT', 'END:VCALENDAR'])
        ical_data = '\r\n'.join(lines)

        from django.utils import timezone as tz
        if dtstart.tzinfo is None:
            from datetime import timezone as dt_tz
            dtstart = dtstart.replace(tzinfo=dt_tz.utc)
        if dtend and dtend.tzinfo is None:
            from datetime import timezone as dt_tz
            dtend = dtend.replace(tzinfo=dt_tz.utc)

        Event.objects.create(
            calendar=cal,
            uid=uid,
            ical_data=ical_data,
            summary=summary,
            description=description,
            location=location,
            dtstart=dtstart,
            dtend=dtend,
            all_day=all_day,
        )
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'ok': True})
        messages.success(request, f'Event "{summary}" created.')
        return redirect(f'/calendars/?calendar={calendar_id}')


class EventDeleteView(LoginRequiredMixin, View):
    def post(self, request, event_id):
        event = get_object_or_404(Event, id=event_id)
        cal = event.calendar
        is_owner = cal.owner_id == request.user.id
        if not is_owner:
            share = CalendarShare.objects.filter(calendar=cal, user=request.user, permission__in=['write', 'admin']).first()
            if not share:
                raise Http404
        event.delete()
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'ok': True})
        messages.success(request, 'Event deleted.')
        return redirect(f'/calendars/?calendar={cal.id}')


# ─── Contacts Web Views ──────────────────────────────────────

class ContactsWebView(LoginRequiredMixin, View):
    def get(self, request):
        from .caldav_views import ensure_defaults_for_user
        ensure_defaults_for_user(request.user)

        all_own = list(AddressBook.objects.filter(owner=request.user).order_by('display_name'))
        own_addressbooks = [a for a in all_own if a.name == 'contacts']
        shareable_addressbooks = [a for a in all_own if a.name != 'contacts']
        shared_ids = AddressBookShare.objects.filter(user=request.user).values_list('addressbook_id', flat=True)
        shared_addressbooks = list(AddressBook.objects.filter(id__in=shared_ids).select_related('owner').order_by('display_name'))

        selected_addressbook = None
        contacts = []
        shares = []
        can_write = False

        ab_id = request.GET.get('addressbook')
        if not ab_id and all_own:
            ab_id = all_own[0].id
        if ab_id:
            try:
                selected_addressbook = AddressBook.objects.select_related('owner').get(id=ab_id)
                is_owner = selected_addressbook.owner_id == request.user.id
                if not is_owner:
                    share = AddressBookShare.objects.filter(addressbook=selected_addressbook, user=request.user).first()
                    if not share:
                        raise AddressBook.DoesNotExist
                    can_write = share.permission in ('write', 'admin')
                else:
                    can_write = True
                contacts = selected_addressbook.contacts.order_by('fn')
                if is_owner:
                    shares = selected_addressbook.shares.select_related('user').all()
            except AddressBook.DoesNotExist:
                selected_addressbook = None

        return render(request, 'file/contacts.html', {
            'addressbooks': own_addressbooks,
            'shareable_addressbooks': shareable_addressbooks,
            'shared_addressbooks': shared_addressbooks,
            'selected_addressbook': selected_addressbook,
            'contacts': contacts,
            'shares': shares,
            'can_write': can_write,
        })


class AddressBookCreateView(LoginRequiredMixin, View):
    def post(self, request):
        if request.user.role != 'admin':
            return redirect('contacts')
        display_name = request.POST.get('display_name', '').strip()
        if not display_name:
            messages.error(request, 'Address book name is required.')
            return redirect('contacts')
        name = display_name.lower().replace(' ', '-')
        base_name = name
        counter = 1
        while AddressBook.objects.filter(owner=request.user, name=name).exists():
            name = f"{base_name}-{counter}"
            counter += 1
        AddressBook.objects.create(
            owner=request.user,
            name=name,
            display_name=display_name,
            description=request.POST.get('description', '').strip() or None,
        )
        messages.success(request, f'Address book "{display_name}" created.')
        return redirect('contacts')


class AddressBookDeleteView(LoginRequiredMixin, View):
    def post(self, request, addressbook_id):
        ab = get_object_or_404(AddressBook, id=addressbook_id, owner=request.user)
        name = ab.display_name
        ab.delete()
        messages.success(request, f'Address book "{name}" deleted.')
        return redirect('contacts')


class AddressBookShareAddView(LoginRequiredMixin, View):
    def get(self, request, addressbook_id):
        ab = get_object_or_404(AddressBook, id=addressbook_id, owner=request.user)
        shares = AddressBookShare.objects.filter(addressbook=ab).select_related('user')
        return JsonResponse({'shares': [
            {'user_id': s.user_id, 'username': s.user.username, 'permission': s.permission}
            for s in shares
        ]})

    def post(self, request, addressbook_id):
        ab = get_object_or_404(AddressBook, id=addressbook_id, owner=request.user)
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        if is_ajax:
            data = json.loads(request.body)
            username = data.get('username', '').strip()
            permission = data.get('permission', 'read')
        else:
            username = request.POST.get('username', '').strip()
            permission = request.POST.get('permission', 'read')
        try:
            target_user = User.objects.get(username=username)
        except User.DoesNotExist:
            if is_ajax:
                return JsonResponse({'error': f'User "{username}" not found.'}, status=400)
            messages.error(request, f'User "{username}" not found.')
            return redirect(f'/contacts/?addressbook={addressbook_id}')
        if target_user == request.user:
            if is_ajax:
                return JsonResponse({'error': 'Cannot share with yourself.'}, status=400)
            messages.error(request, 'Cannot share with yourself.')
            return redirect(f'/contacts/?addressbook={addressbook_id}')
        AddressBookShare.objects.update_or_create(
            addressbook=ab, user=target_user,
            defaults={'permission': permission},
        )
        if is_ajax:
            return JsonResponse({'ok': True})
        messages.success(request, f'Shared with {username}.')
        return redirect(f'/contacts/?addressbook={addressbook_id}')


class AddressBookShareDeleteView(LoginRequiredMixin, View):
    def post(self, request, addressbook_id, user_id):
        ab = get_object_or_404(AddressBook, id=addressbook_id, owner=request.user)
        AddressBookShare.objects.filter(addressbook=ab, user_id=user_id).delete()
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'ok': True})
        messages.success(request, 'Share removed.')
        return redirect(f'/contacts/?addressbook={addressbook_id}')


class ContactCreateView(LoginRequiredMixin, View):
    def post(self, request, addressbook_id):
        ab = get_object_or_404(AddressBook, id=addressbook_id)
        is_owner = ab.owner_id == request.user.id
        if not is_owner:
            share = AddressBookShare.objects.filter(addressbook=ab, user=request.user, permission__in=['write', 'admin']).first()
            if not share:
                raise Http404

        import uuid
        fn = request.POST.get('fn', '').strip()
        email = request.POST.get('email', '').strip() or None
        tel = request.POST.get('tel', '').strip() or None
        org = request.POST.get('org', '').strip() or None

        if not fn:
            messages.error(request, 'Name is required.')
            return redirect(f'/contacts/?addressbook={addressbook_id}')

        uid = str(uuid.uuid4())
        lines = [
            'BEGIN:VCARD',
            'VERSION:3.0',
            f'UID:{uid}',
            f'FN:{fn}',
            f'N:{fn};;;;',
        ]
        if email:
            lines.append(f'EMAIL:{email}')
        if tel:
            lines.append(f'TEL:{tel}')
        if org:
            lines.append(f'ORG:{org}')
        lines.append('END:VCARD')
        vcard_data = '\r\n'.join(lines)

        Contact.objects.create(
            addressbook=ab,
            uid=uid,
            vcard_data=vcard_data,
            fn=fn,
            email=email,
            tel=tel,
            org=org,
        )
        messages.success(request, f'Contact "{fn}" created.')
        return redirect(f'/contacts/?addressbook={addressbook_id}')


class ContactDeleteView(LoginRequiredMixin, View):
    def post(self, request, contact_id):
        contact = get_object_or_404(Contact, id=contact_id)
        ab = contact.addressbook
        is_owner = ab.owner_id == request.user.id
        if not is_owner:
            share = AddressBookShare.objects.filter(addressbook=ab, user=request.user, permission__in=['write', 'admin']).first()
            if not share:
                raise Http404
        contact.delete()
        messages.success(request, 'Contact deleted.')
        return redirect(f'/contacts/?addressbook={ab.id}')


class ContactUpdateView(LoginRequiredMixin, View):
    def post(self, request, contact_id):
        contact = get_object_or_404(Contact, id=contact_id)
        ab = contact.addressbook
        is_owner = ab.owner_id == request.user.id
        if not is_owner:
            share = AddressBookShare.objects.filter(
                addressbook=ab, user=request.user,
                permission__in=['write', 'admin']).first()
            if not share:
                raise Http404

        fn = request.POST.get('fn', '').strip()
        email = request.POST.get('email', '').strip() or None
        tel = request.POST.get('tel', '').strip() or None
        org = request.POST.get('org', '').strip() or None

        if not fn:
            messages.error(request, 'Name is required.')
            return redirect(f'/contacts/?addressbook={ab.id}')

        # Rebuild vCard
        lines = [
            'BEGIN:VCARD',
            'VERSION:3.0',
            f'UID:{contact.uid}',
            f'FN:{fn}',
            f'N:{fn};;;;',
        ]
        if email:
            lines.append(f'EMAIL:{email}')
        if tel:
            lines.append(f'TEL:{tel}')
        if org:
            lines.append(f'ORG:{org}')
        lines.append('END:VCARD')

        contact.vcard_data = '\r\n'.join(lines)
        contact.fn = fn
        contact.email = email
        contact.tel = tel
        contact.org = org
        contact.save()

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'ok': True})
        messages.success(request, f'Contact "{fn}" updated.')
        return redirect(f'/contacts/?addressbook={ab.id}')


# ─── Mail Web Views ──────────────────────────────────────────

def _get_sorted_mailboxes(user):
    """Return mailboxes sorted: system folders first in fixed order, then custom."""
    from .models import SYSTEM_MAILBOXES
    mailboxes = list(Mailbox.objects.filter(owner=user))
    system_order = {name: i for i, name in enumerate(SYSTEM_MAILBOXES)}

    def sort_key(mb):
        if mb.name in system_order:
            return (0, system_order[mb.name])
        return (1, mb.name.lower())

    mailboxes.sort(key=sort_key)
    return mailboxes


class MailWebView(LoginRequiredMixin, View):
    def get(self, request):
        Mailbox.ensure_defaults(request.user)

        mailbox_name = request.GET.get('mailbox', 'INBOX')
        mailbox = Mailbox.objects.filter(owner=request.user, name=mailbox_name).first()
        mailboxes = _get_sorted_mailboxes(request.user)

        selected_email = None
        emails = []
        if mailbox:
            emails = mailbox.emails.all()
            email_id = request.GET.get('email')
            if email_id:
                selected_email = Email.objects.filter(id=email_id, mailbox=mailbox).first()
                if selected_email and not selected_email.is_read:
                    selected_email.is_read = True
                    selected_email.save(update_fields=['is_read'])

        # Unread counts per mailbox
        unread_counts = dict(
            Email.objects.filter(mailbox__owner=request.user, is_read=False)
            .values_list('mailbox_id')
            .annotate(count=models.Count('id'))
            .values_list('mailbox_id', 'count')
        )
        for mb in mailboxes:
            mb.unread_count = unread_counts.get(mb.id, 0)

        return render(request, 'file/mail.html', {
            'mailboxes': mailboxes,
            'selected_mailbox': mailbox,
            'emails': emails,
            'selected_email': selected_email,
        })


class MailboxCreateView(LoginRequiredMixin, View):
    def post(self, request):
        name = request.POST.get('name', '').strip()
        if not name:
            messages.error(request, 'Folder name is required.')
            return redirect('/mail/')
        if Mailbox.objects.filter(owner=request.user, name=name).exists():
            messages.error(request, f'Folder "{name}" already exists.')
            return redirect('/mail/')
        Mailbox.objects.create(owner=request.user, name=name, system=False)
        return redirect(f'/mail/?mailbox={name}')


class MailboxRenameView(LoginRequiredMixin, View):
    def post(self, request, mailbox_id):
        mb = get_object_or_404(Mailbox, id=mailbox_id, owner=request.user)
        if mb.system:
            messages.error(request, 'Cannot rename system folders.')
            return redirect(f'/mail/?mailbox={mb.name}')
        new_name = request.POST.get('name', '').strip()
        if not new_name:
            messages.error(request, 'Folder name is required.')
            return redirect(f'/mail/?mailbox={mb.name}')
        if Mailbox.objects.filter(owner=request.user, name=new_name).exclude(id=mb.id).exists():
            messages.error(request, f'Folder "{new_name}" already exists.')
            return redirect(f'/mail/?mailbox={mb.name}')
        mb.name = new_name
        mb.save(update_fields=['name'])
        return redirect(f'/mail/?mailbox={new_name}')


class MailboxDeleteView(LoginRequiredMixin, View):
    def post(self, request, mailbox_id):
        mb = get_object_or_404(Mailbox, id=mailbox_id, owner=request.user)
        if mb.system:
            messages.error(request, 'Cannot delete system folders.')
            return redirect(f'/mail/?mailbox={mb.name}')
        mb.delete()
        return redirect('/mail/')


class EmailDeleteView(LoginRequiredMixin, View):
    def post(self, request, email_id):
        mail = get_object_or_404(Email, id=email_id, mailbox__owner=request.user)
        mailbox = mail.mailbox

        # Move to Trash instead of deleting, unless already in Trash
        if mailbox.name == 'Trash':
            mail.delete()
            msg = 'Email permanently deleted.'
        else:
            trash, _ = Mailbox.objects.get_or_create(
                owner=request.user, name='Trash', defaults={'system': True})
            mail.mailbox = trash
            mail.save(update_fields=['mailbox_id'])
            msg = 'Email moved to Trash.'

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'ok': True})
        messages.success(request, msg)
        return redirect(f'/mail/?mailbox={mailbox.name}')


class EmailMoveView(LoginRequiredMixin, View):
    def post(self, request, email_id):
        mail = get_object_or_404(Email, id=email_id, mailbox__owner=request.user)
        target_name = request.POST.get('mailbox', '').strip()
        target = get_object_or_404(Mailbox, owner=request.user, name=target_name)
        old_mailbox = mail.mailbox
        mail.mailbox = target
        mail.save(update_fields=['mailbox_id'])
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'ok': True})
        messages.success(request, f'Email moved to {target.name}.')
        return redirect(f'/mail/?mailbox={old_mailbox.name}')


class TrashEmptyView(LoginRequiredMixin, View):
    def post(self, request):
        trash = Mailbox.objects.filter(owner=request.user, name='Trash').first()
        if trash:
            trash.emails.all().delete()
        messages.success(request, 'Trash emptied.')
        return redirect('/mail/?mailbox=Trash')


class EmailAttachmentDownloadView(LoginRequiredMixin, View):
    def get(self, request, attachment_id):
        att = get_object_or_404(
            EmailAttachment, id=attachment_id, email__mailbox__owner=request.user)
        response = HttpResponse(att.data, content_type=att.content_type)
        response['Content-Disposition'] = f'attachment; filename="{att.filename}"'
        return response


class FilePickerView(LoginRequiredMixin, View):
    """API to browse folders and files for the attachment picker."""
    def get(self, request, folder_id=None):
        if folder_id:
            folder, _ = get_accessible_folder(request, folder_id, permission='read')
        else:
            folder = get_object_or_404(
                Folder, owner=request.user,
                full_path=f"/{request.user.username}/")

        is_shared = folder.full_path.startswith('/__shared__/')

        # Breadcrumbs
        breadcrumbs = []
        current = folder
        while current:
            if current.full_path == f"/{request.user.username}/":
                breadcrumbs.insert(0, {'name': 'My files', 'id': current.id})
            else:
                name = current.name or current.full_path.strip('/').split('/')[-1]
                breadcrumbs.insert(0, {'name': name, 'id': current.id})
            current = current.parent

        # Subfolders
        if is_shared:
            children = folder.subfolders.all().order_by('name')
        else:
            children = folder.subfolders.filter(owner=request.user).order_by('name')

        subfolders = [
            {'id': sf.id, 'name': sf.name, 'type': 'folder'}
            for sf in children
        ]

        # Files
        if is_shared:
            file_qs = File.objects.filter(parent=folder).order_by('display_name')
        else:
            file_qs = File.objects.filter(
                parent=folder, owner=request.user).order_by('display_name')

        files = [
            {
                'id': f.id, 'name': f.display_name, 'type': 'file',
                'size': f.file.size if f.file else 0,
                'content_type': f.content_type or '',
            }
            for f in file_qs
        ]

        response = {
            'folder': {'id': folder.id, 'name': folder.name or 'My files'},
            'breadcrumbs': breadcrumbs,
            'items': subfolders + files,
        }

        # Shared folders at root
        if not folder_id or folder.full_path == f"/{request.user.username}/":
            memberships = SharedFolderMembership.objects.filter(
                user=request.user
            ).select_related('shared_folder__root_folder')
            shared = [
                {'id': m.shared_folder.root_folder.id,
                 'name': m.shared_folder.name, 'type': 'shared'}
                for m in memberships
            ]
            response['shared'] = shared

        return JsonResponse(response)


class MailComposeView(LoginRequiredMixin, View):
    def get(self, request):
        Mailbox.ensure_defaults(request.user)
        mailboxes = _get_sorted_mailboxes(request.user)
        signatures = EmailSignature.objects.filter(owner=request.user)
        default_sig = signatures.filter(is_default=True).first()

        # Unread counts
        unread_counts = dict(
            Email.objects.filter(mailbox__owner=request.user, is_read=False)
            .values_list('mailbox_id')
            .annotate(count=models.Count('id'))
            .values_list('mailbox_id', 'count')
        )
        for mb in mailboxes:
            mb.unread_count = unread_counts.get(mb.id, 0)

        # Pre-fill reply/forward
        reply_to = request.GET.get('reply_to')
        forward = request.GET.get('forward')
        prefill = {}
        if reply_to:
            orig = Email.objects.filter(id=reply_to, mailbox__owner=request.user).first()
            if orig:
                prefill['to'] = orig.from_address
                prefill['subject'] = f'Re: {orig.subject}' if not orig.subject.startswith('Re:') else orig.subject
                prefill['quote'] = orig.body_html or orig.body_text or ''
        elif forward:
            orig = Email.objects.filter(id=forward, mailbox__owner=request.user).first()
            if orig:
                prefill['subject'] = f'Fwd: {orig.subject}' if not orig.subject.startswith('Fwd:') else orig.subject
                prefill['quote'] = orig.body_html or orig.body_text or ''

        signatures_json = json.dumps([
            {'id': s.id, 'name': s.name} for s in signatures
        ])

        return render(request, 'file/mail_compose.html', {
            'mailboxes': mailboxes,
            'signatures': signatures,
            'signatures_json': signatures_json,
            'default_signature': default_sig,
            'prefill': prefill,
        })


class MailSendView(LoginRequiredMixin, View):
    def post(self, request):
        import smtplib
        import mimetypes
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        from email.mime.base import MIMEBase
        from email import encoders
        from email.utils import formatdate, make_msgid

        to_addresses = request.POST.get('to', '').strip()
        cc_addresses = request.POST.get('cc', '').strip()
        subject = request.POST.get('subject', '').strip()
        body_html = request.POST.get('body_html', '').strip()

        if not to_addresses:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'error': 'Recipient is required.'}, status=400)
            messages.error(request, 'Recipient is required.')
            return redirect('/mail/compose/')

        from_address = request.user.email or f'{request.user.username}@localhost'

        # Collect attachments
        attachment_data = []  # list of (filename, content_type, data_bytes)

        # Local file uploads
        for f in request.FILES.getlist('attachments'):
            attachment_data.append((
                f.name,
                f.content_type or 'application/octet-stream',
                f.read(),
            ))

        # Djancloud file IDs
        djancloud_ids = request.POST.get('djancloud_file_ids', '')
        if djancloud_ids:
            for fid in djancloud_ids.split(','):
                fid = fid.strip()
                if not fid:
                    continue
                try:
                    db_file, _ = get_accessible_file(request, int(fid), permission='read')
                    ct = db_file.content_type or 'application/octet-stream'
                    attachment_data.append((
                        db_file.display_name,
                        ct,
                        db_file.file.read(),
                    ))
                except Exception:
                    pass

        # Build MIME message
        has_attachments = len(attachment_data) > 0
        if has_attachments:
            msg = MIMEMultipart('mixed')
            body_part = MIMEMultipart('alternative')
        else:
            msg = MIMEMultipart('alternative')
            body_part = msg

        msg['From'] = from_address
        msg['To'] = to_addresses
        if cc_addresses:
            msg['Cc'] = cc_addresses
        msg['Subject'] = subject
        msg['Date'] = formatdate(localtime=True)
        message_id = make_msgid()
        msg['Message-ID'] = message_id

        # Plain text fallback
        import re
        body_text = re.sub(r'<[^>]+>', '', body_html)
        body_part.attach(MIMEText(body_text, 'plain', 'utf-8'))
        body_part.attach(MIMEText(body_html, 'html', 'utf-8'))

        if has_attachments:
            msg.attach(body_part)

        # Attach files
        for filename, content_type, data in attachment_data:
            maintype, subtype = content_type.split('/', 1) if '/' in content_type else ('application', 'octet-stream')
            part = MIMEBase(maintype, subtype)
            part.set_payload(data)
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', 'attachment', filename=filename)
            msg.attach(part)

        # Try to send via SMTP relay if configured
        smtp_host = getattr(settings, 'SMTP_RELAY_HOST', None)
        smtp_port = getattr(settings, 'SMTP_RELAY_PORT', 587)
        smtp_user = getattr(settings, 'SMTP_RELAY_USER', None)
        smtp_pass = getattr(settings, 'SMTP_RELAY_PASSWORD', None)
        smtp_tls = getattr(settings, 'SMTP_RELAY_USE_TLS', True)

        sent_ok = False
        if smtp_host:
            try:
                server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
                if smtp_tls:
                    server.starttls()
                if smtp_user and smtp_pass:
                    server.login(smtp_user, smtp_pass)
                all_recipients = [a.strip() for a in to_addresses.split(',')]
                if cc_addresses:
                    all_recipients += [a.strip() for a in cc_addresses.split(',')]
                server.sendmail(from_address, all_recipients, msg.as_string())
                server.quit()
                sent_ok = True
            except Exception:
                pass

        # Store in Sent folder
        sent_box, _ = Mailbox.objects.get_or_create(
            owner=request.user, name='Sent', defaults={'system': True})
        email_obj = Email.objects.create(
            mailbox=sent_box,
            message_id=message_id,
            from_address=from_address,
            to_addresses=to_addresses,
            cc_addresses=cc_addresses,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
            raw_data=msg.as_string(),
            is_read=True,
        )

        # Store attachments in DB
        for filename, content_type, data in attachment_data:
            EmailAttachment.objects.create(
                email=email_obj,
                filename=filename,
                content_type=content_type,
                data=data,
                size=len(data),
            )

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'ok': True, 'relayed': sent_ok})
        messages.success(request, 'Email sent.')
        return redirect('/mail/?mailbox=Sent')


class ContactSearchView(LoginRequiredMixin, View):
    """API endpoint for contact autocomplete in compose form."""
    def get(self, request):
        q = request.GET.get('q', '').strip()
        if len(q) < 1:
            return JsonResponse([], safe=False)

        # Search user's own contacts + shared address books
        from django.db.models import Q
        own_books = AddressBook.objects.filter(owner=request.user).values_list('id', flat=True)
        shared_books = AddressBookShare.objects.filter(user=request.user).values_list('addressbook_id', flat=True)
        all_books = list(own_books) + list(shared_books)

        contacts = Contact.objects.filter(
            addressbook_id__in=all_books
        ).filter(
            Q(fn__icontains=q) | Q(email__icontains=q)
        )[:20]

        results = []
        for c in contacts:
            if c.email:
                label = f'{c.fn} <{c.email}>' if c.fn else c.email
                results.append({'label': label, 'email': c.email, 'name': c.fn or ''})
        return JsonResponse(results, safe=False)


# ─── Signature Views ──────────────────────────────────────────

class SignatureListView(LoginRequiredMixin, View):
    def get(self, request):
        sigs = EmailSignature.objects.filter(owner=request.user)
        Mailbox.ensure_defaults(request.user)
        mailboxes = _get_sorted_mailboxes(request.user)
        unread_counts = dict(
            Email.objects.filter(mailbox__owner=request.user, is_read=False)
            .values_list('mailbox_id')
            .annotate(count=models.Count('id'))
            .values_list('mailbox_id', 'count')
        )
        for mb in mailboxes:
            mb.unread_count = unread_counts.get(mb.id, 0)

        selected_sig = None
        sig_id = request.GET.get('sig')
        if sig_id:
            selected_sig = EmailSignature.objects.filter(id=sig_id, owner=request.user).first()

        return render(request, 'file/mail_signatures.html', {
            'mailboxes': mailboxes,
            'signatures': sigs,
            'selected_signature': selected_sig,
        })


class SignatureCreateView(LoginRequiredMixin, View):
    def post(self, request):
        name = request.POST.get('name', '').strip()
        html_content = request.POST.get('html_content', '').strip()
        is_default = 'is_default' in request.POST

        if not name:
            messages.error(request, 'Signature name is required.')
            return redirect('/mail/signatures/')

        sig = EmailSignature.objects.create(
            owner=request.user, name=name,
            html_content=html_content, is_default=is_default)

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'ok': True, 'id': sig.id})
        return redirect(f'/mail/signatures/?sig={sig.id}')


class SignatureUpdateView(LoginRequiredMixin, View):
    def post(self, request, sig_id):
        sig = get_object_or_404(EmailSignature, id=sig_id, owner=request.user)
        sig.name = request.POST.get('name', sig.name).strip()
        sig.html_content = request.POST.get('html_content', sig.html_content)
        sig.is_default = 'is_default' in request.POST
        sig.save()

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'ok': True})
        return redirect(f'/mail/signatures/?sig={sig.id}')


class SignatureDeleteView(LoginRequiredMixin, View):
    def post(self, request, sig_id):
        sig = get_object_or_404(EmailSignature, id=sig_id, owner=request.user)
        sig.delete()
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'ok': True})
        return redirect('/mail/signatures/')


class SignatureContentView(LoginRequiredMixin, View):
    """Return signature HTML content as JSON for the compose form."""
    def get(self, request, sig_id):
        sig = get_object_or_404(EmailSignature, id=sig_id, owner=request.user)
        return JsonResponse({'html': sig.html_content})
