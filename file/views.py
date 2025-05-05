from django.contrib.auth import authenticate, login
from django.http import HttpResponse, JsonResponse
import base64
import secrets
from .models import LoginToken
from django.shortcuts import render
from django.views import View
from djangodav.views.views import DavView
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.contrib.auth.forms import AuthenticationForm
# Create your views here.


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
    pass


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

        if request.method == 'POST':
            form = AuthenticationForm(data=request.POST)
            if form.is_valid():
                user = form.get_user()
                login_token.user = user
                login_token.validated = True
                login_token.save()
                login(request, user)
                return HttpResponse("Login successful! You can close this window.")
        else:
            form = AuthenticationForm()

        return render(request, 'login_flow.html', {'form': form})

    def post(self, request, token):
        try:
            login_token = LoginToken.objects.get(token=token)
        except LoginToken.DoesNotExist:
            return JsonResponse({"error": "Invalid token"}, status=404)

        if not login_token.validated or login_token.is_expired():
            return JsonResponse({"error": "Not authorized yet"}, status=404)

        return JsonResponse({
            "server": request.get_host(),
            "loginName": login_token.user.username,
            "appPassword": "fake-app-password"
        })
