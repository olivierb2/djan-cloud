from django.contrib.auth import authenticate, login
from django.http import HttpResponse
import base64
from django.shortcuts import render
from djangodav.views.views import DavView
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
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
