"""
ASGI config for core project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.2/howto/deployment/asgi/
"""

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')

django_asgi_app = get_asgi_application()

from channels.routing import ProtocolTypeRouter, URLRouter
from file.routing import websocket_urlpatterns
from file.ws_auth import SessionAuthMiddleware

application = ProtocolTypeRouter({
    'http': django_asgi_app,
    'websocket': SessionAuthMiddleware(URLRouter(websocket_urlpatterns)),
})
