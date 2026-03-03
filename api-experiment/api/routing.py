from django.urls import re_path
from .consumers import DjancloudConsumer
from .editor_consumer import EditorConsumer

websocket_urlpatterns = [
    re_path(r'ws/user/$', DjancloudConsumer.as_asgi()),
    re_path(r'ws/editor/(?P<file_id>\d+)/$', EditorConsumer.as_asgi()),
]
