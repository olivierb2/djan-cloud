"""
URL configuration for core project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path

from djangodav.acls import FullAcl
from djangodav.locks import DummyLock
from file.views import MyDavView, StatusView, Login, LoginForm, LoginPoll
from django.conf import settings

from django.urls import re_path

from file.resource import MyDavResource

dav_path_regex = fr'^{settings.ROOT_DAV}(?P<path>.*)$'

urlpatterns = [
    path('admin/', admin.site.urls),
    path('status.php', StatusView.as_view()),
    path('index.php/login/v2', Login.as_view()),
    path('index.php/login/v2/flow/<str:token>', LoginForm.as_view()),
    path('index.php/login/v2/poll', LoginPoll.as_view()),
    re_path(
        dav_path_regex,
        MyDavView.as_view(
            resource_class=MyDavResource,
            lock_class=DummyLock,
            acl_class=FullAcl
        ),
        name='fsdav'
    ),
]
