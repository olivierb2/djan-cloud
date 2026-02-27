from django.contrib import admin
from django.urls import path, re_path
from django.conf import settings
from rest_framework_simplejwt.views import TokenRefreshView

from djangodav.acls import FullAcl
from djangodav.locks import DummyLock
from file.resource import MyDavResource
from file.views import (
    MyDavView, DavEntryView, StatusView, Login, LoginForm, LoginPoll,
    OcsUserView, OcsCapabilitiesView,
)
from file.api_views import (
    LoginView, CurrentUserView, BrowseView,
    FileDownloadView, FilePreviewView, FileDeleteView, FolderDeleteView,
    MoveItemView, RenameItemView,
    FolderTreeView, FolderSelectorView,
    SharedFolderCreateView, SharedFolderMembersView, SharedFolderMemberDeleteView,
    UserListView, UserCreateView, UserDeleteView,
)

dav_view = MyDavView.as_view(
    resource_class=MyDavResource,
    lock_class=DummyLock,
    acl_class=FullAcl
)

dav_entry_view = DavEntryView.as_view(
    resource_class=MyDavResource,
    lock_class=DummyLock,
    acl_class=FullAcl
)

urlpatterns = [
    # Admin
    path('admin/', admin.site.urls),

    # JWT Auth API
    path('api/auth/login/', LoginView.as_view(), name='api_login'),
    path('api/auth/token/refresh/', TokenRefreshView.as_view(), name='api_token_refresh'),
    path('api/auth/user/', CurrentUserView.as_view(), name='api_current_user'),

    # Browse API
    path('api/browse/', BrowseView.as_view(), name='api_browse_root'),
    path('api/browse/<path:path>', BrowseView.as_view(), name='api_browse'),

    # File operations API
    path('api/download/<int:file_id>/', FileDownloadView.as_view(), name='api_download_file'),
    path('api/preview/<int:file_id>/', FilePreviewView.as_view(), name='api_preview_file'),
    path('api/files/<int:file_id>/', FileDeleteView.as_view(), name='api_delete_file'),
    path('api/folders/<int:folder_id>/delete/', FolderDeleteView.as_view(), name='api_delete_folder'),

    # Move & Rename API
    path('api/move/<str:item_type>/<int:item_id>/', MoveItemView.as_view(), name='api_move_item'),
    path('api/rename/<str:item_type>/<int:item_id>/', RenameItemView.as_view(), name='api_rename_item'),

    # Folder tree & selector API
    path('api/tree/', FolderTreeView.as_view(), name='api_folder_tree'),
    path('api/folders/', FolderSelectorView.as_view(), name='api_folder_root'),
    path('api/folders/<int:folder_id>/', FolderSelectorView.as_view(), name='api_folder_contents'),

    # Shared folders API
    path('api/shared-folders/create/', SharedFolderCreateView.as_view(), name='api_shared_folder_create'),
    path('api/shared-folders/<int:sf_id>/members/', SharedFolderMembersView.as_view(), name='api_shared_folder_members'),
    path('api/shared-folders/<int:sf_id>/members/<int:user_id>/', SharedFolderMemberDeleteView.as_view(), name='api_shared_folder_member_delete'),

    # User management API
    path('api/users/', UserListView.as_view(), name='api_users'),
    path('api/users/create/', UserCreateView.as_view(), name='api_user_create'),
    path('api/users/<int:user_id>/', UserDeleteView.as_view(), name='api_user_delete'),

    # Nextcloud protocol (DAV, OCS, login flow)
    path('status.php', StatusView.as_view()),
    path('index.php/login/v2', Login.as_view()),
    path('index.php/login/v2/flow/<str:token>', LoginForm.as_view()),
    path('index.php/login/v2/poll', LoginPoll.as_view()),
    path('ocs/v1.php/cloud/user', OcsUserView.as_view()),
    path('ocs/v2.php/cloud/user', OcsUserView.as_view()),
    path('ocs/v1.php/cloud/capabilities', OcsCapabilitiesView.as_view()),
    path('ocs/v2.php/cloud/capabilities', OcsCapabilitiesView.as_view()),
    re_path(fr'^{settings.ROOT_DAV}(?P<username>[^/]+)/(?P<path>.*)$', dav_view, name='fsdav'),
    re_path(r'^remote\.php/dav/files/(?P<username>[^/]+)/(?P<path>.*)$', dav_view, name='fsdav_alt'),
    re_path(r'^dav/(?P<path>.*)$', dav_entry_view, name='fsdav_entry'),
]
