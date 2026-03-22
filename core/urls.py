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
from django.urls import path, re_path, include

from djangodav.acls import FullAcl
from djangodav.locks import DummyLock
from file.views import (
    MyDavView, DavEntryView, RootView, StatusView, Login, LoginForm, LoginPoll,
    WebLoginView, WebLogoutView, FileBrowseView, SearchView, FileDownloadView,
    FileDeleteView, FolderDeleteView, MoveItemView, FolderSelectorView,
    RenameItemView, FilePreviewView, FolderTreeView, OcsUserView,
    OcsCapabilitiesView, SharedFolderCreateView, SharedFolderMembersView,
    SharedFolderMemberDeleteView, UserListView, UserCreateView, UserUpdateView, UserDeleteView,
    UserManagementView, FileEditorView, FileSaveView,
    CalendarWebView, CalendarCreateView, CalendarDeleteView,
    CalendarShareAddView, CalendarShareDeleteView,
    EventCreateView, EventDeleteView, CalendarEventsApiView,
    ContactsWebView, AddressBookCreateView, AddressBookDeleteView,
    AddressBookShareAddView, AddressBookShareDeleteView,
    ContactCreateView, ContactDeleteView, ContactUpdateView,
    MailWebView, MailboxCreateView, MailboxRenameView, MailboxDeleteView,
    EmailToggleReadView, EmailDeleteView, EmailMoveView, TrashEmptyView, EmailAttachmentDownloadView, EmailDetailApiView,
    MailComposeView, MailSendView, ContactSearchView, FilePickerView, ContactFolderCreateView,
    MailSettingsView, SignatureCreateView, SignatureUpdateView,
    SignatureDeleteView, SignatureContentView, OutOfOfficeUpdateView,
    SharedMailboxCreateView, SharedMailboxDeleteView,
    SharedMailboxMemberAddView, SharedMailboxMemberDeleteView,
    BrowseApiView, ApiFolderCreateView, ApiFileUploadView, ApiTextFileCreateView,
    ApiRenameView, ApiDeleteFileView, ApiDeleteFolderView, ApiMoveItemView,
    SettingsView, AllowedDomainCreateView, AllowedDomainDeleteView,
)
from file.caldav_views import (
    WellKnownCalDavView, WellKnownCardDavView,
    DavRootView, PrincipalView,
    CalendarListView, CalendarView, EventView,
    AddressBookListView, AddressBookView, ContactView,
    DavOptionsView,
)
from django.conf import settings

from django.urls import re_path

from file.resource import MyDavResource

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
    path('', RootView.as_view(), name='root'),
    path('admin/', admin.site.urls),
    path('login/', WebLoginView.as_view(), name='login'),
    path('logout/', WebLogoutView.as_view(), name='logout'),
    path('status.php', StatusView.as_view()),

    # Well-known CalDAV/CardDAV discovery
    path('.well-known/caldav', WellKnownCalDavView.as_view()),
    path('.well-known/carddav', WellKnownCardDavView.as_view()),

    # DAV root (service discovery)
    path('remote.php/dav/', DavRootView.as_view(), name='dav_root'),

    # Principals
    re_path(r'^remote\.php/dav/principals/users/(?P<username>[^/]+)/$',
            PrincipalView.as_view(), name='dav_principal'),

    # CalDAV - Calendars
    re_path(r'^remote\.php/dav/calendars/(?P<username>[^/]+)/$',
            CalendarListView.as_view(), name='caldav_calendar_list'),
    re_path(r'^remote\.php/dav/calendars/(?P<username>[^/]+)/(?P<calendar_name>[^/]+)/$',
            CalendarView.as_view(), name='caldav_calendar'),
    re_path(r'^remote\.php/dav/calendars/(?P<username>[^/]+)/(?P<calendar_name>[^/]+)/(?P<event_filename>[^/]+)$',
            EventView.as_view(), name='caldav_event'),

    # CardDAV - Address Books
    re_path(r'^remote\.php/dav/addressbooks/users/(?P<username>[^/]+)/$',
            AddressBookListView.as_view(), name='carddav_addressbook_list'),
    re_path(r'^remote\.php/dav/addressbooks/users/(?P<username>[^/]+)/(?P<addressbook_name>[^/]+)/$',
            AddressBookView.as_view(), name='carddav_addressbook'),
    re_path(r'^remote\.php/dav/addressbooks/users/(?P<username>[^/]+)/(?P<addressbook_name>[^/]+)/(?P<contact_filename>[^/]+)$',
            ContactView.as_view(), name='carddav_contact'),
    path('index.php/login/v2', Login.as_view()),
    path('index.php/login/v2/flow/<str:token>', LoginForm.as_view()),
    path('index.php/login/v2/poll', LoginPoll.as_view()),
    path('ocs/v1.php/cloud/user', OcsUserView.as_view()),
    path('ocs/v2.php/cloud/user', OcsUserView.as_view()),
    path('ocs/v1.php/cloud/capabilities', OcsCapabilitiesView.as_view()),
    path('ocs/v2.php/cloud/capabilities', OcsCapabilitiesView.as_view()),
    # WebDAV discovery endpoint for GNOME Online Accounts / clients
    path('remote.php/webdav', DavOptionsView.as_view()),
    path('remote.php/webdav/', DavOptionsView.as_view()),
    re_path(fr'^{settings.ROOT_DAV}(?P<username>[^/]+)/(?P<path>.*)$', dav_view, name='fsdav'),
    re_path(r'^remote\.php/dav/files/(?P<username>[^/]+)/(?P<path>.*)$', dav_view, name='fsdav_alt'),
    re_path(r'^dav/(?P<path>.*)$', dav_entry_view, name='fsdav_entry'),
    path('browse/', FileBrowseView.as_view(), name='browse_files_root'),
    path('browse/<path:path>', FileBrowseView.as_view(), name='browse_files'),
    path('api/search/', SearchView.as_view(), name='api_search'),
    path('download/<int:file_id>/', FileDownloadView.as_view(), name='download_file'),
    path('delete/file/<int:file_id>/', FileDeleteView.as_view(), name='delete_file'),
    path('delete/folder/<int:folder_id>/', FolderDeleteView.as_view(), name='delete_folder'),
    path('move/<str:item_type>/<int:item_id>/', MoveItemView.as_view(), name='move_item'),
    path('rename/<str:item_type>/<int:item_id>/', RenameItemView.as_view(), name='rename_item'),
    path('preview/<int:file_id>/', FilePreviewView.as_view(), name='preview_file'),
    path('editor/<int:file_id>/', FileEditorView.as_view(), name='editor_file'),
    path('api/files/<int:file_id>/save/', FileSaveView.as_view(), name='api_file_save'),
    path('api/folders/', FolderSelectorView.as_view(), name='api_folder_root'),
    path('api/folders/<int:folder_id>/', FolderSelectorView.as_view(), name='api_folder_contents'),
    path('api/tree/', FolderTreeView.as_view(), name='api_folder_tree'),
    path('api/shared-folders/create/', SharedFolderCreateView.as_view(), name='api_shared_folder_create'),
    path('api/shared-folders/<int:sf_id>/members/', SharedFolderMembersView.as_view(), name='api_shared_folder_members'),
    path('api/shared-folders/<int:sf_id>/members/<int:user_id>/', SharedFolderMemberDeleteView.as_view(), name='api_shared_folder_member_delete'),
    path('api/contact-folders/create/', ContactFolderCreateView.as_view(), name='api_contact_folder_create'),
    path('settings/', SettingsView.as_view(), name='settings'),
    path('api/users/', UserListView.as_view(), name='api_users'),
    path('api/users/create/', UserCreateView.as_view(), name='api_user_create'),
    path('api/users/<int:user_id>/', UserDeleteView.as_view(), name='api_user_delete'),
    path('api/users/<int:user_id>/update/', UserUpdateView.as_view(), name='api_user_update'),
    path('api/domains/create/', AllowedDomainCreateView.as_view(), name='api_domain_create'),
    path('api/domains/<int:domain_id>/', AllowedDomainDeleteView.as_view(), name='api_domain_delete'),

    # Calendar web UI
    path('calendars/', CalendarWebView.as_view(), name='calendars'),
    path('calendars/create/', CalendarCreateView.as_view(), name='calendar_create'),
    path('calendars/<int:calendar_id>/delete/', CalendarDeleteView.as_view(), name='calendar_delete'),
    path('calendars/<int:calendar_id>/share/', CalendarShareAddView.as_view(), name='calendar_share_add'),
    path('calendars/<int:calendar_id>/share/<int:user_id>/delete/', CalendarShareDeleteView.as_view(), name='calendar_share_delete'),
    path('calendars/<int:calendar_id>/events/create/', EventCreateView.as_view(), name='event_create'),
    path('calendars/<int:calendar_id>/events.json', CalendarEventsApiView.as_view(), name='calendar_events_api'),
    path('events/<int:event_id>/delete/', EventDeleteView.as_view(), name='event_delete'),

    # Contacts web UI
    path('contacts/', ContactsWebView.as_view(), name='contacts'),
    path('contacts/addressbooks/create/', AddressBookCreateView.as_view(), name='addressbook_create'),
    path('contacts/addressbooks/<int:addressbook_id>/delete/', AddressBookDeleteView.as_view(), name='addressbook_delete'),
    path('contacts/addressbooks/<int:addressbook_id>/share/', AddressBookShareAddView.as_view(), name='addressbook_share_add'),
    path('contacts/addressbooks/<int:addressbook_id>/share/<int:user_id>/delete/', AddressBookShareDeleteView.as_view(), name='addressbook_share_delete'),
    path('contacts/<int:addressbook_id>/contacts/create/', ContactCreateView.as_view(), name='contact_create'),
    path('contacts/contact/<int:contact_id>/delete/', ContactDeleteView.as_view(), name='contact_delete'),
    path('contacts/contact/<int:contact_id>/update/', ContactUpdateView.as_view(), name='contact_update'),

    # Mail web UI
    path('mail/', MailWebView.as_view(), name='mail'),
    path('mail/folders/create/', MailboxCreateView.as_view(), name='mailbox_create'),
    path('mail/folders/<int:mailbox_id>/rename/', MailboxRenameView.as_view(), name='mailbox_rename'),
    path('mail/folders/<int:mailbox_id>/delete/', MailboxDeleteView.as_view(), name='mailbox_delete'),
    path('api/mail/<int:email_id>/', EmailDetailApiView.as_view(), name='api_email_detail'),
    path('mail/<int:email_id>/toggle-read/', EmailToggleReadView.as_view(), name='email_toggle_read'),
    path('mail/<int:email_id>/delete/', EmailDeleteView.as_view(), name='email_delete'),
    path('mail/<int:email_id>/move/', EmailMoveView.as_view(), name='email_move'),
    path('mail/trash/empty/', TrashEmptyView.as_view(), name='trash_empty'),
    path('mail/attachment/<int:attachment_id>/', EmailAttachmentDownloadView.as_view(), name='email_attachment_download'),
    path('mail/compose/', MailComposeView.as_view(), name='mail_compose'),
    path('mail/send/', MailSendView.as_view(), name='mail_send'),
    path('mail/settings/', MailSettingsView.as_view(), name='mail_settings'),
    path('mail/settings/create-signature/', SignatureCreateView.as_view(), name='signature_create'),
    path('mail/settings/signatures/<int:sig_id>/update/', SignatureUpdateView.as_view(), name='signature_update'),
    path('mail/settings/signatures/<int:sig_id>/delete/', SignatureDeleteView.as_view(), name='signature_delete'),
    path('mail/settings/signatures/<int:sig_id>/content/', SignatureContentView.as_view(), name='signature_content'),
    path('mail/settings/out-of-office/', OutOfOfficeUpdateView.as_view(), name='ooo_update'),
    path('mail/shared/create/', SharedMailboxCreateView.as_view(), name='shared_mailbox_create'),
    path('mail/shared/<int:sm_id>/delete/', SharedMailboxDeleteView.as_view(), name='shared_mailbox_delete'),
    path('mail/shared/<int:sm_id>/members/add/', SharedMailboxMemberAddView.as_view(), name='shared_mailbox_member_add'),
    path('mail/shared/<int:sm_id>/members/<int:user_id>/delete/', SharedMailboxMemberDeleteView.as_view(), name='shared_mailbox_member_delete'),
    path('api/contacts/search/', ContactSearchView.as_view(), name='contact_search'),
    path('api/filepicker/', FilePickerView.as_view(), name='filepicker_root'),
    path('api/filepicker/<int:folder_id>/', FilePickerView.as_view(), name='filepicker_folder'),

    # Browse SPA API
    path('api/browse/', BrowseApiView.as_view(), name='api_browse_root'),
    path('api/browse/<path:path>', BrowseApiView.as_view(), name='api_browse'),
    path('api/folders/create/', ApiFolderCreateView.as_view(), name='api_folder_create'),
    path('api/files/upload/', ApiFileUploadView.as_view(), name='api_file_upload'),
    path('api/files/create-text/', ApiTextFileCreateView.as_view(), name='api_text_file_create'),
    path('api/rename/<str:item_type>/<int:item_id>/', ApiRenameView.as_view(), name='api_rename'),
    path('api/files/<int:file_id>/delete/', ApiDeleteFileView.as_view(), name='api_file_delete'),
    path('api/folders/<int:folder_id>/delete/', ApiDeleteFolderView.as_view(), name='api_folder_delete'),
    path('api/move/<str:item_type>/<int:item_id>/', ApiMoveItemView.as_view(), name='api_move_item'),
]
