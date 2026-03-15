"""CalDAV and CardDAV views for calendar and contact synchronization."""
import hashlib
import logging

from django.db.models import Q
from django.http import HttpResponse, Http404
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from lxml import etree
from lxml.builder import ElementMaker

from .models import (
    Calendar, CalendarShare, Event,
    AddressBook, AddressBookShare, Contact,
    User,
)
from .views import BasicAuthMixin
from .ical_utils import (
    parse_icalendar, parse_vcard, generate_etag,
    validate_icalendar, validate_vcard,
)

logger = logging.getLogger(__name__)


def ensure_defaults_for_user(user):
    """Auto-create a default 'personal' calendar and 'contacts' addressbook if they don't exist."""
    if not Calendar.objects.filter(owner=user, name='personal').exists():
        Calendar.objects.create(
            owner=user,
            name='personal',
            display_name='Personal',
            color='#0082c9',
        )
    if not AddressBook.objects.filter(owner=user, name='contacts').exists():
        AddressBook.objects.create(
            owner=user,
            name='contacts',
            display_name='Contacts',
        )


# XML Namespaces
DAV_NS = 'DAV:'
CALDAV_NS = 'urn:ietf:params:xml:ns:caldav'
CARDDAV_NS = 'urn:ietf:params:xml:ns:carddav'
CS_NS = 'http://calendarserver.org/ns/'
OC_NS = 'http://owncloud.org/ns'
NC_NS = 'http://nextcloud.org/ns'

NSMAP = {
    'd': DAV_NS,
    'cal': CALDAV_NS,
    'card': CARDDAV_NS,
    'cs': CS_NS,
    'oc': OC_NS,
    'nc': NC_NS,
}

D = ElementMaker(namespace=DAV_NS, nsmap=NSMAP)
C = ElementMaker(namespace=CALDAV_NS, nsmap=NSMAP)
CARD = ElementMaker(namespace=CARDDAV_NS, nsmap=NSMAP)
CS = ElementMaker(namespace=CS_NS, nsmap=NSMAP)


def xml_response(body, status=207):
    content = etree.tostring(body, xml_declaration=True, encoding='utf-8')
    return HttpResponse(content, status=status, content_type='application/xml; charset=utf-8')


def parse_xml_body(request):
    """Parse XML body from request if present."""
    ct = request.content_type or ''
    if 'xml' in ct and request.body:
        try:
            return etree.fromstring(request.body)
        except etree.XMLSyntaxError:
            pass
    return None


def get_depth(request):
    return request.META.get('HTTP_DEPTH', 'infinity')


# ─── Base CalDAV/CardDAV View ──────────────────────────────────

@method_decorator(csrf_exempt, name='dispatch')
class DavAuthView(BasicAuthMixin, View):
    """Base view: BasicAuthMixin.dispatch() handles auth, then View.dispatch()
    routes to the correct handler method based on http_method_names."""

    http_method_names = ['options', 'get', 'head', 'put', 'delete',
                         'propfind', 'proppatch', 'report', 'mkcalendar', 'mkcol']

    def dispatch(self, request, *args, **kwargs):
        # OPTIONS must pass without authentication (CORS preflight / DAV discovery)
        if request.method == 'OPTIONS':
            return self.options(request, *args, **kwargs)
        return super().dispatch(request, *args, **kwargs)

    def options(self, request, *args, **kwargs):
        response = HttpResponse(status=200)
        response['Allow'] = 'OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, REPORT, MKCALENDAR, MKCOL'
        response['DAV'] = '1, 2, 3, calendar-access, addressbook'
        return response


# ─── Principal Discovery View ──────────────────────────────────

class PrincipalView(DavAuthView):
    """Handles PROPFIND on /remote.php/dav/principals/users/{username}/"""

    def propfind(self, request, username=None):
        user = request.user

        responses = []

        # Principal resource
        principal_href = f'/remote.php/dav/principals/users/{user.username}/'
        props = D.prop(
            D.resourcetype(D.principal()),
            D.displayname(user.get_full_name() or user.username),
            D('{DAV:}current-user-principal', D.href(principal_href)),
            C('{urn:ietf:params:xml:ns:caldav}calendar-home-set',
              D.href(f'/remote.php/dav/calendars/{user.username}/')),
            CARD('{urn:ietf:params:xml:ns:carddav}addressbook-home-set',
                 D.href(f'/remote.php/dav/addressbooks/users/{user.username}/')),
        )

        responses.append(D.response(
            D.href(principal_href),
            D.propstat(props, D.status('HTTP/1.1 200 OK'))
        ))

        return xml_response(D.multistatus(*responses))

    def options(self, request, *args, **kwargs):
        response = HttpResponse()
        response['DAV'] = '1, 2, 3, calendar-access, addressbook'
        response['Allow'] = 'OPTIONS, PROPFIND'
        return response


# ─── DAV Root View ────────────────────────────────────────────

class DavRootView(DavAuthView):
    """Handles PROPFIND on /remote.php/dav/ for service discovery."""

    def propfind(self, request):
        user = request.user
        principal_href = f'/remote.php/dav/principals/users/{user.username}/'

        responses = [D.response(
            D.href('/remote.php/dav/'),
            D.propstat(
                D.prop(
                    D.resourcetype(D.collection()),
                    D('{DAV:}current-user-principal', D.href(principal_href)),
                ),
                D.status('HTTP/1.1 200 OK')
            )
        )]

        return xml_response(D.multistatus(*responses))

    def options(self, request, *args, **kwargs):
        response = HttpResponse()
        response['DAV'] = '1, 2, 3, calendar-access, addressbook'
        response['Allow'] = 'OPTIONS, PROPFIND'
        return response


# ─── CalDAV Views ──────────────────────────────────────────────

def _get_user_calendars(user):
    """Get all calendars accessible to a user (own + shared)."""
    own = Calendar.objects.filter(owner=user)
    shared_ids = CalendarShare.objects.filter(user=user).values_list('calendar_id', flat=True)
    shared = Calendar.objects.filter(id__in=shared_ids)
    return list(own) + list(shared)


def _calendar_propstat(calendar, user, base_href):
    """Build propstat element for a calendar collection."""
    rt = D.resourcetype(D.collection(), C('{urn:ietf:params:xml:ns:caldav}calendar'))

    props = [
        rt,
        D.displayname(calendar.display_name),
        D.getetag(f'"{calendar.sync_token}"'),
    ]

    # CalDAV-specific properties
    if calendar.description:
        props.append(C('{urn:ietf:params:xml:ns:caldav}calendar-description', calendar.description))

    # Supported components
    comp_set = C('{urn:ietf:params:xml:ns:caldav}supported-calendar-component-set')
    comp_set.append(C('{urn:ietf:params:xml:ns:caldav}comp', name='VEVENT'))
    comp_set.append(C('{urn:ietf:params:xml:ns:caldav}comp', name='VTODO'))
    props.append(comp_set)

    # Sync token
    props.append(D('{DAV:}sync-token', f'http://sabre.io/ns/sync/{calendar.sync_token}'))

    # Color (Apple/Nextcloud extension)
    color_el = etree.Element('{http://apple.com/ns/ical/}calendar-color')
    color_el.text = calendar.color
    props.append(color_el)

    # Permissions
    is_owner = calendar.owner_id == user.id
    if is_owner:
        privs = D('{DAV:}current-user-privilege-set',
                   D.privilege(D.read()),
                   D.privilege(D.write()),
                   D.privilege(D('{DAV:}write-content')),
                   D.privilege(D('{DAV:}bind')),
                   D.privilege(D('{DAV:}unbind')))
    else:
        share = CalendarShare.objects.filter(calendar=calendar, user=user).first()
        if share and share.permission in ('write', 'admin'):
            privs = D('{DAV:}current-user-privilege-set',
                       D.privilege(D.read()),
                       D.privilege(D.write()))
        else:
            privs = D('{DAV:}current-user-privilege-set',
                       D.privilege(D.read()))
    props.append(privs)

    return D.propstat(D.prop(*props), D.status('HTTP/1.1 200 OK'))


def _event_propstat(event, base_href):
    """Build propstat element for a calendar event resource."""
    props = D.prop(
        D.resourcetype(),  # Not a collection
        D.displayname(event.summary or event.uid),
        D.getetag(f'"{event.etag}"'),
        D.getcontenttype('text/calendar; charset=utf-8'),
        D.getcontentlength(str(len(event.ical_data.encode('utf-8')))),
    )
    return D.propstat(props, D.status('HTTP/1.1 200 OK'))


class CalendarListView(DavAuthView):
    """Handles /remote.php/dav/calendars/{username}/
    PROPFIND - list calendars
    """

    def propfind(self, request, username):
        user = request.user
        ensure_defaults_for_user(user)
        depth = get_depth(request)
        calendars = _get_user_calendars(user)

        responses = []

        # The collection itself
        home_href = f'/remote.php/dav/calendars/{user.username}/'
        home_props = D.prop(
            D.resourcetype(D.collection()),
            D.displayname('Calendars'),
            D('{DAV:}current-user-principal',
              D.href(f'/remote.php/dav/principals/users/{user.username}/')),
        )
        responses.append(D.response(
            D.href(home_href),
            D.propstat(home_props, D.status('HTTP/1.1 200 OK'))
        ))

        # List calendars if depth > 0
        if depth != '0':
            for cal in calendars:
                cal_href = f'/remote.php/dav/calendars/{cal.owner.username}/{cal.name}/'
                responses.append(D.response(
                    D.href(cal_href),
                    _calendar_propstat(cal, user, cal_href)
                ))

        return xml_response(D.multistatus(*responses))

    def options(self, request, *args, **kwargs):
        response = HttpResponse()
        response['DAV'] = '1, 2, 3, calendar-access'
        response['Allow'] = 'OPTIONS, PROPFIND, MKCALENDAR'
        return response


class CalendarView(DavAuthView):
    """Handles /remote.php/dav/calendars/{username}/{calendar_name}/
    PROPFIND - list events in calendar
    REPORT - calendar-query, calendar-multiget
    MKCALENDAR - create new calendar
    DELETE - delete calendar
    """

    def _get_calendar(self, request, username, calendar_name, require_write=False):
        """Get calendar with access check."""
        try:
            calendar = Calendar.objects.select_related('owner').get(
                owner__username=username, name=calendar_name)
        except Calendar.DoesNotExist:
            raise Http404()

        user = request.user
        if calendar.owner == user:
            return calendar, 'admin'

        share = CalendarShare.objects.filter(calendar=calendar, user=user).first()
        if not share:
            raise Http404()
        if require_write and share.permission == 'read':
            return None, None
        return calendar, share.permission

    def propfind(self, request, username, calendar_name):
        calendar, perm = self._get_calendar(request, username, calendar_name)
        if not calendar:
            raise Http404()

        depth = get_depth(request)
        responses = []

        # Calendar collection
        cal_href = f'/remote.php/dav/calendars/{username}/{calendar_name}/'
        responses.append(D.response(
            D.href(cal_href),
            _calendar_propstat(calendar, request.user, cal_href)
        ))

        # List events if depth > 0
        if depth != '0':
            for event in calendar.events.all():
                event_href = f'{cal_href}{event.uid}.ics'
                responses.append(D.response(
                    D.href(event_href),
                    _event_propstat(event, event_href)
                ))

        return xml_response(D.multistatus(*responses))

    def report(self, request, username, calendar_name):
        calendar, perm = self._get_calendar(request, username, calendar_name)
        if not calendar:
            raise Http404()

        xml_body = parse_xml_body(request)
        if xml_body is None:
            return HttpResponse(status=400)

        root_tag = etree.QName(xml_body.tag)

        if root_tag.localname == 'calendar-multiget':
            return self._report_multiget(request, calendar, xml_body, username, calendar_name)
        elif root_tag.localname == 'calendar-query':
            return self._report_query(request, calendar, xml_body, username, calendar_name)
        elif root_tag.localname == 'sync-collection':
            return self._report_sync_collection(request, calendar, xml_body, username, calendar_name)
        else:
            return HttpResponse(status=400)

    def _report_multiget(self, request, calendar, xml_body, username, calendar_name):
        """Handle calendar-multiget REPORT."""
        responses = []
        hrefs = xml_body.findall(f'{{{DAV_NS}}}href')

        for href_el in hrefs:
            href = href_el.text.strip()
            # Extract UID from href: .../uid.ics
            parts = href.rstrip('/').split('/')
            if not parts:
                continue
            filename = parts[-1]
            if filename.endswith('.ics'):
                uid = filename[:-4]
            else:
                uid = filename

            try:
                event = calendar.events.get(uid=uid)
                cal_data = C('{urn:ietf:params:xml:ns:caldav}calendar-data')
                cal_data.text = event.ical_data

                props = D.prop(
                    D.getetag(f'"{event.etag}"'),
                    D.getcontenttype('text/calendar; charset=utf-8'),
                    cal_data,
                )
                responses.append(D.response(
                    D.href(href),
                    D.propstat(props, D.status('HTTP/1.1 200 OK'))
                ))
            except Event.DoesNotExist:
                responses.append(D.response(
                    D.href(href),
                    D.propstat(D.prop(), D.status('HTTP/1.1 404 Not Found'))
                ))

        return xml_response(D.multistatus(*responses))

    def _report_query(self, request, calendar, xml_body, username, calendar_name):
        """Handle calendar-query REPORT."""
        events = calendar.events.all()

        # Apply time-range filter if present
        filters = xml_body.findall(f'.//{{{CALDAV_NS}}}time-range')
        for tr in filters:
            start = tr.get('start')
            end = tr.get('end')
            if start:
                from dateutil.parser import parse as dt_parse
                try:
                    events = events.filter(
                        Q(dtend__gte=dt_parse(start)) | Q(dtend__isnull=True))
                except (ValueError, ImportError):
                    pass
            if end:
                from dateutil.parser import parse as dt_parse
                try:
                    events = events.filter(dtstart__lte=dt_parse(end))
                except (ValueError, ImportError):
                    pass

        # Check if calendar-data is requested
        cal_data_requested = xml_body.find(f'.//{{{CALDAV_NS}}}calendar-data') is not None

        responses = []
        cal_href = f'/remote.php/dav/calendars/{username}/{calendar_name}/'

        for event in events:
            event_href = f'{cal_href}{event.uid}.ics'
            prop_children = [
                D.getetag(f'"{event.etag}"'),
                D.getcontenttype('text/calendar; charset=utf-8'),
            ]
            if cal_data_requested:
                cal_data_el = C('{urn:ietf:params:xml:ns:caldav}calendar-data')
                cal_data_el.text = event.ical_data
                prop_children.append(cal_data_el)

            responses.append(D.response(
                D.href(event_href),
                D.propstat(D.prop(*prop_children), D.status('HTTP/1.1 200 OK'))
            ))

        return xml_response(D.multistatus(*responses))

    def _report_sync_collection(self, request, calendar, xml_body, username, calendar_name):
        """Handle sync-collection REPORT (RFC 6578)."""
        events = calendar.events.all()

        responses = []
        cal_href = f'/remote.php/dav/calendars/{username}/{calendar_name}/'

        for event in events:
            event_href = f'{cal_href}{event.uid}.ics'
            props = D.prop(
                D.getetag(f'"{event.etag}"'),
                D.getcontenttype('text/calendar; charset=utf-8'),
            )
            responses.append(D.response(
                D.href(event_href),
                D.propstat(props, D.status('HTTP/1.1 200 OK'))
            ))

        body = D.multistatus(*responses)
        token_el = D('{DAV:}sync-token')
        token_el.text = f'http://sabre.io/ns/sync/{calendar.sync_token}'
        body.append(token_el)

        return xml_response(body)

    def mkcalendar(self, request, username, calendar_name):
        """Create a new calendar collection."""
        user = request.user
        if user.username != username:
            return HttpResponse(status=403)

        if Calendar.objects.filter(owner=user, name=calendar_name).exists():
            return HttpResponse(status=405)

        display_name = calendar_name
        description = ''
        color = '#3498db'
        timezone_val = 'UTC'

        xml_body = parse_xml_body(request)
        if xml_body is not None:
            dn = xml_body.find(f'.//{{{DAV_NS}}}displayname')
            if dn is not None and dn.text:
                display_name = dn.text
            desc = xml_body.find(f'.//{{{CALDAV_NS}}}calendar-description')
            if desc is not None and desc.text:
                description = desc.text
            tz = xml_body.find(f'.//{{{CALDAV_NS}}}calendar-timezone')
            if tz is not None and tz.text:
                timezone_val = tz.text
            color_el = xml_body.find('.//{http://apple.com/ns/ical/}calendar-color')
            if color_el is not None and color_el.text:
                color = color_el.text

        Calendar.objects.create(
            owner=user,
            name=calendar_name,
            display_name=display_name,
            description=description,
            timezone=timezone_val,
            color=color,
        )

        return HttpResponse(status=201)

    def delete(self, request, username, calendar_name):
        calendar, perm = self._get_calendar(request, username, calendar_name, require_write=True)
        if not calendar:
            return HttpResponse(status=403)
        if perm != 'admin' and calendar.owner != request.user:
            return HttpResponse(status=403)
        calendar.delete()
        return HttpResponse(status=204)

    def options(self, request, *args, **kwargs):
        response = HttpResponse()
        response['DAV'] = '1, 2, 3, calendar-access'
        response['Allow'] = 'OPTIONS, PROPFIND, REPORT, MKCALENDAR, DELETE'
        return response


class EventView(DavAuthView):
    """Handles /remote.php/dav/calendars/{username}/{calendar_name}/{event_uid}.ics
    GET - download event
    PUT - create/update event
    DELETE - delete event
    """

    def _get_calendar_and_event(self, request, username, calendar_name, event_filename):
        uid = event_filename
        if uid.endswith('.ics'):
            uid = uid[:-4]

        try:
            calendar = Calendar.objects.select_related('owner').get(
                owner__username=username, name=calendar_name)
        except Calendar.DoesNotExist:
            raise Http404()

        user = request.user
        if calendar.owner != user:
            share = CalendarShare.objects.filter(calendar=calendar, user=user).first()
            if not share:
                raise Http404()

        return calendar, uid

    def get(self, request, username, calendar_name, event_filename):
        calendar, uid = self._get_calendar_and_event(request, username, calendar_name, event_filename)

        try:
            event = calendar.events.get(uid=uid)
        except Event.DoesNotExist:
            raise Http404()

        response = HttpResponse(event.ical_data, content_type='text/calendar; charset=utf-8')
        response['ETag'] = f'"{event.etag}"'
        return response

    def put(self, request, username, calendar_name, event_filename):
        calendar, uid = self._get_calendar_and_event(request, username, calendar_name, event_filename)

        # Check write permission
        user = request.user
        if calendar.owner != user:
            share = CalendarShare.objects.filter(calendar=calendar, user=user).first()
            if not share or share.permission == 'read':
                return HttpResponse(status=403)

        ical_data = request.body.decode('utf-8')

        # Validate
        is_valid, error = validate_icalendar(ical_data)
        if not is_valid:
            return HttpResponse(f'Invalid iCalendar data: {error}', status=400)

        # Parse fields
        parsed = parse_icalendar(ical_data)
        ical_uid = parsed.get('uid', uid)

        # If-Match header for conflict detection
        if_match = request.META.get('HTTP_IF_MATCH')

        new_etag = generate_etag(ical_uid)

        try:
            event = calendar.events.get(uid=ical_uid)
            # Update existing
            if if_match and if_match.strip('"') != event.etag:
                return HttpResponse(status=412)  # Precondition Failed

            event.ical_data = ical_data
            event.summary = parsed.get('summary')
            event.description = parsed.get('description')
            event.location = parsed.get('location')
            event.dtstart = parsed.get('dtstart')
            event.dtend = parsed.get('dtend')
            event.all_day = parsed.get('all_day', False)
            event.recurrence_rule = parsed.get('recurrence_rule')
            event.etag = new_etag
            event.save()

            response = HttpResponse(status=204)
        except Event.DoesNotExist:
            # Create new
            if if_match:
                return HttpResponse(status=412)

            event = Event.objects.create(
                calendar=calendar,
                uid=ical_uid,
                ical_data=ical_data,
                summary=parsed.get('summary'),
                description=parsed.get('description'),
                location=parsed.get('location'),
                dtstart=parsed.get('dtstart'),
                dtend=parsed.get('dtend'),
                all_day=parsed.get('all_day', False),
                recurrence_rule=parsed.get('recurrence_rule'),
                etag=new_etag,
            )

            response = HttpResponse(status=201)

        response['ETag'] = f'"{event.etag}"'
        return response

    def delete(self, request, username, calendar_name, event_filename):
        calendar, uid = self._get_calendar_and_event(request, username, calendar_name, event_filename)

        # Check write permission
        user = request.user
        if calendar.owner != user:
            share = CalendarShare.objects.filter(calendar=calendar, user=user).first()
            if not share or share.permission == 'read':
                return HttpResponse(status=403)

        try:
            event = calendar.events.get(uid=uid)
            event.delete()
            return HttpResponse(status=204)
        except Event.DoesNotExist:
            raise Http404()

    def propfind(self, request, username, calendar_name, event_filename):
        calendar, uid = self._get_calendar_and_event(request, username, calendar_name, event_filename)

        try:
            event = calendar.events.get(uid=uid)
        except Event.DoesNotExist:
            raise Http404()

        event_href = f'/remote.php/dav/calendars/{username}/{calendar_name}/{event_filename}'
        responses = [D.response(
            D.href(event_href),
            _event_propstat(event, event_href)
        )]

        return xml_response(D.multistatus(*responses))

    def options(self, request, *args, **kwargs):
        response = HttpResponse()
        response['DAV'] = '1, 2, 3, calendar-access'
        response['Allow'] = 'OPTIONS, GET, PUT, DELETE, PROPFIND'
        return response


# ─── CardDAV Views ──────────────────────────────────────────────

def _get_user_addressbooks(user):
    """Get all addressbooks accessible to a user (own + shared)."""
    own = AddressBook.objects.filter(owner=user)
    shared_ids = AddressBookShare.objects.filter(user=user).values_list('addressbook_id', flat=True)
    shared = AddressBook.objects.filter(id__in=shared_ids)
    return list(own) + list(shared)


def _addressbook_propstat(addressbook, user, base_href):
    """Build propstat element for an addressbook collection."""
    rt = D.resourcetype(D.collection(), CARD('{urn:ietf:params:xml:ns:carddav}addressbook'))

    props = [
        rt,
        D.displayname(addressbook.display_name),
        D.getetag(f'"{addressbook.sync_token}"'),
        D('{DAV:}sync-token', f'http://sabre.io/ns/sync/{addressbook.sync_token}'),
    ]

    if addressbook.description:
        props.append(CARD('{urn:ietf:params:xml:ns:carddav}addressbook-description',
                          addressbook.description))

    # Supported address data
    sup = CARD('{urn:ietf:params:xml:ns:carddav}supported-address-data')
    addr_type = CARD('{urn:ietf:params:xml:ns:carddav}address-data-type')
    addr_type.set('content-type', 'text/vcard')
    addr_type.set('version', '3.0')
    sup.append(addr_type)
    addr_type4 = CARD('{urn:ietf:params:xml:ns:carddav}address-data-type')
    addr_type4.set('content-type', 'text/vcard')
    addr_type4.set('version', '4.0')
    sup.append(addr_type4)
    props.append(sup)

    # Permissions
    is_owner = addressbook.owner_id == user.id
    if is_owner:
        privs = D('{DAV:}current-user-privilege-set',
                   D.privilege(D.read()),
                   D.privilege(D.write()),
                   D.privilege(D('{DAV:}write-content')),
                   D.privilege(D('{DAV:}bind')),
                   D.privilege(D('{DAV:}unbind')))
    else:
        share = AddressBookShare.objects.filter(addressbook=addressbook, user=user).first()
        if share and share.permission in ('write', 'admin'):
            privs = D('{DAV:}current-user-privilege-set',
                       D.privilege(D.read()),
                       D.privilege(D.write()))
        else:
            privs = D('{DAV:}current-user-privilege-set',
                       D.privilege(D.read()))
    props.append(privs)

    return D.propstat(D.prop(*props), D.status('HTTP/1.1 200 OK'))


def _contact_propstat(contact, base_href):
    """Build propstat element for a contact resource."""
    props = D.prop(
        D.resourcetype(),  # Not a collection
        D.displayname(contact.fn or contact.uid),
        D.getetag(f'"{contact.etag}"'),
        D.getcontenttype('text/vcard; charset=utf-8'),
        D.getcontentlength(str(len(contact.vcard_data.encode('utf-8')))),
    )
    return D.propstat(props, D.status('HTTP/1.1 200 OK'))


class AddressBookListView(DavAuthView):
    """Handles /remote.php/dav/addressbooks/users/{username}/
    PROPFIND - list addressbooks
    """

    def propfind(self, request, username):
        user = request.user
        ensure_defaults_for_user(user)
        depth = get_depth(request)
        addressbooks = _get_user_addressbooks(user)

        responses = []

        # The collection itself
        home_href = f'/remote.php/dav/addressbooks/users/{user.username}/'
        home_props = D.prop(
            D.resourcetype(D.collection()),
            D.displayname('Address Books'),
            D('{DAV:}current-user-principal',
              D.href(f'/remote.php/dav/principals/users/{user.username}/')),
        )
        responses.append(D.response(
            D.href(home_href),
            D.propstat(home_props, D.status('HTTP/1.1 200 OK'))
        ))

        # List addressbooks if depth > 0
        if depth != '0':
            for ab in addressbooks:
                ab_href = f'/remote.php/dav/addressbooks/users/{ab.owner.username}/{ab.name}/'
                responses.append(D.response(
                    D.href(ab_href),
                    _addressbook_propstat(ab, user, ab_href)
                ))

        return xml_response(D.multistatus(*responses))

    def options(self, request, *args, **kwargs):
        response = HttpResponse()
        response['DAV'] = '1, 2, 3, addressbook'
        response['Allow'] = 'OPTIONS, PROPFIND'
        return response


class AddressBookView(DavAuthView):
    """Handles /remote.php/dav/addressbooks/users/{username}/{addressbook_name}/
    PROPFIND - list contacts in addressbook
    REPORT - addressbook-query, addressbook-multiget
    DELETE - delete addressbook
    """

    def _get_addressbook(self, request, username, addressbook_name, require_write=False):
        try:
            addressbook = AddressBook.objects.select_related('owner').get(
                owner__username=username, name=addressbook_name)
        except AddressBook.DoesNotExist:
            raise Http404()

        user = request.user
        if addressbook.owner == user:
            return addressbook, 'admin'

        share = AddressBookShare.objects.filter(addressbook=addressbook, user=user).first()
        if not share:
            raise Http404()
        if require_write and share.permission == 'read':
            return None, None
        return addressbook, share.permission

    def propfind(self, request, username, addressbook_name):
        addressbook, perm = self._get_addressbook(request, username, addressbook_name)
        if not addressbook:
            raise Http404()

        depth = get_depth(request)
        responses = []

        # Addressbook collection
        ab_href = f'/remote.php/dav/addressbooks/users/{username}/{addressbook_name}/'
        responses.append(D.response(
            D.href(ab_href),
            _addressbook_propstat(addressbook, request.user, ab_href)
        ))

        # List contacts if depth > 0
        if depth != '0':
            for contact in addressbook.contacts.all():
                contact_href = f'{ab_href}{contact.uid}.vcf'
                responses.append(D.response(
                    D.href(contact_href),
                    _contact_propstat(contact, contact_href)
                ))

        return xml_response(D.multistatus(*responses))

    def report(self, request, username, addressbook_name):
        addressbook, perm = self._get_addressbook(request, username, addressbook_name)
        if not addressbook:
            raise Http404()

        xml_body = parse_xml_body(request)
        if xml_body is None:
            return HttpResponse(status=400)

        root_tag = etree.QName(xml_body.tag)

        if root_tag.localname == 'addressbook-multiget':
            return self._report_multiget(request, addressbook, xml_body, username, addressbook_name)
        elif root_tag.localname == 'addressbook-query':
            return self._report_query(request, addressbook, xml_body, username, addressbook_name)
        elif root_tag.localname == 'sync-collection':
            return self._report_sync_collection(request, addressbook, xml_body, username, addressbook_name)
        else:
            return HttpResponse(status=400)

    def _report_multiget(self, request, addressbook, xml_body, username, addressbook_name):
        """Handle addressbook-multiget REPORT."""
        responses = []
        hrefs = xml_body.findall(f'{{{DAV_NS}}}href')

        for href_el in hrefs:
            href = href_el.text.strip()
            parts = href.rstrip('/').split('/')
            if not parts:
                continue
            filename = parts[-1]
            if filename.endswith('.vcf'):
                uid = filename[:-4]
            else:
                uid = filename

            try:
                contact = addressbook.contacts.get(uid=uid)
                addr_data = CARD('{urn:ietf:params:xml:ns:carddav}address-data')
                addr_data.text = contact.vcard_data

                props = D.prop(
                    D.getetag(f'"{contact.etag}"'),
                    D.getcontenttype('text/vcard; charset=utf-8'),
                    addr_data,
                )
                responses.append(D.response(
                    D.href(href),
                    D.propstat(props, D.status('HTTP/1.1 200 OK'))
                ))
            except Contact.DoesNotExist:
                responses.append(D.response(
                    D.href(href),
                    D.propstat(D.prop(), D.status('HTTP/1.1 404 Not Found'))
                ))

        return xml_response(D.multistatus(*responses))

    def _report_query(self, request, addressbook, xml_body, username, addressbook_name):
        """Handle addressbook-query REPORT."""
        contacts = addressbook.contacts.all()

        # Apply text-match filters
        prop_filters = xml_body.findall(f'.//{{{CARDDAV_NS}}}prop-filter')
        for pf in prop_filters:
            prop_name = pf.get('name', '').upper()
            text_match = pf.find(f'{{{CARDDAV_NS}}}text-match')
            if text_match is not None and text_match.text:
                match_type = text_match.get('match-type', 'contains')
                value = text_match.text

                if prop_name == 'FN':
                    field = 'fn'
                elif prop_name == 'EMAIL':
                    field = 'email'
                elif prop_name == 'TEL':
                    field = 'tel'
                elif prop_name == 'ORG':
                    field = 'org'
                else:
                    continue

                if match_type == 'contains':
                    contacts = contacts.filter(**{f'{field}__icontains': value})
                elif match_type == 'starts-with':
                    contacts = contacts.filter(**{f'{field}__istartswith': value})
                elif match_type == 'ends-with':
                    contacts = contacts.filter(**{f'{field}__iendswith': value})
                elif match_type == 'equals':
                    contacts = contacts.filter(**{f'{field}__iexact': value})

        # Check if address-data is requested
        addr_data_requested = xml_body.find(f'.//{{{CARDDAV_NS}}}address-data') is not None

        responses = []
        ab_href = f'/remote.php/dav/addressbooks/users/{username}/{addressbook_name}/'

        for contact in contacts:
            contact_href = f'{ab_href}{contact.uid}.vcf'
            prop_children = [
                D.getetag(f'"{contact.etag}"'),
                D.getcontenttype('text/vcard; charset=utf-8'),
            ]
            if addr_data_requested:
                addr_data_el = CARD('{urn:ietf:params:xml:ns:carddav}address-data')
                addr_data_el.text = contact.vcard_data
                prop_children.append(addr_data_el)

            responses.append(D.response(
                D.href(contact_href),
                D.propstat(D.prop(*prop_children), D.status('HTTP/1.1 200 OK'))
            ))

        return xml_response(D.multistatus(*responses))

    def _report_sync_collection(self, request, addressbook, xml_body, username, addressbook_name):
        """Handle sync-collection REPORT (RFC 6578)."""
        contacts = addressbook.contacts.all()

        responses = []
        ab_href = f'/remote.php/dav/addressbooks/users/{username}/{addressbook_name}/'

        for contact in contacts:
            contact_href = f'{ab_href}{contact.uid}.vcf'
            props = D.prop(
                D.getetag(f'"{contact.etag}"'),
                D.getcontenttype('text/vcard; charset=utf-8'),
            )
            responses.append(D.response(
                D.href(contact_href),
                D.propstat(props, D.status('HTTP/1.1 200 OK'))
            ))

        body = D.multistatus(*responses)
        token_el = D('{DAV:}sync-token')
        token_el.text = f'http://sabre.io/ns/sync/{addressbook.sync_token}'
        body.append(token_el)

        return xml_response(body)

    def mkcol(self, request, username, addressbook_name):
        """Create a new addressbook collection."""
        user = request.user
        if user.username != username:
            return HttpResponse(status=403)

        if AddressBook.objects.filter(owner=user, name=addressbook_name).exists():
            return HttpResponse(status=405)

        display_name = addressbook_name
        description = ''

        xml_body = parse_xml_body(request)
        if xml_body is not None:
            dn = xml_body.find(f'.//{{{DAV_NS}}}displayname')
            if dn is not None and dn.text:
                display_name = dn.text
            desc = xml_body.find(f'.//{{{CARDDAV_NS}}}addressbook-description')
            if desc is not None and desc.text:
                description = desc.text

        AddressBook.objects.create(
            owner=user,
            name=addressbook_name,
            display_name=display_name,
            description=description,
        )

        return HttpResponse(status=201)

    def delete(self, request, username, addressbook_name):
        addressbook, perm = self._get_addressbook(request, username, addressbook_name, require_write=True)
        if not addressbook:
            return HttpResponse(status=403)
        if perm != 'admin' and addressbook.owner != request.user:
            return HttpResponse(status=403)
        addressbook.delete()
        return HttpResponse(status=204)

    def options(self, request, *args, **kwargs):
        response = HttpResponse()
        response['DAV'] = '1, 2, 3, addressbook'
        response['Allow'] = 'OPTIONS, PROPFIND, REPORT, MKCOL, DELETE'
        return response


class ContactView(DavAuthView):
    """Handles /remote.php/dav/addressbooks/users/{username}/{addressbook_name}/{contact_uid}.vcf
    GET - download contact
    PUT - create/update contact
    DELETE - delete contact
    """

    def _get_addressbook_and_contact(self, request, username, addressbook_name, contact_filename):
        uid = contact_filename
        if uid.endswith('.vcf'):
            uid = uid[:-4]

        try:
            addressbook = AddressBook.objects.select_related('owner').get(
                owner__username=username, name=addressbook_name)
        except AddressBook.DoesNotExist:
            raise Http404()

        user = request.user
        if addressbook.owner != user:
            share = AddressBookShare.objects.filter(addressbook=addressbook, user=user).first()
            if not share:
                raise Http404()

        return addressbook, uid

    def get(self, request, username, addressbook_name, contact_filename):
        addressbook, uid = self._get_addressbook_and_contact(
            request, username, addressbook_name, contact_filename)

        try:
            contact = addressbook.contacts.get(uid=uid)
        except Contact.DoesNotExist:
            raise Http404()

        response = HttpResponse(contact.vcard_data, content_type='text/vcard; charset=utf-8')
        response['ETag'] = f'"{contact.etag}"'
        return response

    def put(self, request, username, addressbook_name, contact_filename):
        addressbook, uid = self._get_addressbook_and_contact(
            request, username, addressbook_name, contact_filename)

        # Check write permission
        user = request.user
        if addressbook.owner != user:
            share = AddressBookShare.objects.filter(addressbook=addressbook, user=user).first()
            if not share or share.permission == 'read':
                return HttpResponse(status=403)

        vcard_data = request.body.decode('utf-8')

        # Validate
        is_valid, error = validate_vcard(vcard_data)
        if not is_valid:
            return HttpResponse(f'Invalid vCard data: {error}', status=400)

        # Parse fields
        parsed = parse_vcard(vcard_data)
        vcard_uid = parsed.get('uid', uid)

        # If-Match for conflict detection
        if_match = request.META.get('HTTP_IF_MATCH')

        new_etag = generate_etag(vcard_uid)

        try:
            contact = addressbook.contacts.get(uid=vcard_uid)
            # Update
            if if_match and if_match.strip('"') != contact.etag:
                return HttpResponse(status=412)

            contact.vcard_data = vcard_data
            contact.fn = parsed.get('fn')
            contact.n = parsed.get('n')
            contact.email = parsed.get('email')
            contact.tel = parsed.get('tel')
            contact.org = parsed.get('org')
            contact.etag = new_etag
            contact.save()

            response = HttpResponse(status=204)
        except Contact.DoesNotExist:
            # Create
            if if_match:
                return HttpResponse(status=412)

            contact = Contact.objects.create(
                addressbook=addressbook,
                uid=vcard_uid,
                vcard_data=vcard_data,
                fn=parsed.get('fn'),
                n=parsed.get('n'),
                email=parsed.get('email'),
                tel=parsed.get('tel'),
                org=parsed.get('org'),
                etag=new_etag,
            )

            response = HttpResponse(status=201)

        response['ETag'] = f'"{contact.etag}"'
        return response

    def delete(self, request, username, addressbook_name, contact_filename):
        addressbook, uid = self._get_addressbook_and_contact(
            request, username, addressbook_name, contact_filename)

        user = request.user
        if addressbook.owner != user:
            share = AddressBookShare.objects.filter(addressbook=addressbook, user=user).first()
            if not share or share.permission == 'read':
                return HttpResponse(status=403)

        try:
            contact = addressbook.contacts.get(uid=uid)
            contact.delete()
            return HttpResponse(status=204)
        except Contact.DoesNotExist:
            raise Http404()

    def propfind(self, request, username, addressbook_name, contact_filename):
        addressbook, uid = self._get_addressbook_and_contact(
            request, username, addressbook_name, contact_filename)

        try:
            contact = addressbook.contacts.get(uid=uid)
        except Contact.DoesNotExist:
            raise Http404()

        contact_href = f'/remote.php/dav/addressbooks/users/{username}/{addressbook_name}/{contact_filename}'
        responses = [D.response(
            D.href(contact_href),
            _contact_propstat(contact, contact_href)
        )]

        return xml_response(D.multistatus(*responses))

    def options(self, request, *args, **kwargs):
        response = HttpResponse()
        response['DAV'] = '1, 2, 3, addressbook'
        response['Allow'] = 'OPTIONS, GET, PUT, DELETE, PROPFIND'
        return response


# ─── Well-Known Redirects ──────────────────────────────────────

@method_decorator(csrf_exempt, name='dispatch')
class DavOptionsView(View):
    """Respond to OPTIONS on /remote.php/webdav for DAV discovery."""
    def dispatch(self, request, *args, **kwargs):
        response = HttpResponse(status=200)
        response['Allow'] = 'OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE'
        response['DAV'] = '1, 2, 3'
        return response


class WellKnownCalDavView(View):
    def dispatch(self, request, *args, **kwargs):
        response = HttpResponse(status=301)
        response['Location'] = '/remote.php/dav/'
        return response


class WellKnownCardDavView(View):
    def dispatch(self, request, *args, **kwargs):
        response = HttpResponse(status=301)
        response['Location'] = '/remote.php/dav/'
        return response
