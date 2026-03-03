from channels.db import database_sync_to_async
from channels.middleware import BaseMiddleware
from django.contrib.auth.models import AnonymousUser
from django.contrib.sessions.models import Session
from django.utils import timezone

from file.models import User


@database_sync_to_async
def get_user_from_session(session_key):
    try:
        session = Session.objects.get(session_key=session_key, expire_date__gte=timezone.now())
        uid = session.get_decoded().get('_auth_user_id')
        if uid:
            return User.objects.get(id=uid)
    except (Session.DoesNotExist, User.DoesNotExist):
        pass
    return AnonymousUser()


class SessionAuthMiddleware(BaseMiddleware):
    async def __call__(self, scope, receive, send):
        headers = dict(scope.get("headers", []))
        cookie_header = headers.get(b"cookie", b"").decode("utf-8")

        session_key = None
        for cookie in cookie_header.split("; "):
            if cookie.startswith("sessionid="):
                session_key = cookie.split("=", 1)[1]
                break

        if session_key:
            scope["user"] = await get_user_from_session(session_key)
        else:
            scope["user"] = AnonymousUser()

        return await super().__call__(scope, receive, send)
