import logging

from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer

from file.models import File, SharedFolderMembership

logger = logging.getLogger(__name__)


class EditorConsumer(AsyncWebsocketConsumer):
    """
    WebSocket consumer for collaborative Yjs editing.
    Operates as a relay: broadcasts binary Yjs messages between all
    clients connected to the same file room.
    """

    async def connect(self):
        self.user = self.scope.get("user")
        if not self.user or self.user.is_anonymous:
            await self.close(code=4001)
            return

        self.file_id = self.scope["url_route"]["kwargs"]["file_id"]
        self.room_group_name = f"editor_{self.file_id}"

        # Check file access
        access = await self._check_file_access()
        if access is None:
            await self.close(code=4003)
            return

        self.can_write = access

        await self.channel_layer.group_add(
            self.room_group_name, self.channel_name
        )
        await self.accept()

    async def disconnect(self, close_code):
        if hasattr(self, "room_group_name"):
            await self.channel_layer.group_discard(
                self.room_group_name, self.channel_name
            )

    async def receive(self, text_data=None, bytes_data=None):
        if bytes_data:
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    "type": "yjs.message",
                    "data": bytes_data,
                    "sender_channel": self.channel_name,
                },
            )

    async def yjs_message(self, event):
        # Relay to all clients except the sender
        if event.get("sender_channel") != self.channel_name:
            await self.send(bytes_data=event["data"])

    @database_sync_to_async
    def _check_file_access(self):
        """Return True if user can write, False if read-only, None if no access."""
        try:
            file_obj = File.objects.get(id=self.file_id)
        except File.DoesNotExist:
            return None

        # Owner has full access
        if file_obj.owner_id == self.user.id:
            return True

        # Check shared folder membership
        if not file_obj.full_path or not file_obj.full_path.startswith("/__shared__/"):
            return None

        parts = file_obj.full_path.split("/")
        if len(parts) < 4:
            return None
        share_name = parts[2]

        membership = SharedFolderMembership.objects.filter(
            shared_folder__name=share_name, user=self.user
        ).first()
        if not membership:
            return None

        return membership.permission in ("write", "admin")
