import json
from channels.generic.websocket import AsyncWebsocketConsumer


class ScanConsumer(AsyncWebsocketConsumer):
    """
    WebSocket consumer — sends live scan events to the browser.
    Each scan has its own channel group: scan_{session_id}

    Domain confirmation is handled via POST /scan/{id}/continue/
    so the consumer is now purely one-way: server → client.
    """

    async def connect(self):
        self.session_id = self.scope['url_route']['kwargs']['session_id']
        self.group_name = f'scan_{self.session_id}'

        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

        await self.send(text_data=json.dumps({
            'type': 'connected',
            'message': 'WebSocket connected. Waiting for scan to start...',
        }))

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive(self, text_data):
        # No client → server messages needed anymore.
        # Domain confirmation goes through HTTP POST.
        pass

    async def scan_update(self, event):
        """Relay an event from Celery → browser."""
        await self.send(text_data=json.dumps(event['message']))
