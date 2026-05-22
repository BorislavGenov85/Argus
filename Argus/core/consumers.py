import json
from channels.generic.websocket import AsyncWebsocketConsumer


class ScanConsumer(AsyncWebsocketConsumer):
    """
    WebSocket consumer — изпраща live updates от сканирането към браузъра.
    Всеки скан има собствена група: scan_{session_id}
    """

    async def connect(self):
        self.session_id = self.scope['url_route']['kwargs']['session_id']
        self.group_name = f'scan_{self.session_id}'

        # Добавяме се към групата
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

        # Изпраща потвърждение към клиента че е свързан
        # Celery task чака countdown=2s преди да стартира, така имаме буфер
        await self.send(text_data=json.dumps({
            'type': 'connected',
            'message': '🔗 WebSocket connected. Waiting for scan to start...'
        }))

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def scan_update(self, event):
        """Получава update от Celery task и го праща към браузъра."""
        await self.send(text_data=json.dumps(event['message']))