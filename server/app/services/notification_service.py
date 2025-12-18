import logging
import httpx
import os
from enum import Enum

logger = logging.getLogger(__name__)

class AlertLevel(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    SUCCESS = "success"

class NotificationService:
    def __init__(self):
        self.webhook_url = os.getenv("SLACK_WEBHOOK_URL")

    async def send_slack_notification(self, message: str, level: AlertLevel = AlertLevel.INFO):
        if not self.webhook_url:
            logger.warning("Slack Webhook URL not configured. Notification skipped.")
            return

        try:
            emoji = "ℹ️"
            color = "#36a64f" # Default green/info

            if level == AlertLevel.WARNING:
                emoji = "⚠️"
                color = "#ffcc00"
            elif level == AlertLevel.ERROR:
                emoji = "🚨"
                color = "#ff0000"
            elif level == AlertLevel.CRITICAL:
                emoji = "🔥"
                color = "#7b0000"
            elif level == AlertLevel.SUCCESS:
                emoji = "✅"
                color = "#00ff00"

            payload = {
                "text": f"{emoji} *Luna Security Alert* [{level.value.upper()}]\n{message}"
            }

            async with httpx.AsyncClient() as client:
                response = await client.post(self.webhook_url, json=payload)
                response.raise_for_status()
                logger.info(f"Notification sent to Slack: {message}")

        except Exception as e:
            logger.error(f"Failed to send Slack notification: {str(e)}")


