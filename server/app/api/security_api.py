from fastapi import APIRouter, HTTPException, status, Depends
from pydantic import BaseModel
import hashlib
import httpx
import logging
from app.dependencies import get_current_user, get_notification_service
from app.dto.token import UserInfo
from app.services.notification_service import NotificationService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/security", tags=["security"])

class PasswordCheckRequest(BaseModel):
    password: str

@router.post("/check-leak")
async def check_leak(
    request: PasswordCheckRequest,
    _user_info: UserInfo = Depends(get_current_user),
    notification_service: NotificationService = Depends(get_notification_service)
):
    """
    Check if a password has been compromised using HaveIBeenPwned API (k-anonymity).
    """
    try:
        # 1. Hash the password with SHA-1
        sha1_password = hashlib.sha1(request.password.encode("utf-8")).hexdigest().upper()
        
        # 2. Split into prefix (5 chars) and suffix
        prefix = sha1_password[:5]
        suffix = sha1_password[5:]
        
        # 3. Query HIBP API
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        async with httpx.AsyncClient() as client:
            response = await client.get(url)
            response.raise_for_status()
            
            # 4. Parse response
            hashes = (line.split(':') for line in response.text.splitlines())
            for h, count in hashes:
                if h == suffix:
                    # Leak detected
                    count_int = int(count)
                    await notification_service.send_slack_notification(
                        f"LEAK DETECTED! A user just checked a password that appears in {count_int} breaches.",
                        level="warning"
                    )
                    return {"is_leaked": True, "count": count_int}
            
            return {"is_leaked": False, "count": 0}
            
    except Exception as e:
        logger.error(f"Error checking leak: {str(e)}")

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to check leak status: {str(e)}"
        )
