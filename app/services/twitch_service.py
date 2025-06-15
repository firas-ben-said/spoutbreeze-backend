from datetime import datetime, timedelta
from sqlalchemy import select, update
from app.config.database.session import get_db
from app.models.twitch.twitch_models import TwitchToken
from app.config.twitch_auth import TwitchAuth
from app.config.logger_config import get_logger

logger = get_logger("TwitchService")

class TwitchService:
    def __init__(self):
        self.twitch_auth = TwitchAuth()
    
    async def get_connection_status(self) -> dict:
        """Get current Twitch connection status"""
        async for db in get_db():
            stmt = select(TwitchToken).where(TwitchToken.is_active == True).order_by(TwitchToken.created_at.desc())
            result = await db.execute(stmt)
            token = result.scalars().first()
            
            if not token:
                return {"status": "disconnected", "needs_auth": True}
            
            # Check if token is expired or will expire soon
            expires_soon = token.expires_at <= datetime.now() + timedelta(hours=1)
            
            if expires_soon and not token.refresh_token:
                return {"status": "expired", "needs_auth": True}
            
            return {
                "status": "connected",
                "needs_auth": False,
                "expires_at": token.expires_at.isoformat(),
                "can_refresh": bool(token.refresh_token)
            }
    
    async def is_token_valid(self) -> bool:
        """Quick check if we have a valid token"""
        async for db in get_db():
            stmt = select(TwitchToken).where(
                TwitchToken.is_active == True,
                TwitchToken.expires_at > datetime.now() + timedelta(minutes=5)
            )
            result = await db.execute(stmt)
            return bool(result.scalars().first())
    
    async def disconnect(self):
        """Disconnect Twitch account"""
        async for db in get_db():
            stmt = update(TwitchToken).where(TwitchToken.is_active == True).values(is_active=False)
            await db.execute(stmt)
            await db.commit()