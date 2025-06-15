from fastapi import APIRouter, Query, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import update, select
from app.config.database.session import get_db
from app.config.twitch_auth import TwitchAuth
from app.models.twitch.twitch_models import TwitchToken
from datetime import datetime, timedelta

router = APIRouter(prefix="/auth", tags=["Twitch Authentication"])


@router.get("/twitch/callback")
async def twitch_callback(
    code: str = Query(...),
    state: str = Query(...),
    error: str = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """Handle Twitch OAuth callback"""
    if error:
        raise HTTPException(status_code=400, detail=f"Twitch OAuth error: {error}")

    try:
        twitch_auth = TwitchAuth()
        token_data = await twitch_auth.exchange_code_for_token(code)

        # Store token in database
        expires_at = datetime.now() + timedelta(
            seconds=token_data.get("expires_in", 3600)
        )

        # Deactivate old tokens using SQLAlchemy ORM
        stmt = (
            update(TwitchToken)
            .where(TwitchToken.is_active)
            .values(is_active=False)
        )
        await db.execute(stmt)

        # Store new token
        token = TwitchToken(
            access_token=token_data.get("access_token"),
            refresh_token=token_data.get("refresh_token"),
            expires_at=expires_at,
            is_active=True,
        )
        db.add(token)
        await db.commit()

        return {
            "message": "Successfully authenticated with Twitch and token stored",
            "expires_in": token_data.get("expires_in"),
        }
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to exchange code: {str(e)}"
        )


@router.get("/twitch/login")
async def twitch_login():
    """Redirect user to Twitch for authorization"""
    twitch_auth = TwitchAuth()
    auth_url = twitch_auth.get_authorization_url()
    return {"authorization_url": auth_url}


@router.post("/twitch/disconnect")
async def twitch_disconnect(db: AsyncSession = Depends(get_db)):
    """Disconnect from Twitch by deactivating tokens"""
    try:
        # Deactivate all active tokens
        stmt = (
            update(TwitchToken)
            .where(TwitchToken.is_active)
            .values(is_active=False)
        )
        await db.execute(stmt)
        await db.commit()

        # Disable IRC connection
        from app.main import twitch_client

        twitch_client.connection_enabled = False

        return {"message": "Successfully disconnected from Twitch"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to disconnect: {str(e)}")


@router.get("/twitch/status")
async def twitch_status(db: AsyncSession = Depends(get_db)):
    """Get current Twitch connection status"""
    try:
        from app.main import twitch_client

        stmt = (
            select(TwitchToken)
            .where(TwitchToken.is_active)
            .order_by(TwitchToken.created_at.desc())
        )
        result = await db.execute(stmt)
        token_record = result.scalars().first()

        return {
            "connection_enabled": twitch_client.connection_enabled,
            "has_active_token": bool(token_record),
            "token_expires_at": token_record.expires_at.isoformat()
            if token_record
            else None,
            "is_connected": twitch_client.writer is not None,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Status check failed: {str(e)}")
