from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from datetime import datetime, timezone
from fastapi.security import (
    OAuth2AuthorizationCodeBearer,
    HTTPBearer,
)
from app.services.auth_service import AuthService
from app.models.auth_models import (
    TokenRequest,
    TokenResponse,
)
from app.config.settings import keycloak_openid, get_settings
from app.config.database.session import get_db
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError
from sqlalchemy import select
from app.models.user_models import User
from app.controllers.user_controller import get_current_user
from typing import cast
from datetime import timedelta

from app.config.logger_config import logger
from pydantic import BaseModel


bearer_scheme = HTTPBearer()
settings = get_settings()

router = APIRouter(prefix="/api", tags=["Authentication"])

# OAuth2 scheme for token extraction
oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl=f"{keycloak_openid.well_known()['authorization_endpoint']}",
    tokenUrl=f"{keycloak_openid.well_known()['token_endpoint']}",
)

auth_service = AuthService()


class ProtectedRouteResponse(BaseModel):
    message: str


@router.get("/protected", response_model=ProtectedRouteResponse)
async def protected_route(current_user: User = Depends(get_current_user)):
    """
    Protected route that requires authentication

    Returns:
        A welcome message with the username
    """
    return {"message": f"Hello, {current_user.username}! This is a protected route."}


@router.post("/token")
async def exchange_token(
    request: TokenRequest, response: Response, db: AsyncSession = Depends(get_db)
):
    """Exchange authorization code for tokens and set secure cookies"""
    try:
        token_data = auth_service.exchange_token(
            request.code, request.redirect_uri, request.code_verifier
        )

        # Extract the access token
        access_token = token_data.get("access_token")

        # Get user information
        user_info = auth_service.get_user_info(cast(str, access_token))
        print("User info:", user_info)

        # Check if the user already exists
        keycloak_id = user_info.get("sub")

        stmt = select(User).where(User.keycloak_id == keycloak_id)
        result = await db.execute(stmt)
        existing_user = result.scalars().first()

        if not existing_user:
            # Create a new user in the database
            new_user = User(
                keycloak_id=str(keycloak_id),
                username=str(user_info.get("preferred_username", "")),
                email=str(user_info.get("email", "")),
                first_name=str(user_info.get("given_name", "")),
                last_name=str(user_info.get("family_name", "")),
            )
            db.add(new_user)
            await db.commit()
            await db.refresh(new_user)
            logger.info(
                f"New user created: {new_user.username}, with keycloak ID: {new_user.keycloak_id}"
            )
        else:
            # Update the existing user information
            setattr(
                existing_user,
                "username",
                str(user_info.get("preferred_username", existing_user.username)),
            )
            setattr(
                existing_user, "email", str(user_info.get("email", existing_user.email))
            )
            setattr(
                existing_user,
                "first_name",
                str(user_info.get("given_name", existing_user.first_name)),
            )
            setattr(
                existing_user,
                "last_name",
                str(user_info.get("family_name", existing_user.last_name)),
            )
            setattr(existing_user, "updated_at", datetime.now())
            await db.commit()
            await db.refresh(existing_user)
            logger.info(
                f"User updated: {existing_user.username}, with keycloak ID: {existing_user.keycloak_id}"
            )

        # Set HTTP-only cookies with proper UTC datetime
        access_token_expires = datetime.now(timezone.utc) + timedelta(
            seconds=token_data.get("expires_in", 300)
        )
        refresh_token_expires = datetime.now(timezone.utc) + timedelta(days=30)

        # Set access token cookie
        response.set_cookie(
            key="access_token",
            value=token_data["access_token"],
            expires=access_token_expires,
            httponly=True,
            # secure=settings.env == "production",  # Only secure in production
            secure=True, # Always secure for cookies
            # samesite="lax",
            samesite="none",
            path="/",
            domain=".67.222.155.30.nip.io",
        )

        # Set refresh token cookie
        response.set_cookie(
            key="refresh_token",
            value=token_data["refresh_token"],
            expires=refresh_token_expires,
            httponly=True,
            # secure=settings.env == "production",  # Only secure in production
            secure=True,
            # samesite="lax",
            samesite="none",
            path="/",
            domain=".67.222.155.30.nip.io",
        )

        # Return user info only (no tokens)
        return {
            "user_info": user_info,
            "expires_in": token_data["expires_in"],
            "token_type": "Bearer",
        }
    except IntegrityError as e:
        await db.rollback()
        logger.error(f"Database integrity error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User with this Keycloak ID already exists",
        )
    except Exception as e:
        logger.error(f"Error exchanging token: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to exchange token: {str(e)}",
        )


@router.post("/refresh")
async def refresh_token(request: Request, response: Response):
    """Refresh tokens using cookie-stored refresh token"""
    try:
        # Get refresh token from cookie instead of request body
        refresh_token = request.cookies.get("refresh_token")

        if not refresh_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token not found",
            )

        token_data = auth_service.refresh_token(refresh_token)

        # Set new cookies with proper UTC datetime
        access_token_expires = datetime.now(timezone.utc) + timedelta(
            seconds=token_data.get("expires_in", 300)
        )
        refresh_token_expires = datetime.now(timezone.utc) + timedelta(days=30)

        response.set_cookie(
            key="access_token",
            value=token_data["access_token"],
            expires=access_token_expires,
            httponly=True,
            # secure=settings.env == "production",  # Only secure in production
            secure=True,  # Always secure for cookies
            samesite="none",
            path="/",
            domain=".67.222.155.30.nip.io",
        )

        response.set_cookie(
            key="refresh_token",
            value=token_data["refresh_token"],
            expires=refresh_token_expires,
            httponly=True,
            # secure=settings.env == "production",  # Only secure in production
            secure=True,  # Always secure for cookies
            samesite="none",
            path="/",
            domain=".67.222.155.30.nip.io",
        )

        return {
            "user_info": token_data["user_info"],
            "expires_in": token_data["expires_in"],
            "token_type": "Bearer",
        }
    except Exception as e:
        # Clear cookies on error
        response.delete_cookie("access_token", path="/")
        response.delete_cookie("refresh_token", path="/")
        logger.error(f"Refresh token error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token invalid or expired",
        )


# FOR DEVELOPMENT ONLY
@router.post("/dev-token", response_model=TokenResponse)
async def get_dev_token(
    username: str,
    password: str,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """Development endpoint to get tokens (ONLY FOR LOCAL TESTING)"""
    try:
        # Only allow in development mode
        env = settings.env
        if env != "development":
            raise HTTPException(status_code=404, detail="Not found")

        # Get token from Keycloak
        token_response = keycloak_openid.token(
            grant_type="password",
            username=username,
            password=password,
            scope="openid profile email",
        )

        # Process user info
        access_token = token_response.get("access_token")
        user_info = auth_service.get_user_info(cast(str, access_token))

        # Check if user exists
        keycloak_id = user_info.get("sub")
        stmt = select(User).where(User.keycloak_id == keycloak_id)
        result = await db.execute(stmt)
        existing_user = result.scalars().first()

        # Create user if doesn't exist (similar to exchange_token)
        if not existing_user:
            # Create new user logic here
            pass

        # Set HTTP-only cookies with proper UTC datetime
        access_token_expires = datetime.now(timezone.utc) + timedelta(
            seconds=token_response.get("expires_in", 300)
        )
        refresh_token_expires = datetime.now(timezone.utc) + timedelta(days=30)

        # Set access token cookie
        response.set_cookie(
            key="access_token",
            value=token_response["access_token"],
            expires=access_token_expires,
            httponly=True,
            # secure=settings.env == "production",  # Only secure in production
            secure=True,  # Always secure for cookies
            samesite="none",
            path="/",
            domain=".67.222.155.30.nip.io",
        )

        # Set refresh token cookie
        response.set_cookie(
            key="refresh_token",
            value=token_response["refresh_token"],
            expires=refresh_token_expires,
            httponly=True,
            # secure=settings.env == "production",  # Only secure in production
            secure=True,  # Always secure for cookies
            samesite="none",
            path="/",
            domain=".67.222.155.30.nip.io",
        )

        return {
            "access_token": token_response["access_token"],
            "expires_in": token_response["expires_in"],
            "refresh_token": token_response["refresh_token"],
            "refresh_expires_in": token_response["refresh_expires_in"],
            "token_type": "Bearer",
            "user_info": user_info,
        }

    except IntegrityError as e:
        await db.rollback()
        logger.error(f"Database integrity error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User with this Keycloak ID already exists",
        )
    except Exception as e:
        logger.error(f"Dev token error: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Failed to get token: {str(e)}")


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Logout the user and invalidate the refresh token
    """
    try:
        # Get refresh token from cookie
        refresh_token = request.cookies.get("refresh_token")

        if refresh_token:
            auth_service.logout(refresh_token)

        # Clear cookies
        response.delete_cookie("access_token", path="/")
        response.delete_cookie("refresh_token", path="/")

        # Clear Keycloak cookies as well
        keycloak_cookies = [
            "AUTH_SESSION_ID",
            "KC_AUTH_SESSION_HASH",
            "KEYCLOAK_IDENTITY",
            "KEYCLOAK_SESSION",
        ]

        for cookie_name in keycloak_cookies:
            response.delete_cookie(
                cookie_name, path=f"/realms/${settings.keycloak_realm}/"
            )
            # Also try to clear for the Keycloak domain if different
            response.delete_cookie(
                cookie_name,
                path=f"/realms/${settings.keycloak_realm}/",
                domain=".localhost",
            )

        return {
            "message": "Successfully logged out",
            "statusCode": status.HTTP_200_OK,
        }
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        # Still clear cookies even if logout fails
        response.delete_cookie("access_token", path="/")
        response.delete_cookie("refresh_token", path="/")
        return {
            "message": "Successfully logged out",
            "statusCode": status.HTTP_200_OK,
        }
