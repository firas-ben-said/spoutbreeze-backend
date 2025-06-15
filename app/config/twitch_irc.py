import asyncio
import ssl
import httpx
from datetime import datetime, timedelta
from sqlalchemy import select, update
from typing import Optional, Dict, Any

from app.config.chat_manager import chat_manager
from app.config.settings import get_settings
from app.config.logger_config import get_logger
from app.config.database.session import get_db
from app.models.twitch.twitch_models import TwitchToken

logger = get_logger("Twitch")


class TwitchIRCClient:
    def __init__(self):
        self.settings = get_settings()
        self.server = self.settings.twitch_server
        self.port = self.settings.twitch_port
        self.nickname = self.settings.twitch_nick
        self.channel = f"#{self.settings.twitch_channel}"
        self.reader = None
        self.writer = None
        self.token = None
        self.connection_enabled = True
        self.last_auth_check = None
        self.auth_check_interval = 300  # Check every 5 minutes
        self.is_connected = False
        self.ping_task = None

    def _get_public_ssl_context(self):
        """Create SSL context for public APIs with system certificates"""
        ssl_context = ssl.create_default_context()

        # Try different system certificate locations
        cert_paths = [
            "/etc/ssl/certs/ca-certificates.crt",  # Debian/Ubuntu
            "/etc/pki/tls/certs/ca-bundle.crt",    # CentOS/RHEL
            "/etc/ssl/cert.pem",                   # macOS
        ]

        for cert_path in cert_paths:
            try:
                ssl_context.load_verify_locations(cert_path)
                return ssl_context
            except FileNotFoundError:
                continue

        # Fallback to certifi if available
        try:
            import certifi

            ssl_context.load_verify_locations(certifi.where())
            return ssl_context
        except ImportError:
            pass

        # Last resort: use default context
        return ssl.create_default_context()

    async def get_active_token(self) -> Optional[str]:
        """Get the active token from database, return None if no valid token exists"""
        try:
            async for db in get_db():
                stmt = (
                    select(TwitchToken)
                    .where(
                        TwitchToken.is_active,
                        TwitchToken.expires_at > datetime.now(),
                    )
                    .order_by(TwitchToken.created_at.desc())
                )

                result = await db.execute(stmt)
                token_record = result.scalars().first()

                if token_record:
                    logger.info("[TwitchIRC] Using database user access token")
                    return token_record.access_token
                else:
                    # Check if we have any tokens at all (active but expired)
                    expired_stmt = (
                        select(TwitchToken)
                        .where(TwitchToken.is_active)
                        .order_by(TwitchToken.created_at.desc())
                    )
                    expired_result = await db.execute(expired_stmt)
                    expired_token = expired_result.scalars().first()

                    if expired_token:
                        logger.warning(
                            "[TwitchIRC] Token has expired, attempting refresh..."
                        )
                        return None
                    else:
                        logger.info(
                            "[TwitchIRC] No Twitch tokens found - user needs to authenticate"
                        )
                        self.connection_enabled = False
                        return None

        except Exception as e:
            logger.error(f"[TwitchIRC] Error fetching token from database: {e}")
            return None

    async def refresh_token_if_needed(self):
        """Check if token needs refresh and refresh if possible"""
        try:
            async for db in get_db():
                # Get the most recent active token
                stmt = (
                    select(TwitchToken)
                    .where(TwitchToken.is_active)
                    .order_by(TwitchToken.created_at.desc())
                )
                result = await db.execute(stmt)
                token_record = result.scalars().first()

                if not token_record:
                    logger.warning("[TwitchIRC] No valid token found in database")
                    return

                # Check if token needs refresh (expires within 5 minutes)
                current_time = datetime.now()
                if token_record.expires_at <= current_time + timedelta(minutes=5):
                    logger.info("[TwitchIRC] Token expires soon, attempting refresh...")

                    if token_record.refresh_token:
                        new_token_data = await self._refresh_access_token(
                            token_record.refresh_token
                        )

                        if new_token_data:
                            # Update the existing token record
                            new_expires_at = current_time + timedelta(
                                seconds=new_token_data.get("expires_in", 3600)
                            )

                            stmt = (
                                update(TwitchToken)
                                .where(TwitchToken.id == token_record.id)
                                .values(
                                    access_token=new_token_data.get("access_token"),
                                    refresh_token=new_token_data.get(
                                        "refresh_token", token_record.refresh_token
                                    ),
                                    expires_at=new_expires_at,
                                )
                            )
                            await db.execute(stmt)
                            await db.commit()
                            logger.info("[TwitchIRC] Token successfully refreshed")
                        else:
                            logger.error("[TwitchIRC] Failed to refresh token")
                    else:
                        logger.warning("[TwitchIRC] No refresh token available")

        except Exception as e:
            logger.error(f"[TwitchIRC] Error during token refresh: {e}")

    async def _refresh_access_token(
        self, refresh_token: str
    ) -> Optional[Dict[str, Any]]:
        """Refresh the access token using the refresh token"""
        try:
            # Use system SSL context for Twitch API
            ssl_context = self._get_public_ssl_context()

            async with httpx.AsyncClient(verify=ssl_context) as client:
                response = await client.post(
                    "https://id.twitch.tv/oauth2/token",
                    data={
                        "client_id": self.settings.twitch_client_id,
                        "client_secret": self.settings.twitch_client_secret,
                        "grant_type": "refresh_token",
                        "refresh_token": refresh_token,
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )

                if response.status_code == 200:
                    return response.json()
                else:
                    logger.error(
                        f"[TwitchIRC] Token refresh failed: {response.status_code} - {response.text}"
                    )
                    return None

        except Exception as e:
            logger.error(f"[TwitchIRC] Exception during token refresh: {e}")
            return None

    async def connect(self):
        """Connect to Twitch IRC with database token"""
        consecutive_failures = 0
        max_failures = 3

        while self.connection_enabled:
            try:
                # Only check auth status periodically
                current_time = datetime.now()
                if (
                    self.last_auth_check is None
                    or (current_time - self.last_auth_check).seconds
                    > self.auth_check_interval
                ):
                    await self.refresh_token_if_needed()
                    self.last_auth_check = current_time

                # Get fresh token from database
                self.token = await self.get_active_token()

                if not self.token:
                    consecutive_failures += 1
                    if consecutive_failures >= max_failures:
                        logger.warning(
                            "[TwitchIRC] No valid token available after multiple attempts. "
                            "Disabling connection until user re-authenticates. "
                            "Please visit /auth/twitch/login to reconnect."
                        )
                        self.connection_enabled = False
                        # Notify via chat manager that Twitch is disconnected
                        await chat_manager.broadcast(
                            "SYSTEM: Twitch chat disconnected - authentication required"
                        )
                        break

                    logger.info(
                        f"[TwitchIRC] No token available, waiting 60 seconds... (attempt {consecutive_failures}/{max_failures})"
                    )
                    await asyncio.sleep(60)
                    continue

                # Reset failure counter on successful token retrieval
                consecutive_failures = 0

                # Use system SSL context for IRC connection too
                ssl_context = self._get_public_ssl_context()

                # Open a secure TLS connection with proper SSL context
                self.reader, self.writer = await asyncio.open_connection(
                    self.server, self.port, ssl=ssl_context
                )

                # Send PASS, NICK, JOIN
                self.writer.write(f"PASS oauth:{self.token}\r\n".encode())
                self.writer.write(f"NICK {self.nickname}\r\n".encode())
                self.writer.write(f"JOIN {self.channel}\r\n".encode())
                await self.writer.drain()

                logger.info("[TwitchIRC] Connected, listening for messages…")
                await chat_manager.broadcast("SYSTEM: Twitch chat connected")
                await self.listen()

            except Exception as e:
                consecutive_failures += 1
                logger.info(
                    f"[TwitchIRC] Connection error: {e!r} (attempt {consecutive_failures}/{max_failures})"
                )

                if consecutive_failures >= max_failures:
                    logger.warning(
                        "[TwitchIRC] Too many connection failures, disabling automatic reconnection"
                    )
                    self.connection_enabled = False
                    await chat_manager.broadcast(
                        "SYSTEM: Twitch chat connection failed - please check authentication"
                    )
                    break

                # Exponential backoff
                backoff_time = min(60, 5 * (2 ** (consecutive_failures - 1)))
                await asyncio.sleep(backoff_time)

        logger.info("[TwitchIRC] Connection loop stopped")

    def enable_connection(self):
        """Re-enable connection attempts (call this after successful auth)"""
        self.connection_enabled = True
        logger.info("[TwitchIRC] Connection re-enabled")

    # async def start_token_refresh_scheduler(self):
    #     """Start a background task to periodically check and refresh tokens"""
    #     while True:
    #         try:
    #             if self.connection_enabled:
    #                 await self.refresh_token_if_needed()
    #             # Check every 30 minutes
    #             await asyncio.sleep(1800)
    #         except Exception as e:
    #             logger.error(f"[TwitchIRC] Token refresh scheduler error: {e}")
    #             await asyncio.sleep(300)  # Wait 5 minutes on error

    async def listen(self):
        """Listen for IRC messages"""
        try:
            while True:
                data = await self.reader.readline()
                if not data:
                    break

                message = data.decode("utf-8").strip()
                logger.info(f"[TwitchIRC] Received: {message}")

                # Handle PING
                if message.startswith("PING"):
                    pong_response = message.replace("PING", "PONG")
                    self.writer.write(f"{pong_response}\r\n".encode())
                    await self.writer.drain()

                # Handle chat messages and broadcast them
                if "PRIVMSG" in message:
                    await chat_manager.broadcast(f"TWITCH: {message}")

        except Exception as e:
            logger.error(f"[TwitchIRC] Listen error: {e}")
        finally:
            if self.writer:
                self.writer.close()
                await self.writer.wait_closed()

    async def send_message(self, message: str):
        """Send a message to the Twitch channel"""
        if self.writer:
            self.writer.write(f"PRIVMSG {self.channel} :{message}\r\n".encode())
            await self.writer.drain()

    async def connect_for_meeting(self) -> bool:
        """Connect to Twitch IRC specifically for a meeting"""
        try:
            token = await self.get_active_token()
            if not token:
                logger.warning("[TwitchIRC] No valid token for meeting connection")
                return False

            # Create SSL context for connection
            ssl_context = self._get_public_ssl_context()

            # Connect to Twitch IRC
            self.reader, self.writer = await asyncio.open_connection(
                self.server, self.port, ssl=ssl_context
            )

            # Authenticate
            self.writer.write(f"PASS oauth:{token}\r\n".encode())
            self.writer.write(f"NICK {self.nickname}\r\n".encode())
            self.writer.write(f"JOIN {self.channel}\r\n".encode())
            await self.writer.drain()

            self.is_connected = True

            # Start ping handler and message listener
            self.ping_task = asyncio.create_task(self._handle_connection())

            logger.info("[TwitchIRC] Connected for meeting")
            return True

        except Exception as e:
            logger.error(f"[TwitchIRC] Failed to connect for meeting: {e}")
            return False

    async def disconnect_from_meeting(self):
        """Disconnect from Twitch IRC when meeting ends"""
        try:
            self.is_connected = False

            if self.ping_task:
                self.ping_task.cancel()
                try:
                    await self.ping_task
                except asyncio.CancelledError:
                    pass

            if self.writer:
                self.writer.write(f"PART {self.channel}\r\n".encode())
                await self.writer.drain()
                self.writer.close()
                await self.writer.wait_closed()

            self.reader = None
            self.writer = None

            logger.info("[TwitchIRC] Disconnected from meeting")

        except Exception as e:
            logger.error(f"[TwitchIRC] Error during meeting disconnect: {e}")

    async def _handle_connection(self):
        """Handle IRC connection (PING/PONG and messages)"""
        try:
            while self.is_connected and self.reader:
                try:
                    # Set a timeout for reading
                    data = await asyncio.wait_for(self.reader.readline(), timeout=30.0)
                    if not data:
                        break

                    message = data.decode('utf-8').strip()

                    # Handle PING (respond immediately)
                    if message.startswith("PING"):
                        pong_response = message.replace("PING", "PONG")
                        self.writer.write(f"{pong_response}\r\n".encode())
                        await self.writer.drain()
                        # Don't log PINGs - they're just keepalives
                        continue

                    # Log other messages
                    if message:
                        logger.info(f"[TwitchIRC] {message}")

                        # Handle chat messages
                        if "PRIVMSG" in message:
                            await chat_manager.broadcast(f"TWITCH: {message}")

                except asyncio.TimeoutError:
                    # Send keepalive if no data received
                    if self.writer and self.is_connected:
                        self.writer.write("PING :keepalive\r\n".encode())
                        await self.writer.drain()
                    continue

        except Exception as e:
            logger.error(f"[TwitchIRC] Connection handler error: {e}")
        finally:
            self.is_connected = False
