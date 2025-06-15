import httpx
import ssl
from app.config.settings import get_settings
from urllib.parse import urlencode
import secrets

settings = get_settings()


class TwitchAuth:
    def __init__(self):
        self.client_id = settings.twitch_client_id
        self.client_secret = settings.twitch_client_secret
        self.redirect_uri = settings.twitch_redirect_uri

    def get_authorization_url(self) -> str:
        """Generate the URL for user authorization"""
        state = secrets.token_urlsafe(32)  # Store this securely
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": "chat:read chat:edit",
            "state": state,
        }
        return f"https://id.twitch.tv/oauth2/authorize?{urlencode(params)}"

    def _get_public_ssl_context(self):
        """Create SSL context for public APIs (like Twitch) with system certificates"""
        ssl_context = ssl.create_default_context()

        # Try different system certificate locations
        cert_paths = [
            "/etc/ssl/certs/ca-certificates.crt",  # Debian/Ubuntu
            "/etc/pki/tls/certs/ca-bundle.crt",  # CentOS/RHEL
            "/etc/ssl/cert.pem",  # macOS
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

        # Last resort: use default context (might fail)
        return ssl.create_default_context()

    async def exchange_code_for_token(self, code: str) -> dict:
        """Exchange authorization code for access token"""
        # Use system certificates specifically for Twitch API
        ssl_context = self._get_public_ssl_context()

        async with httpx.AsyncClient(verify=ssl_context) as client:
            response = await client.post(
                "https://id.twitch.tv/oauth2/token",
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": self.redirect_uri,
                },
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "SpoutBreeze/1.0",
                },
            )
            response.raise_for_status()
            return response.json()
