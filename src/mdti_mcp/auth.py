"""Reuse Microsoft MSAL; credentials never cross the tool boundary."""
from __future__ import annotations

import asyncio
import os
from urllib.parse import urlsplit

import httpx

from .core import Failure, SERVICE_NAME, Settings


def vault():
    if os.name != "nt":
        raise Failure("not_configured", "WINDOWS_VAULT_REQUIRED_OR_USE_MDTI_CLIENT_SECRET")
    from keyring.backends.Windows import WinVaultKeyring
    return WinVaultKeyring()


def secret_for(settings: Settings) -> str:
    secret = os.environ.get("MDTI_CLIENT_SECRET")
    if not secret:
        try:
            secret = vault().get_password(SERVICE_NAME, settings.tenant_id + ":" + settings.client_id)
        except Failure:
            raise
        except Exception:
            raise Failure("not_configured", "CREDENTIAL_STORE_UNAVAILABLE") from None
    if not secret:
        raise Failure("not_configured", "MDTI_CLIENT_SECRET_MISSING")
    return secret


class IdentityHttp:
    """MSAL's documented HTTP-client interface, using the same proxy/CA settings."""
    def __init__(self, settings: Settings):
        self.tenant = settings.tenant_id
        self.client = httpx.Client(verify=settings.tls_context(), proxy=settings.proxy,
                                   trust_env=False, follow_redirects=False,
                                   timeout=httpx.Timeout(15, connect=5))

    def _check(self, url: str) -> None:
        u = urlsplit(url)
        if (u.scheme != "https" or u.netloc != "login.microsoftonline.com" or u.fragment
                or not u.path.lower().startswith("/" + self.tenant.lower() + "/")):
            raise Failure("unauthorized", "IDENTITY_ENDPOINT_NOT_ALLOWED")

    def get(self, url, **kwargs):
        self._check(url)
        response = self.client.get(url, **kwargs)
        if response.status_code >= 300:
            raise Failure("unauthorized", "IDENTITY_DISCOVERY_FAILED", response.status_code)
        return response

    def post(self, url, **kwargs):
        self._check(url)
        return self.client.post(url, **kwargs)


class MsalTokens:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._app = None
        self._http = None
        self._lock = asyncio.Lock()

    def _token_sync(self, refresh: bool) -> str:
        from msal import ConfidentialClientApplication
        if self._app is None:
            self._http = IdentityHttp(self.settings)
            self._app = ConfidentialClientApplication(
                self.settings.client_id,
                authority="https://login.microsoftonline.com/" + self.settings.tenant_id,
                client_credential=secret_for(self.settings),
                http_client=self._http,
                instance_discovery=False,
                enable_pii_log=False,
            )
        if refresh:
            self._app.remove_tokens_for_client()
        result = self._app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
        token = result.get("access_token")
        if not isinstance(token, str) or not token:
            raise Failure("unauthorized", "ENTRA_TOKEN_FAILED")
        return token

    async def token(self, refresh: bool = False) -> str:
        self.settings.check()
        async with self._lock:
            try:
                return await asyncio.to_thread(self._token_sync, refresh)
            except Failure:
                raise
            except httpx.ProxyError:
                raise Failure("proxy_error", "IDENTITY_PROXY_FAILED") from None
            except httpx.TimeoutException:
                raise Failure("timeout", "IDENTITY_TIMEOUT") from None
            except httpx.TransportError:
                raise Failure("unauthorized", "IDENTITY_TLS_OR_CONNECTION_FAILED") from None
            except Exception:
                raise Failure("unauthorized", "ENTRA_TOKEN_FAILED") from None

    def close(self) -> None:
        if self._http:
            self._http.client.close()
