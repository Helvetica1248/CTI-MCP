"""Bounded, read-only Graph client. No DNS/TLS connection to the investigated host."""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import secrets
import ssl
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Literal, Protocol
from urllib.parse import quote, urlsplit
from uuid import UUID

import httpx
import idna
from pydantic import BaseModel, Field

GRAPH = "https://graph.microsoft.com/v1.0/security/threatIntelligence"
SERVICE_NAME = "mdti-mcp"
MAX_HTTP_BYTES = 2 * 1024 * 1024
MAX_RESULT_BYTES = 256 * 1024
DATA_BUDGET = 220 * 1024


class Failure(Exception):
    """Only constant, sanitized error codes cross the MCP boundary."""
    def __init__(self, status: str, code: str, http_status: int | None = None,
                 retry_after: int | None = None):
        super().__init__(code)
        self.status, self.code = status, code
        self.http_status, self.retry_after = http_status, retry_after


class Result(BaseModel):
    schema_version: str = "1"
    source: str = "microsoft_graph_threat_intelligence"
    operation: str
    status: str = "ok"
    retrieved_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    query: dict[str, Any] = Field(default_factory=dict)
    data: dict[str, Any] | list[Any] | None = None
    source_url: str | None = None
    next_cursor: str | None = None
    has_more: bool = False
    truncated: bool = False
    error_code: str | None = None
    http_status: int | None = None
    retry_after: int | None = None


def default_config_path() -> Path:
    # Absolute path: tunnel-client may start the process in a different cwd.
    explicit = os.environ.get("MDTI_CONFIG")
    if explicit:
        p = Path(explicit).expanduser()
        if not p.is_absolute():
            raise Failure("not_configured", "MDTI_CONFIG_MUST_BE_ABSOLUTE")
        return p
    root = Path(os.environ.get("LOCALAPPDATA", Path.home() / ".config"))
    return root / "MDTI-MCP" / "config.json"


@dataclass(frozen=True)
class Settings:
    tenant_id: str = ""
    client_id: str = ""
    allow_ai_output: bool = False
    proxy: str | None = field(default=None, repr=False)
    ca_bundle: str | None = None

    @classmethod
    def load(cls) -> Settings:
        path = default_config_path()
        try:
            values = json.loads(path.read_text("utf-8")) if path.exists() else {}
            if not isinstance(values, dict) or set(values) - {"tenant_id", "client_id", "allow_ai_output"}:
                raise ValueError
            for k in ("tenant_id", "client_id"):
                if values.get(k):
                    values[k] = str(UUID(values[k]))
            if type(values.get("allow_ai_output", False)) is not bool:
                raise ValueError
            proxy = os.environ.get("MDTI_PROXY_URL") or os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
            if proxy:
                u = urlsplit(proxy)
                if u.scheme not in {"http", "https"} or not u.hostname:
                    raise ValueError
            ca = os.environ.get("MDTI_CA_BUNDLE") or os.environ.get("REQUESTS_CA_BUNDLE")
            return cls(**values, proxy=proxy, ca_bundle=ca)
        except (ValueError, TypeError, OSError):
            raise Failure("not_configured", "INVALID_MDTI_CONFIG") from None

    def tls_context(self) -> ssl.SSLContext:
        context = ssl.create_default_context()
        if self.ca_bundle:
            try:
                context.load_verify_locations(cafile=self.ca_bundle)
            except (OSError, ssl.SSLError):
                raise Failure("not_configured", "INVALID_CA_BUNDLE") from None
        return context

    def check(self) -> None:
        if not self.tenant_id or not self.client_id:
            raise Failure("not_configured", "RUN_CONFIGURE_FIRST")
        if not self.allow_ai_output:
            raise Failure("policy_blocked", "AI_OUTPUT_NOT_APPROVED")


def normalize_host(value: str) -> tuple[str, bool]:
    if not isinstance(value, str) or not value or len(value) > 253 or value != value.strip():
        raise Failure("unsupported_input", "INVALID_HOST")
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        ip = None
    if ip is not None:
        if not ip.is_global or ip.is_multicast:
            raise Failure("unsupported_input", "NON_PUBLIC_IP")
        return ip.compressed, True
    # Reject URLs, netmasks, IDs, wildcards, local names, and ambiguous numeric IPs.
    if any(c in value for c in "/:@?#\\%*[]") or re.fullmatch(r"[\d.]+", value):
        raise Failure("unsupported_input", "FQDN_OR_PUBLIC_IP_REQUIRED")
    try:
        host = idna.encode(value.rstrip("."), uts46=True, std3_rules=True).decode("ascii").lower()
    except idna.IDNAError:
        raise Failure("unsupported_input", "INVALID_FQDN") from None
    if "." not in host or host.endswith((".local", ".localhost", ".internal", ".invalid")):
        raise Failure("unsupported_input", "PUBLIC_FQDN_REQUIRED")
    return host, False


def certificate_segment(value: str) -> str:
    # Graph's native ID is not the host/certificate relationship ID, nor raw SHA-1.
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_+/=-]{1,512}", value):
        raise Failure("unsupported_input", "INVALID_CERTIFICATE_ID")
    return quote(value, safe="")


def retry_delay(value: str | None) -> int:
    if value is None:
        return 1
    try:
        return min(86400, max(0, int(value)))
    except ValueError:
        try:
            d = parsedate_to_datetime(value)
            return min(86400, max(0, int((d - datetime.now(timezone.utc)).total_seconds()) + 1))
        except (ValueError, TypeError, OverflowError):
            return 1


class TokenProvider(Protocol):
    async def token(self, refresh: bool = False) -> str: ...


class GraphReader:
    def __init__(self, settings: Settings, tokens: TokenProvider,
                 client: httpx.AsyncClient | None = None):
        self.settings, self.tokens = settings, tokens
        self.client = client or httpx.AsyncClient(
            verify=settings.tls_context(), proxy=settings.proxy, trust_env=False,
            follow_redirects=False, timeout=httpx.Timeout(20, connect=5),
            limits=httpx.Limits(max_connections=4, max_keepalive_connections=4))

    @staticmethod
    def check_url(url: str, path: str) -> None:
        u, expected = urlsplit(url), urlsplit(GRAPH + path)
        if (u.scheme != "https" or u.netloc != "graph.microsoft.com" or u.fragment
                or u.path != expected.path or len(url) > 16384):
            raise Failure("upstream_error", "UNSAFE_CONTINUATION_URL")

    async def get(self, path: str, params: dict | None = None,
                  continuation: str | None = None) -> dict:
        # A second boundary; the service only constructs the following TI paths.
        if not re.fullmatch(r"/(hosts/[^/?]+(?:/(?:reputation|passiveDns|passiveDnsReverse|sslCertificates))?|sslCertificates/[^/?]+(?:/relatedHosts)?)", path):
            raise Failure("unsupported_input", "ENDPOINT_NOT_ALLOWED")
        url = continuation or GRAPH + path
        self.check_url(url, path)
        refresh, refreshed = False, False
        for attempt in range(4):
            token = await self.tokens.token(refresh)
            refresh = False
            try:
                async with self.client.stream(
                    "GET", url, params=None if continuation else params,
                    headers={"Authorization": "Bearer " + token, "Accept": "application/json"},
                ) as r:
                    status = r.status_code
                    if status == 401 and not refreshed:
                        refreshed, refresh = True, True
                        continue
                    if status == 429 or 500 <= status < 600:
                        delay = retry_delay(r.headers.get("Retry-After"))
                        if attempt < 2 and delay <= 2:
                            await asyncio.sleep(delay)
                            continue
                        raise Failure("rate_limited" if status == 429 else "upstream_error",
                                      "GRAPH_THROTTLED" if status == 429 else "GRAPH_UNAVAILABLE", status, delay)
                    if status != 200:
                        state = {401: "unauthorized", 403: "forbidden", 404: "not_found",
                                 407: "proxy_error"}.get(status, "upstream_error")
                        code = {401: "GRAPH_UNAUTHORIZED", 403: "CHECK_PERMISSION_AND_API_ENTITLEMENT",
                                404: "NO_RECORD_IN_GRAPH", 407: "PROXY_AUTH_REQUIRED"}.get(status, "GRAPH_HTTP_ERROR")
                        raise Failure(state, code, status)
                    data = bytearray()
                    async for chunk in r.aiter_bytes():
                        data.extend(chunk)
                        if len(data) > MAX_HTTP_BYTES:
                            raise Failure("upstream_error", "GRAPH_RESPONSE_TOO_LARGE", status)
                try:
                    payload = json.loads(data)
                    if not isinstance(payload, dict):
                        raise ValueError
                    return payload
                except (ValueError, UnicodeDecodeError):
                    raise Failure("upstream_error", "INVALID_GRAPH_JSON", 200) from None
            except httpx.ProxyError:
                raise Failure("proxy_error", "PROXY_CONNECTION_FAILED") from None
            except httpx.TimeoutException:
                raise Failure("timeout", "GRAPH_TIMEOUT") from None
            except httpx.TransportError:
                raise Failure("upstream_error", "GRAPH_TLS_OR_CONNECTION_FAILED") from None
        raise Failure("unauthorized", "GRAPH_UNAUTHORIZED", 401)

    async def close(self) -> None:
        await self.client.aclose()


@dataclass
class PageState:
    binding: str
    items: list[Any]
    next_url: str | None
    expires: float
    size: int


class CursorStore:
    """Opaque, process-local continuations; bounded by TTL/count/bytes."""
    def __init__(self):
        self.entries: OrderedDict[str, PageState] = OrderedDict()

    def _purge(self) -> None:
        for token in list(self.entries):
            if self.entries[token].expires <= time.monotonic():
                del self.entries[token]

    def read(self, token: str, binding: str) -> PageState:
        self._purge()
        state = self.entries.get(token)
        if not state or state.binding != binding:
            raise Failure("unsupported_input", "CURSOR_EXPIRED_OR_MISMATCHED")
        return state

    def put(self, binding: str, items: list, next_url: str | None) -> str:
        self._purge()
        size = len(json.dumps(items, ensure_ascii=True).encode()) + len(next_url or "")
        if size > 16 * 1024 * 1024:
            raise Failure("upstream_error", "CURSOR_BUFFER_TOO_LARGE")
        while self.entries and (len(self.entries) >= 64 or sum(s.size for s in self.entries.values()) + size > 16 * 1024 * 1024):
            self.entries.popitem(last=False)
        token = secrets.token_urlsafe(24)
        self.entries[token] = PageState(binding, items, next_url, time.monotonic() + 600, size)
        return token


class IntelligenceService:
    def __init__(self, settings: Settings, graph: GraphReader):
        self.settings, self.graph = settings, graph
        self.cursors = CursorStore()
        self.successful_operations: set[str] = set()
        self.slots = asyncio.Semaphore(4)

    def capabilities(self) -> Result:
        return Result(operation="capabilities", data={
            "implemented": ["host", "reputation", "resolutions", "certificates", "certificate", "certificate_hosts"],
            "configuration_present": bool(self.settings.tenant_id and self.settings.client_id),
            "allow_ai_output": self.settings.allow_ai_output,
            "verified_this_process": sorted(self.successful_operations),
            "permission": "ThreatIntelligence.Read.All", "telemetry_access": False,
            "active_host_probing": False, "persistent_intelligence_storage": False,
            "credential_service": SERVICE_NAME, "tool_prefix": "mdti_",
            "cursor_ttl_seconds": 600, "ui_parity_verified": False,
        })

    async def execute(self, operation: str, *, host: str | None = None,
                      certificate_id: str | None = None, direction: str = "auto",
                      limit: int = 50, cursor: str | None = None) -> Result:
        query: dict[str, Any] = {}
        path: str | None = None
        try:
            if type(limit) is not int or not 1 <= limit <= 200:
                raise Failure("unsupported_input", "LIMIT_MUST_BE_1_TO_200")
            collection = operation in {"resolutions", "certificates", "certificate_hosts"}
            if operation in {"host", "reputation", "resolutions", "certificates"}:
                normalized, is_ip = normalize_host(host)
                query = {"input": host, "host": normalized}
                path = "/hosts/" + quote(normalized, safe="")
                if operation == "resolutions":
                    if direction not in {"auto", "forward", "reverse"}:
                        raise Failure("unsupported_input", "INVALID_DIRECTION")
                    actual = ("reverse" if is_ip else "forward") if direction == "auto" else direction
                    query["direction"] = actual
                    path += "/passiveDnsReverse" if actual == "reverse" else "/passiveDns"
                elif operation == "certificates":
                    path += "/sslCertificates"
                elif operation == "reputation":
                    path += "/reputation"
            elif operation in {"certificate", "certificate_hosts"}:
                path = "/sslCertificates/" + certificate_segment(certificate_id)
                query = {"certificate_id": certificate_id}
                if collection:
                    path += "/relatedHosts"
            else:
                raise Failure("unsupported_input", "UNKNOWN_OPERATION")
            self.settings.check()
            binding = json.dumps([path, limit], separators=(",", ":"))
            async with asyncio.timeout(30):
                async with self.slots:
                    if collection:
                        data, nxt, clipped = await self._page(path, limit, cursor, binding)
                    else:
                        if cursor:
                            raise Failure("unsupported_input", "CURSOR_NOT_SUPPORTED")
                        data = await self.graph.get(path)
                        data.pop("@odata.context", None)
                        data.pop("@odata.nextLink", None)
                        nxt, clipped = None, False
                        if len(json.dumps(data).encode()) > DATA_BUDGET:
                            raise Failure("upstream_error", "SINGLE_RECORD_TOO_LARGE")
            self.successful_operations.add(operation)
            return Result(operation=operation, status="ok" if data or nxt else "not_found",
                          query=query, data=data, source_url=GRAPH + path,
                          next_cursor=nxt, has_more=nxt is not None, truncated=clipped)
        except TimeoutError:
            return Result(operation=operation, status="timeout", query=query, error_code="REQUEST_DEADLINE_EXCEEDED")
        except Failure as e:
            return Result(operation=operation, status=e.status, query=query,
                          source_url=GRAPH + path if path else None, error_code=e.code,
                          http_status=e.http_status, retry_after=e.retry_after)
        except Exception:
            # Do not return repr(exception): auth/proxy/URL text may contain secrets.
            return Result(operation=operation, status="upstream_error", error_code="INTERNAL_ERROR")

    async def _page(self, path: str, limit: int, cursor: str | None, binding: str) -> tuple:
        state = self.cursors.read(cursor, binding) if cursor else None
        if state and state.items:
            items, next_url = state.items, state.next_url
        else:
            payload = await self.graph.get(path, {"$top": limit}, state.next_url if state else None)
            items, next_url = payload.get("value"), payload.get("@odata.nextLink")
            if not isinstance(items, list) or (next_url is not None and not isinstance(next_url, str)):
                raise Failure("upstream_error", "INVALID_GRAPH_COLLECTION")
            if next_url:
                self.graph.check_url(next_url, path)
        selected, size = [], 2
        for item in items[:limit]:
            item_size = len(json.dumps(item, ensure_ascii=True).encode()) + 1
            if size + item_size > DATA_BUDGET:
                if not selected:
                    raise Failure("upstream_error", "SINGLE_RECORD_TOO_LARGE")
                break
            selected.append(item)
            size += item_size
        rest = items[len(selected):]
        token = self.cursors.put(binding, rest, next_url) if rest or next_url else None
        return selected, token, bool(rest)

    async def close(self) -> None:
        await self.graph.close()
