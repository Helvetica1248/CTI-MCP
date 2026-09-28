import asyncio
import json
from dataclasses import replace
from unittest.mock import patch

import httpx
import pytest

from mdti_mcp.core import (CursorStore, DATA_BUDGET, Failure, GRAPH, GraphReader,
                           IntelligenceService, Settings, normalize_host)

SETTINGS = Settings(tenant_id="11111111-1111-4111-8111-111111111111",
                    client_id="22222222-2222-4222-8222-222222222222", allow_ai_output=True)


class Tokens:
    def __init__(self):
        self.refreshes = []
    async def token(self, refresh=False):
        self.refreshes.append(refresh)
        return "synthetic-test-token"


def run(handler, operation="host", settings=SETTINGS, **kwargs):
    async def check():
        tokens = Tokens()
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        s = IntelligenceService(settings, GraphReader(settings, tokens, client))
        try:
            return await s.execute(operation, **kwargs), tokens
        finally:
            await s.close()
    return asyncio.run(check())


@pytest.mark.parametrize("original,expected,is_ip", [
    ("GOOGLE.COM", "google.com", False), ("google.com.", "google.com", False),
    ("8.8.8.8", "8.8.8.8", True), ("2001:4860:4860::8888", "2001:4860:4860::8888", True),
    ("例え.jp", "xn--r8jz45g.jp", False),
])
def test_host_normalization(original, expected, is_ip):
    assert normalize_host(original) == (expected, is_ip)


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "10.1.2.3", "169.254.169.254",
                                  "::1", "https://google.com/a", "google.com:443", "*.google.com",
                                  "01.02.03.04", "host.local", "a/b.com", "google.com%2f", "", " google.com"])
def test_unsafe_or_wrong_host_never_queries(host):
    def handler(request):
        pytest.fail("Invalid host must not call Graph")
    r, _ = run(handler, host=host)
    assert r.status == "unsupported_input"


@pytest.mark.parametrize("host,expected", [("google.com", "passiveDns"), ("8.8.8.8", "passiveDnsReverse")])
def test_resolution_direction_and_observation_fields(host, expected):
    record = {"id": "record", "firstSeenDateTime": "2024-01-01T00:00:00Z",
              "lastSeenDateTime": "2024-02-01T00:00:00Z", "collectedDateTime": "2024-02-02T00:00:00Z",
              "recordType": "A", "parentHost": {"id": "example.com"}, "artifact": {"id": "8.8.8.8"}}
    def handler(request):
        assert request.method == "GET"
        assert request.url.host == "graph.microsoft.com"
        assert request.url.path.endswith("/" + expected)
        assert request.url.params["$top"] == "50"
        return httpx.Response(200, json={"value": [record]})
    r, _ = run(handler, "resolutions", host=host)
    assert r.status == "ok" and r.data == [record]
    assert not r.has_more
    assert r.retrieved_at != record["lastSeenDateTime"]


def test_certificate_relationship_id_is_not_certificate_id():
    row = {"id": "relationship-id", "firstSeenDateTime": "2024-01-01T00:00:00Z",
           "ports": [{"port": 443}], "sslCertificate": {"id": "Y2VydA==", "sha1": "a" * 40}}
    def handler(request):
        assert request.url.path.endswith("/hosts/example.com/sslCertificates")
        return httpx.Response(200, json={"value": [row]})
    r, _ = run(handler, "certificates", host="example.com")
    assert r.data[0]["id"] != r.data[0]["sslCertificate"]["id"]
    assert r.data[0] == row


@pytest.mark.parametrize("operation,suffix,payload", [
    ("certificate", "", {"subject": {"commonName": "example.com"}, "issuer": {"commonName": "Example CA"}}),
    ("certificate_hosts", "/relatedHosts", {"value": [{"id": "example.com"}]}),
])
def test_certificate_read_routes(operation, suffix, payload):
    def handler(request):
        assert request.url.raw_path.split(b"?")[0].endswith(("/sslCertificates/Y2VydA%3D%3D" + suffix).encode())
        return httpx.Response(200, json=payload)
    r, _ = run(handler, operation, certificate_id="Y2VydA==")
    assert r.status == "ok"


@pytest.mark.parametrize("code,status", [(400, "upstream_error"), (401, "unauthorized"), (403, "forbidden"),
                                       (404, "not_found"), (407, "proxy_error"), (429, "rate_limited"), (503, "upstream_error")])
def test_errors_sanitized(code, status):
    def handler(request):
        return httpx.Response(code, json={"error": {"message": "private-sensitive-value"}}, headers={"Retry-After": "60"})
    r, tokens = run(handler, host="example.com")
    assert r.status == status
    assert "private-sensitive-value" not in r.model_dump_json()
    assert "synthetic-test-token" not in r.model_dump_json()
    if code == 401:
        assert tokens.refreshes == [False, True]


def test_401_refresh_then_success():
    n = 0
    def handler(request):
        nonlocal n
        n += 1
        return httpx.Response(401 if n == 1 else 200, json={"id": "example.com"})
    r, tokens = run(handler, host="example.com")
    assert r.status == "ok" and tokens.refreshes == [False, True]


def test_empty_is_not_benign():
    r, _ = run(lambda _: httpx.Response(200, json={"value": []}), "resolutions", host="example.com")
    assert r.status == "not_found" and r.data == []
    assert "benign" not in r.model_dump_json()


@pytest.mark.parametrize("exception,status", [(httpx.ReadTimeout("private-sensitive-value"), "timeout"),
                                            (httpx.ConnectError("private-sensitive-value"), "upstream_error"),
                                            (httpx.ProxyError("private-sensitive-value"), "proxy_error")])
def test_transport_error(exception, status):
    def handler(_):
        raise exception
    r, _ = run(handler, host="example.com")
    assert r.status == status and "private-sensitive-value" not in r.model_dump_json()


@pytest.mark.parametrize("settings,status", [(Settings(), "not_configured"),
                                           (replace(SETTINGS, allow_ai_output=False), "policy_blocked")])
def test_no_network_without_configuration_and_policy(settings, status):
    r, tokens = run(lambda _: pytest.fail("must not query"), settings=settings, host="example.com")
    assert r.status == status and tokens.refreshes == []


def test_cursor_bound_to_path_and_limit_without_item_loss():
    async def check():
        calls = []
        def handler(request):
            calls.append(str(request.url))
            if "$skip=3" in str(request.url):
                return httpx.Response(200, json={"value": [{"id": 4}]})
            return httpx.Response(200, json={"value": [{"id": i} for i in (1, 2, 3)],
                                  "@odata.nextLink": GRAPH + "/hosts/example.com/passiveDns?$skip=3"})
        s = IntelligenceService(SETTINGS, GraphReader(SETTINGS, Tokens(), httpx.AsyncClient(transport=httpx.MockTransport(handler))))
        try:
            one = await s.execute("resolutions", host="example.com", limit=2)
            assert [r["id"] for r in one.data] == [1, 2]
            assert one.has_more and one.truncated and "skip" not in one.next_cursor
            wrong = await s.execute("resolutions", host="other.com", limit=2, cursor=one.next_cursor)
            assert wrong.error_code == "CURSOR_EXPIRED_OR_MISMATCHED"
            two = await s.execute("resolutions", host="example.com", limit=2, cursor=one.next_cursor)
            assert two.data == [{"id": 3}] and len(calls) == 1
            three = await s.execute("resolutions", host="example.com", limit=2, cursor=two.next_cursor)
            assert three.data == [{"id": 4}] and not three.has_more and len(calls) == 2
        finally:
            await s.close()
    asyncio.run(check())


@pytest.mark.parametrize("url", ["https://attacker.example/collect", "https://graph.microsoft.com/v1.0/auditLogs/signIns",
                                 "https://graph.microsoft.com@attacker.example/", "http://graph.microsoft.com/v1.0/security/threatIntelligence/hosts/example.com/passiveDns"])
def test_continuation_cannot_access_other_origins_or_tenant_logs(url):
    r, _ = run(lambda _: httpx.Response(200, json={"value": [], "@odata.nextLink": url}),
               "resolutions", host="example.com")
    assert r.error_code == "UNSAFE_CONTINUATION_URL"


def test_no_redirect_following():
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(302, headers={"Location": "https://attacker.example/"})
    r, _ = run(handler, host="example.com")
    assert r.status == "upstream_error" and len(calls) == 1


def test_size_limit_and_no_silent_record_loss():
    record = {"id": "x", "text": "a" * (DATA_BUDGET // 2 + 10)}
    r, _ = run(lambda _: httpx.Response(200, json={"value": [record, record]}), "certificates", host="example.com")
    assert r.truncated and r.next_cursor and len(r.data) == 1
    assert len(r.model_dump_json().encode()) < 256 * 1024


def test_cursor_ttl_and_capacity():
    store = CursorStore()
    with patch("mdti_mcp.core.time.monotonic", return_value=0):
        first = store.put("binding", [], "url")
    with patch("mdti_mcp.core.time.monotonic", return_value=601):
        with pytest.raises(Failure):
            store.read(first, "binding")
        for _ in range(80):
            store.put("binding", [], "url")
        assert len(store.entries) == 64


def test_config_separate_and_no_environment_changes(tmp_path, monkeypatch):
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"tenant_id": SETTINGS.tenant_id, "client_id": SETTINGS.client_id, "allow_ai_output": True}))
    monkeypatch.setenv("MDTI_CONFIG", str(cfg))
    monkeypatch.setenv("VT_API_KEY", "untouched-vt-value")
    from mdti_mcp.core import SERVICE_NAME
    s = Settings.load()
    assert s.tenant_id == SETTINGS.tenant_id
    assert SERVICE_NAME == "mdti-mcp"
    import os
    assert os.environ["VT_API_KEY"] == "untouched-vt-value"


def test_invalid_config_is_not_exposed(tmp_path, monkeypatch):
    cfg = tmp_path / "config.json"
    cfg.write_text('{"client_secret":"private-sensitive-value"}')
    monkeypatch.setenv("MDTI_CONFIG", str(cfg))
    with pytest.raises(Failure) as e:
        Settings.load()
    assert str(e.value) == "INVALID_MDTI_CONFIG"


def test_msal_http_rejects_nonidentity_origin():
    from mdti_mcp.auth import IdentityHttp
    h = IdentityHttp(SETTINGS)
    try:
        with pytest.raises(Failure):
            h.get("https://attacker.example/token")
    finally:
        h.client.close()
