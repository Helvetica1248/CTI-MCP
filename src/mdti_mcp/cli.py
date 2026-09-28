"""Setup/diagnostics are explicit; normal stdio startup is silent."""
from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import logging
import os
import sys
from uuid import UUID

from .auth import MsalTokens, vault
from .core import Failure, GraphReader, IntelligenceService, SERVICE_NAME, Settings, default_config_path


def configure() -> int:
    tenant = str(UUID(input("Entra tenant ID: ").strip()))
    client = str(UUID(input("Application client ID: ").strip()))
    secret = getpass.getpass("Client secret VALUE (not secret ID): ")
    if not secret:
        raise Failure("not_configured", "EMPTY_CLIENT_SECRET")
    allow = input("External TI may be returned to your AI client under your policy? [y/N]: ").lower() == "y"
    store = vault()  # Refuse plaintext fallback on unsupported platforms.
    store.set_password(SERVICE_NAME, tenant + ":" + client, secret)
    path = default_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"tenant_id": tenant, "client_id": client, "allow_ai_output": allow}
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    temp.replace(path)
    print("MDTI_CONFIGURED=YES; credentials stored under mdti-mcp only")
    print("ENTITLEMENT=NOT_TESTED")
    return 0


async def doctor(live: bool, host: str | None) -> int:
    settings = Settings.load()
    tokens = MsalTokens(settings)
    service = IntelligenceService(settings, GraphReader(settings, tokens))
    try:
        if not live:
            print(service.capabilities().model_dump_json())
            print("LIVE_API=NOT_TESTED")
            return 0
        if not host:
            raise Failure("unsupported_input", "LIVE_DOCTOR_REQUIRES_HOST")
        states = {}
        for operation in ("host", "resolutions", "certificates"):
            result = await service.execute(operation, host=host, limit=1)
            states[operation] = {"status": result.status, "error_code": result.error_code}
        # No raw TI or credentials in diagnostic output.
        print(json.dumps({"live_checks": states, "ui_parity": "NOT_TESTED", "tenant_logs_accessed": False}))
        return 0 if all(v["status"] == "ok" for v in states.values()) else 1
    finally:
        await service.close()
        tokens.close()


def main() -> int:
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
    for logger in ("httpx", "httpcore", "msal"):
        logging.getLogger(logger).setLevel(logging.CRITICAL)
    parser = argparse.ArgumentParser(description="Microsoft external host intelligence MCP")
    parser.add_argument("mode", choices=["serve", "configure", "doctor", "audit-tools"], nargs="?", default="serve")
    parser.add_argument("--live", action="store_true", help="Explicitly enable a small Graph read smoke")
    parser.add_argument("--host", help="FQDN or public IP to query for live doctor")
    args = parser.parse_args()
    try:
        if args.mode == "configure":
            return configure()
        if args.mode == "doctor":
            return asyncio.run(doctor(args.live, args.host))
        from .server import TOOLS, build_server
        server = build_server()
        if args.mode == "audit-tools":
            tools = asyncio.run(server.list_tools())
            if {t.name for t in tools} != TOOLS or any(not t.outputSchema for t in tools):
                raise Failure("upstream_error", "TOOL_SCHEMA_AUDIT_FAILED")
            print(json.dumps({"server": "MDTI-MCP", "tools": [t.name for t in tools],
                              "tenant_log_tools": [], "write_tools": []}))
            return 0
        server.run(transport="stdio")
        return 0
    except Failure as error:
        print(json.dumps({"status": error.status, "error_code": error.code}), file=sys.stderr)
        return 1
    except (ValueError, OSError, ImportError):
        print("MDTI_SETUP_OR_DEPENDENCY_ERROR", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
