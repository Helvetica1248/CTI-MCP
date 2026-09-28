"""Real SDK tests. Skipped only when SDK unavailable; CI requires the SDK."""
import asyncio
import os
import sys

import pytest

pytest.importorskip("mcp")
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mdti_mcp.server import TOOLS, build_server


def test_tool_catalog():
    async def check():
        tools = await build_server().list_tools()
        assert {t.name for t in tools} == TOOLS
        for t in tools:
            assert t.name.startswith("mdti_") and t.outputSchema
            assert t.annotations.readOnlyHint is True
            assert t.annotations.destructiveHint is False
        assert not any(x in t.name.lower() for t in tools for x in ["hunt", "logs", "incident", "kql", "article"])
    asyncio.run(check())


def test_two_real_stdio_processes_are_independent(tmp_path):
    async def check():
        env = dict(os.environ, MDTI_CONFIG=str(tmp_path / "missing.json"))
        p = StdioServerParameters(command=sys.executable, args=["-m", "mdti_mcp.cli"], env=env)
        async with asyncio.timeout(30):
            async with stdio_client(p) as (r1, w1), stdio_client(p) as (r2, w2):
                async with ClientSession(r1, w1) as a, ClientSession(r2, w2) as b:
                    await asyncio.gather(a.initialize(), b.initialize())
                    a_result, b_result = await asyncio.gather(
                        a.call_tool("mdti_capabilities", {}), b.call_tool("mdti_capabilities", {}))
                    assert not a_result.isError and not b_result.isError
                    assert a_result.structuredContent["data"]["telemetry_access"] is False
                    assert b_result.structuredContent["data"]["credential_service"] == "mdti-mcp"
                    # One server rejects a URL without interfering with the other server.
                    bad = await a.call_tool("mdti_resolutions", {"host": "https://google.com"})
                    assert bad.structuredContent["status"] == "unsupported_input"
                    assert not (await b.call_tool("mdti_capabilities", {})).isError
    asyncio.run(check())
