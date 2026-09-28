"""Read-only handshake/catalog check with the user's actual installed VT-MCP.

Does not query VT/Graph data, modify either installation, or stop a running tunnel.
It launches a separate stdio process for each installed executable for this check.
"""
import argparse
import asyncio
import json
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def check(mdti: str, vt: str) -> None:
    async with asyncio.timeout(45):
        async with stdio_client(StdioServerParameters(command=mdti)) as (mr, mw):
            async with stdio_client(StdioServerParameters(command=vt)) as (vr, vw):
                async with ClientSession(mr, mw) as ms, ClientSession(vr, vw) as vs:
                    await asyncio.gather(ms.initialize(), vs.initialize())
                    mtools, vtools = await asyncio.gather(ms.list_tools(), vs.list_tools())
                    mn, vn = {t.name for t in mtools.tools}, {t.name for t in vtools.tools}
                    if not mn or not vn or mn & vn or not all(n.startswith("mdti_") for n in mn):
                        raise RuntimeError("catalog conflict")
                    capabilities = await ms.call_tool("mdti_capabilities", {})
                    if capabilities.isError:
                        raise RuntimeError("MDTI capability call failed")
                    print(json.dumps({"CONCURRENT_STDIO_CATALOG": "PASS", "MDTI_TOOLS": len(mn),
                                      "VT_TOOLS": len(vn), "NAME_COLLISIONS": [],
                                      "LIVE_GRAPH_READ": "NOT_TESTED", "CHATGPT_TUNNELS": "NOT_TESTED"}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mdti-executable", required=True)
    parser.add_argument("--vt-executable", required=True)
    args = parser.parse_args()
    for name in (args.mdti_executable, args.vt_executable):
        if not Path(name).is_absolute() or not Path(name).is_file():
            parser.error("Both paths must be existing absolute executable paths")
    try:
        asyncio.run(check(args.mdti_executable, args.vt_executable))
    except Exception:
        print("CONCURRENT_STDIO_CATALOG=FAIL; check installations and startup configuration")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
