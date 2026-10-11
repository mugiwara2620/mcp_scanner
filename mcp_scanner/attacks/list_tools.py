"""Loads every test MCP server in this directory and lists its tools.

Each server module exposes a module-level `mcp` FastMCP instance (no
`get_tools()` helper exists elsewhere in this repo, so this follows
FastMCP's own convention and calls its native `list_tools()`).

Usage:
    python attacks/list_tools.py

For each server, prints the tool name and repr(description) -- repr() is
used so any non-printable character would show up as an escape sequence
instead of disappearing, in case a future fixture encodes something
invisible in its description.
"""

import asyncio
import importlib.util
import sys
from pathlib import Path

ATTACKS_DIR = Path(__file__).resolve().parent
EXCLUDE = {Path(__file__).name}  # don't try to load this script itself


def discover_server_files() -> list[Path]:
    files = sorted(ATTACKS_DIR.glob("evil_*.py")) + sorted(ATTACKS_DIR.glob("safe_*.py"))
    return [f for f in files if f.name not in EXCLUDE]


def load_module(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not create import spec for {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def get_fastmcp_instance(module):
    # Follow the convention used in this directory: a module-level `mcp`
    # object. Fall back to scanning for any FastMCP instance if the name
    # ever differs, so this script stays robust to minor refactors.
    if hasattr(module, "mcp"):
        return module.mcp
    from mcp.server.fastmcp import FastMCP

    for value in vars(module).values():
        if isinstance(value, FastMCP):
            return value
    raise AttributeError("No FastMCP instance found (expected a module-level 'mcp')")


def main() -> int:
    server_files = discover_server_files()
    if not server_files:
        print("No server files found in attacks/.")
        return 1

    exit_code = 0
    for path in server_files:
        print(f"=== {path.name} ===")
        try:
            module = load_module(path)
            server = get_fastmcp_instance(module)
            tools = asyncio.run(server.list_tools())
        except Exception as exc:  # noqa: BLE001 - report and keep going
            print(f"  ERROR loading {path.name}: {exc!r}")
            exit_code = 1
            continue

        if not tools:
            print("  (no tools registered)")
        for tool in tools:
            print(f"  name={tool.name!r}")
            print(f"  description={tool.description!r}")
        print()

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
