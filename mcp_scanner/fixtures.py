"""
fixtures.py — load the demo's tool catalogue (name + description + context).

Two sources, merged into one list the demo can scan:

  1. The poisoned servers in attacks/evil_*.py. Each module defines plain
     module-level constants (TOOL_NAME, TOOL_DESCRIPTION, META, and sometimes
     a second FILE_TOOL_NAME/FILE_TOOL_DESCRIPTION). We read those constants
     *statically* with `ast` instead of importing the module, because importing
     builds a FastMCP server (requires the `mcp` SDK) and we want the demo to
     work even when that optional dependency isn't installed.

  2. A small set of genuinely clean tools (from trusted_tools.py's spirit) so
     the demo visibly passes healthy tools as well as blocking traps.

Each returned tool is a dict:
    {
        "name": str,
        "description": str,
        "server": str,          # which fixture / source it came from
        "attack_class": str,    # "" for clean tools
        "expected": str,        # "dangereux" / "sain" (ground truth, for the demo)
        "why_judge": str,       # one-line note on why the LLM is needed
    }
"""

from __future__ import annotations

import ast
from pathlib import Path

ATTACKS_DIR = Path(__file__).resolve().parent / "attacks"


def _module_constants(path: Path) -> dict:
    """Return the module-level literal constants of a .py file, without importing it."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out: dict = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    try:
                        out[target.id] = ast.literal_eval(node.value)
                    except Exception:
                        pass  # skip non-literal assignments (functions, calls…)
    return out


def _load_attack_tools() -> list[dict]:
    tools: list[dict] = []
    for path in sorted(ATTACKS_DIR.glob("evil_*.py")):
        c = _module_constants(path)
        meta = c.get("META", {}) if isinstance(c.get("META"), dict) else {}
        expected = c.get("EXPECTED_VERDICT", "dangereux")
        # normalise English "dangerous" -> French "dangereux" used across the repo
        expected = "dangereux" if str(expected).startswith("danger") else expected
        why = meta.get("why_judge_catches", "")

        # Primary poisoned tool.
        if "TOOL_DESCRIPTION" in c:
            tools.append({
                "name": c.get("TOOL_NAME", path.stem),
                "description": c["TOOL_DESCRIPTION"],
                "server": path.stem,
                "attack_class": c.get("ATTACK_CLASS", meta.get("attack_class", "")),
                "expected": expected,
                "why_judge": why,
            })
        # Optional second poisoned tool (evil_shadow has one).
        if "FILE_TOOL_DESCRIPTION" in c:
            tools.append({
                "name": c.get("FILE_TOOL_NAME", path.stem + "_file"),
                "description": c["FILE_TOOL_DESCRIPTION"],
                "server": path.stem,
                "attack_class": c.get("ATTACK_CLASS", meta.get("attack_class", "")),
                "expected": expected,
                "why_judge": why,
            })
    return tools


# A few honest tools (clean descriptions) so the demo shows healthy pass-through.
_CLEAN_TOOLS = [
    {
        "name": "get_weather",
        "description": "Returns the current weather for a given city.",
        "server": "trusted_tools",
        "attack_class": "",
        "expected": "sain",
        "why_judge": "",
    },
    {
        "name": "send_email",
        "description": "Sends an email to the given recipient with the given subject and body.",
        "server": "trusted_tools",
        "attack_class": "",
        "expected": "sain",
        "why_judge": "",
    },
    {
        "name": "add",
        "description": "Adds two numbers and returns the sum. Parameters: a (number), b (number).",
        "server": "trusted_tools",
        "attack_class": "",
        "expected": "sain",
        "why_judge": "",
    },
]


def load_catalogue(include_clean: bool = True) -> list[dict]:
    """Return the full list of tools to scan in the demo."""
    tools = _load_attack_tools()
    if include_clean:
        tools = tools + _CLEAN_TOOLS
    return tools


if __name__ == "__main__":
    for t in load_catalogue():
        print(f"[{t['expected']:9}] {t['server']:14} {t['name']:24} :: {t['description'][:60]}…")
