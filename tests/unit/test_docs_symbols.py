"""Docs-truth tests.

``docs/api/index.md`` documents the public API. These tests execute every
``from agentguard... import ...`` line in that file so that a documented symbol
which does not exist fails CI, and assert that the docs do not advertise CLI
commands that were never implemented.
"""

from __future__ import annotations

import ast
import re
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
API_DOC = REPO_ROOT / "docs" / "api" / "index.md"

_PYTHON_BLOCK = re.compile(r"^```python$(.*?)^```$", re.MULTILINE | re.DOTALL)

# CLI invocations that appear in the docs but have never existed in cli.py.
# Keep these out of the prose: an unimplemented command is a bug report from a
# user, not a roadmap entry.
PHANTOM_CLI_COMMANDS = (
    "agentguard verify workflow",
    "agentguard verify model",
    "agentguard sandbox run",
)

# Files whose prose must not advertise the phantom commands.
_TRUTH_CHECKED_FILES = sorted(
    {
        *(p for p in (REPO_ROOT / "docs").rglob("*.md") if "plans" not in p.parts),
        REPO_ROOT / "ARCHITECTURE.md",
        REPO_ROOT / "CLAUDE.md",
        REPO_ROOT / "README.md",
        REPO_ROOT / "AGENTS.md",
    }
)


def _import_lines() -> list[str]:
    """Every ``from agentguard...`` import inside a fenced python block.

    The blocks are parsed with :mod:`ast` rather than scanned line-by-line so
    that multi-line parenthesised imports (as produced by ``ruff format``)
    survive extraction intact.
    """
    text = API_DOC.read_text(encoding="utf-8")
    lines: list[str] = []
    for block in _PYTHON_BLOCK.findall(text):
        tree = ast.parse(textwrap.dedent(block))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("agentguard"):
                lines.append(ast.unparse(node))
    return lines


def test_api_doc_has_import_blocks() -> None:
    """Guard against the extraction silently matching nothing."""
    lines = _import_lines()
    assert len(lines) >= 15, f"expected the API doc to document many imports, got {len(lines)}"


@pytest.mark.parametrize("import_line", _import_lines())
def test_documented_symbol_imports(import_line: str) -> None:
    """Each documented import statement must actually execute."""
    try:
        exec(import_line, {})  # noqa: S102 - the input is a doc line, not user data
    except ImportError as exc:  # pragma: no cover - only on a docs regression
        pytest.fail(
            f"docs/api/index.md documents a symbol that does not exist: {import_line}\n{exc}"
        )


@pytest.mark.parametrize("path", _TRUTH_CHECKED_FILES, ids=lambda p: str(p.relative_to(REPO_ROOT)))
def test_no_phantom_cli_commands(path: Path) -> None:
    """Docs must not reference CLI commands that are not implemented."""
    text = path.read_text(encoding="utf-8")
    found = [cmd for cmd in PHANTOM_CLI_COMMANDS if cmd in text]
    rel = path.relative_to(REPO_ROOT)
    assert not found, f"{rel} references unimplemented CLI commands: {found}"


def test_documented_cli_groups_exist() -> None:
    """The CLI surface listed in the API doc matches the Typer app."""
    from typer.main import get_command

    from agentguard.cli import app

    groups = set(get_command(app).commands)  # type: ignore[attr-defined]
    assert groups == {"audit", "policy", "verify", "observe"}
