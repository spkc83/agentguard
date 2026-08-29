"""Tests that pyproject.toml dependency declarations match reality.

Guards against the class of drift documented in
docs/plans/guardrails-realignment.md §6 row 0.2: declared dependencies that are
never imported anywhere under the package, and vice versa.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import agentguard

REPO_ROOT = Path(__file__).resolve().parents[2]
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"

# Maps a PyPI distribution name to the top-level module it is imported as.
DIST_TO_MODULE = {
    "pyyaml": "yaml",
    "pydantic": "pydantic",
    "structlog": "structlog",
    "rich": "rich",
    "typer": "typer",
}

# Extends DIST_TO_MODULE for optional-dependency checks.
EXTRA_DIST_TO_MODULE = {
    **DIST_TO_MODULE,
    "docker": "docker",
    "torch": "torch",
    "pandas": "pandas",
    "z3-solver": "z3",
    "opentelemetry-sdk": "opentelemetry",
    "opentelemetry-exporter-otlp": "opentelemetry",
    "opentelemetry-instrumentation": "opentelemetry",
    "langgraph": "langgraph",
    "langchain-core": "langchain_core",
    "crewai": "crewai",
    "google-adk": "google.adk",
    "mcp": "mcp",
    "pyjwt": "jwt",
}

# PyJWT is intentionally loaded through ``importlib`` so importing
# ``agentguard.core`` does not require the optional auth extra.
ALLOWED_UNIMPORTED = {
    "langgraph",
    "langchain-core",
    "crewai",
    "google-adk",
    "mcp",  # The adapter is intentionally duck-typed; native MCP is covered by optional tests.
    "pyjwt",
}

SEARCH_DIRS = ("agentguard", "scripts", "examples")

_DIST_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*")


def _dist_name(requirement: str) -> str:
    """Extract the bare distribution name from a PEP 508 requirement string."""
    match = _DIST_NAME_RE.match(requirement.strip())
    assert match is not None, f"Could not parse requirement: {requirement!r}"
    return match.group(0).lower()


def _load_pyproject() -> dict:
    with PYPROJECT_PATH.open("rb") as f:
        return tomllib.load(f)


def _module_is_imported(module: str) -> bool:
    """Search source trees for an import/from statement referencing `module`."""
    pattern = re.compile(rf"^\s*(?:import|from)\s+{re.escape(module)}\b", re.MULTILINE)
    for dirname in SEARCH_DIRS:
        directory = REPO_ROOT / dirname
        if not directory.exists():
            continue
        for path in directory.rglob("*.py"):
            if pattern.search(path.read_text(encoding="utf-8")):
                return True
    return False


def test_core_dependencies_are_imported() -> None:
    """Every core dependency in [project.dependencies] must be imported somewhere."""
    pyproject = _load_pyproject()
    dependencies = pyproject["project"]["dependencies"]

    for requirement in dependencies:
        dist = _dist_name(requirement)
        assert dist in DIST_TO_MODULE, (
            f"'{dist}' is a core dependency but has no entry in DIST_TO_MODULE — "
            "add one so this test can verify it is actually imported."
        )
        module = DIST_TO_MODULE[dist]
        assert _module_is_imported(module), (
            f"Core dependency '{dist}' (module '{module}') is declared in "
            "[project.dependencies] but is not imported anywhere under "
            f"{', '.join(SEARCH_DIRS)}/. Remove it or import it."
        )


def test_optional_extras_are_imported_or_allowlisted() -> None:
    """Every optional-dependency entry must be imported, unless allowlisted."""
    pyproject = _load_pyproject()
    extras = pyproject["project"]["optional-dependencies"]

    for extra_name, requirements in extras.items():
        if extra_name in ("dev", "all"):
            continue
        for requirement in requirements:
            dist = _dist_name(requirement)
            if dist in ALLOWED_UNIMPORTED:
                continue
            assert dist in EXTRA_DIST_TO_MODULE, (
                f"'{dist}' is declared in extra '{extra_name}' but has no entry "
                "in EXTRA_DIST_TO_MODULE — add one so this test can verify it."
            )
            module = EXTRA_DIST_TO_MODULE[dist]
            assert _module_is_imported(module), (
                f"Optional dependency '{dist}' (module '{module}') from extra "
                f"'{extra_name}' is not imported anywhere under "
                f"{', '.join(SEARCH_DIRS)}/. Remove it, import it, or add it to "
                "ALLOWED_UNIMPORTED with a reason."
            )


def test_version_matches_readme() -> None:
    """The pyproject version string must appear in the README status heading."""
    pyproject = _load_pyproject()
    version = pyproject["project"]["version"]
    readme_text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert f"Current Status: v{version}" in readme_text, (
        f"pyproject version '{version}' does not appear in the README "
        "'Current Status' heading — update one or the other."
    )


def test_package_version_matches_pyproject() -> None:
    """The runtime package version must match the distribution metadata."""
    pyproject = _load_pyproject()
    assert agentguard.__version__ == pyproject["project"]["version"] == "0.9.0"


def test_py_typed_present() -> None:
    """PEP 561 marker file must exist so type checkers treat the package as typed."""
    assert (REPO_ROOT / "agentguard" / "py.typed").is_file()


def test_wheel_ships_license_types_and_policies(tmp_path: Path) -> None:
    """The built wheel must carry LICENSE, py.typed and the three policy bundles.

    ``PolicyEngine`` loads its defaults from ``Path(__file__).parent / "policies"``;
    if packaging ever drops the YAML files every default policy path silently
    loads zero rules.
    """
    import subprocess
    import sys
    import zipfile

    subprocess.run(  # noqa: S603 — fixed argv, no untrusted input
        [sys.executable, "-m", "build", "--wheel", "--no-isolation", "--outdir", str(tmp_path)],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
    )
    wheels = list(tmp_path.glob("agentguard-*.whl"))
    assert len(wheels) == 1, wheels
    names = set(zipfile.ZipFile(wheels[0]).namelist())
    assert "agentguard/py.typed" in names
    for bundle in ("owasp_agentic", "finos_aigf_v2", "eu_ai_act"):
        assert f"agentguard/compliance/policies/{bundle}.yaml" in names
    assert any(n.endswith("/licenses/LICENSE") for n in names), sorted(names)
    # Every runtime subpackage must ship — a hatchling include regression
    # would otherwise surface only as ImportError in a consumer install.
    for module in (
        "agentguard/guardrails/kernel.py",
        "agentguard/guardrails/chain.py",
        "agentguard/guardrails/content.py",
        "agentguard/testing/synthetic.py",
        "agentguard/core/audit_collector.py",
        "agentguard/core/jwt_authentication.py",
        "agentguard/compliance/execution_journal.py",
        "agentguard/domains/finance/credit_risk/reason_codes.py",
    ):
        assert module in names, f"wheel is missing {module}"
