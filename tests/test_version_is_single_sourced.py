"""A8.1: version is single-sourced from ``pramiti_mcp_gateway.__version__``."""
from __future__ import annotations

import re
from pathlib import Path

import tomllib

_PKG_ROOT = Path(__file__).resolve().parents[1]
_PYPROJECT = _PKG_ROOT / "pyproject.toml"
_INIT = _PKG_ROOT / "src" / "pramiti_mcp_gateway" / "__init__.py"
_MOD = "pramiti_mcp_gateway"


def _version_from_init() -> str:
    text = _INIT.read_text(encoding="utf-8")
    m = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', text, re.M)
    assert m, f"{_INIT} missing __version__"
    return m.group(1)


def test_version_is_semver_shaped():
    version = _version_from_init()
    parts = version.split(".")
    assert len(parts) >= 2
    assert all(p.isdigit() for p in parts[:2]), version


def test_pyproject_declares_dynamic_version_from_init():
    data = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    dynamic = data.get("project", {}).get("dynamic") or []
    assert "version" in dynamic, f"project.dynamic missing version: {dynamic}"
    assert "version" not in data.get("project", {}), "static project.version must be removed"
    attr = (
        data.get("tool", {})
        .get("setuptools", {})
        .get("dynamic", {})
        .get("version", {})
        .get("attr")
    )
    assert attr == f"{_MOD}.__version__", attr
    # Single source: the attr target exists and is semver-shaped
    assert _version_from_init()
