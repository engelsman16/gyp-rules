import pathlib
from functools import lru_cache

import yara

_RULES_DIR = pathlib.Path(__file__).parent.parent.parent / "rules"

# Maps exact filename → list of rule file paths (relative to rules dir).
# Community rules are added to all files via auto-discovery.
_FILENAME_ROUTING: dict[str, list[str]] = {
    "binding.gyp": ["npm/binding_gyp.yar"],
    "package.json": ["npm/package_json.yar"],
}


def _discover_community() -> list[pathlib.Path]:
    community = _RULES_DIR / "community"
    if not community.is_dir():
        return []
    return list(community.rglob("*.yar"))


@lru_cache(maxsize=None)
def _compiled(rule_path: pathlib.Path) -> yara.Rules:
    return yara.compile(str(rule_path))


def rules_for_file(filename: str) -> list[yara.Rules]:
    """Return compiled YARA rules applicable to a given filename."""
    specific = [
        _compiled(_RULES_DIR / rel)
        for rel in _FILENAME_ROUTING.get(filename, [])
        if (_RULES_DIR / rel).exists()
    ]
    community = [_compiled(p) for p in _discover_community()]
    return specific + community
