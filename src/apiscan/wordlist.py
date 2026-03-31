"""Load routes from flat wordlist files (one path per line)."""

from __future__ import annotations

from apiscan.kite import Route


def load_wordlist(path: str) -> list[Route]:
    """Read a wordlist file and return ``Route`` objects (GET, no crumbs).

    Blank lines and lines starting with ``#`` are skipped.
    Paths are deduplicated and normalised to start with ``/``.
    """
    seen: set[str] = set()
    routes: list[Route] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if not line.startswith("/"):
                line = "/" + line
            if line in seen:
                continue
            seen.add(line)
            routes.append(Route(template_path=line, method="GET"))
    return routes
