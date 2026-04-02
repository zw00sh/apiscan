"""Route model for API content discovery."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Route:
    template_path: str
    method: str
