"""Parse .kite protobuf files, generate crumb values, render routes, and apply safety filters."""

from __future__ import annotations

import base64
import json
import random
import re
import string
import struct
from dataclasses import dataclass, field
from urllib.parse import urlencode
from uuid import uuid4

import exrex


# ---------------------------------------------------------------------------
# Protobuf wire-format decoder
# ---------------------------------------------------------------------------

def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        b = data[pos]
        result |= (b & 0x7F) << shift
        pos += 1
        if not (b & 0x80):
            return result, pos
        shift += 7


def _read_field(data: bytes, pos: int) -> tuple[int, int, int | bytes, int]:
    """Return (field_number, wire_type, value, new_pos)."""
    tag, pos = _read_varint(data, pos)
    wire_type = tag & 0x7
    field_num = tag >> 3
    if wire_type == 0:  # varint
        val, pos = _read_varint(data, pos)
        return field_num, wire_type, val, pos
    if wire_type == 2:  # length-delimited
        length, pos = _read_varint(data, pos)
        return field_num, wire_type, data[pos : pos + length], pos + length
    if wire_type == 1:  # 64-bit fixed
        return field_num, wire_type, data[pos : pos + 8], pos + 8
    if wire_type == 5:  # 32-bit fixed
        return field_num, wire_type, data[pos : pos + 4], pos + 4
    raise ValueError(f"unsupported wire type {wire_type} at position {pos}")


def _decode_message(data: bytes) -> dict[int, list]:
    """Decode all fields into {field_number: [values]}."""
    fields: dict[int, list] = {}
    pos = 0
    end = len(data)
    while pos < end:
        fn, _wt, val, pos = _read_field(data, pos)
        fields.setdefault(fn, []).append(val)
    return fields


def _str(fields: dict[int, list], num: int, default: str = "") -> str:
    vals = fields.get(num)
    if not vals:
        return default
    v = vals[0]
    return v.decode("utf-8", errors="replace") if isinstance(v, bytes) else str(v)


def _int(fields: dict[int, list], num: int, default: int = 0) -> int:
    vals = fields.get(num)
    if not vals:
        return default
    v = vals[0]
    # handle zigzag/signed: proto3 int64 fields are unsigned on the wire
    return v if isinstance(v, int) else int.from_bytes(v, "little", signed=True)


def _bool(fields: dict[int, list], num: int, default: bool = False) -> bool:
    vals = fields.get(num)
    return bool(vals[0]) if vals else default


def _double(fields: dict[int, list], num: int, default: float = 0.0) -> float:
    vals = fields.get(num)
    if not vals:
        return default
    v = vals[0]
    if isinstance(v, bytes) and len(v) == 8:
        return struct.unpack("<d", v)[0]
    return float(v)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Crumb:
    kind: str
    name: str = ""
    fields: dict = field(default_factory=dict)
    children: list[Crumb] = field(default_factory=list)


@dataclass
class Route:
    template_path: str
    method: str
    path_crumbs: list[Crumb] = field(default_factory=list)
    header_crumbs: list[Crumb] = field(default_factory=list)
    query_crumbs: list[Crumb] = field(default_factory=list)
    body_crumbs: list[Crumb] = field(default_factory=list)
    content_types: list[str] = field(default_factory=list)
    source_api_url: str = ""


@dataclass
class FilterStats:
    total: int
    kept: int
    method_filtered: int
    keyword_filtered: int
    method_breakdown: dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Proto -> model parsing
# ---------------------------------------------------------------------------

_CRUMB_PARSERS: dict[int, str] = {
    1: "uuid", 2: "static", 3: "int", 4: "bool", 5: "float",
    6: "random_string", 7: "regex_string", 8: "basic_auth",
    9: "array", 10: "object", 11: "string_crumb",
}


def _parse_crumb(data: bytes) -> Crumb | None:
    """Parse a ProtoCrumb oneof message."""
    outer = _decode_message(data)
    for fn, kind_name in _CRUMB_PARSERS.items():
        if fn not in outer:
            continue
        inner = _decode_message(outer[fn][0])
        if kind_name == "uuid":
            return Crumb("uuid", name=_str(inner, 1))
        if kind_name == "static":
            return Crumb("static", name=_str(inner, 1), fields={"v": _str(inner, 2)})
        if kind_name == "int":
            return Crumb("int", name=_str(inner, 5), fields={
                "min": _int(inner, 1), "max": _int(inner, 2),
                "val": _int(inner, 3), "fixed": _bool(inner, 4),
            })
        if kind_name == "bool":
            return Crumb("bool", name=_str(inner, 1), fields={
                "fixed": _bool(inner, 2), "val": _bool(inner, 3),
            })
        if kind_name == "float":
            return Crumb("float", name=_str(inner, 1), fields={
                "fixed": _bool(inner, 2), "val": _double(inner, 3),
            })
        if kind_name == "random_string":
            return Crumb("random_string", name=_str(inner, 1), fields={
                "charset": _str(inner, 2), "length": _int(inner, 3),
            })
        if kind_name == "regex_string":
            return Crumb("regex_string", name=_str(inner, 1), fields={
                "regex": _str(inner, 2),
            })
        if kind_name == "basic_auth":
            return Crumb("basic_auth", name=_str(inner, 1, "Authorization"), fields={
                "user": _str(inner, 2), "password": _str(inner, 3),
                "random": _bool(inner, 4),
            })
        if kind_name == "array":
            arr_fields = _decode_message(outer[fn][0])
            child = _parse_crumb(arr_fields[2][0]) if 2 in arr_fields else None
            return Crumb("array", name=_str(arr_fields, 1), children=[child] if child else [])
        if kind_name == "object":
            obj_fields = _decode_message(outer[fn][0])
            children = [c for raw in obj_fields.get(2, []) if (c := _parse_crumb(raw))]
            return Crumb("object", name=_str(obj_fields, 1), children=children)
        if kind_name == "string_crumb":
            sc_fields = _decode_message(outer[fn][0])
            child = _parse_crumb(sc_fields[2][0]) if 2 in sc_fields else None
            return Crumb("string_crumb", name=_str(sc_fields, 1), children=[child] if child else [])
    return None


def _parse_crumbs(fields: dict[int, list], num: int) -> list[Crumb]:
    return [c for raw in fields.get(num, []) if (c := _parse_crumb(raw))]


def _parse_route(data: bytes, api_url: str = "",
                 api_headers: list[Crumb] | None = None,
                 api_query: list[Crumb] | None = None,
                 api_body: list[Crumb] | None = None) -> Route | None:
    f = _decode_message(data)
    method = _str(f, 2).strip().upper()
    if method not in VALID_METHODS:
        return None
    return Route(
        template_path=_str(f, 1),
        method=method,
        path_crumbs=_parse_crumbs(f, 3),
        header_crumbs=(api_headers or []) + _parse_crumbs(f, 4),
        query_crumbs=(api_query or []) + _parse_crumbs(f, 5),
        body_crumbs=(api_body or []) + _parse_crumbs(f, 6),
        content_types=[v.decode("utf-8", errors="replace") if isinstance(v, bytes) else v
                       for v in f.get(7, [])],
        source_api_url=api_url,
    )


VALID_METHODS = frozenset({"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"})


def load_kite(path: str) -> list[Route]:
    """Load a .kite file and return a flat list of Route objects."""
    with open(path, "rb") as fh:
        data = fh.read()

    top = _decode_message(data)
    routes: list[Route] = []
    for api_data in top.get(1, []):
        af = _decode_message(api_data)
        api_url = _str(af, 1)
        api_headers = _parse_crumbs(af, 4)
        api_query = _parse_crumbs(af, 5)
        api_body = _parse_crumbs(af, 6)
        for route_data in af.get(3, []):
            r = _parse_route(route_data, api_url, api_headers, api_query, api_body)
            if r is not None:
                routes.append(r)
    return routes


# ---------------------------------------------------------------------------
# Crumb value generation
# ---------------------------------------------------------------------------

_ASCII_ALPHANUM = string.ascii_letters + string.digits


def generate_value(crumb: Crumb) -> str:
    k = crumb.kind
    f = crumb.fields

    if k == "uuid":
        return str(uuid4())

    if k == "static":
        return f.get("v", "")

    if k == "int":
        if f.get("fixed"):
            return str(f["val"])
        lo, hi = f.get("min", 0), f.get("max", 0)
        if lo >= hi:
            lo, hi = 0, 1_000_000
        return str(random.randint(lo, hi - 1))

    if k == "bool":
        if f.get("fixed"):
            return str(f["val"]).lower()
        return random.choice(["true", "false"])

    if k == "float":
        if f.get("fixed"):
            return str(f["val"])
        return str(random.random())

    if k == "random_string":
        charset = f.get("charset") or _ASCII_ALPHANUM
        length = f.get("length") or 8
        return "".join(random.choice(charset) for _ in range(length))

    if k == "regex_string":
        try:
            return exrex.getone(f.get("regex", "."))
        except Exception:
            return "1"

    if k == "basic_auth":
        user = f.get("user", "")
        password = f.get("password", "")
        if (not user and not password) or f.get("random"):
            user = "".join(random.choice(_ASCII_ALPHANUM) for _ in range(16))
            password = "".join(random.choice(_ASCII_ALPHANUM) for _ in range(16))
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        return f"Basic {token}"

    if k == "array":
        if crumb.children:
            return json.dumps([_crumb_json_value(crumb.children[0])])
        return "[]"

    if k == "object":
        obj = {}
        for child in crumb.children:
            obj[child.name or "key"] = _crumb_json_value(child)
        return json.dumps(obj)

    if k == "string_crumb":
        if crumb.children:
            return json.dumps(generate_value(crumb.children[0]))
        return '""'

    return ""


def _crumb_json_value(crumb: Crumb):
    """Return a native Python value suitable for JSON serialization."""
    k = crumb.kind
    if k == "int":
        return int(generate_value(crumb))
    if k == "float":
        return float(generate_value(crumb))
    if k == "bool":
        return generate_value(crumb) == "true"
    if k == "object":
        return {c.name or "key": _crumb_json_value(c) for c in crumb.children}
    if k == "array":
        if crumb.children:
            return [_crumb_json_value(crumb.children[0])]
        return []
    return generate_value(crumb)


# ---------------------------------------------------------------------------
# Route rendering
# ---------------------------------------------------------------------------

def render_path(route: Route) -> str:
    crumb_map = {c.name: c for c in route.path_crumbs if c.name}

    def _replacer(m: re.Match) -> str:
        name = m.group(1)
        if name in crumb_map:
            return generate_value(crumb_map[name])
        return "42"

    return re.sub(r"\{([^}]+)\}", _replacer, route.template_path)


def render_query(route: Route) -> str:
    if not route.query_crumbs:
        return ""
    params = [(c.name or c.fields.get("k", "q"), generate_value(c)) for c in route.query_crumbs]
    return urlencode(params)


def render_body(route: Route) -> str | None:
    if not route.body_crumbs:
        return None
    body = {}
    for c in route.body_crumbs:
        body[c.name or "data"] = _crumb_json_value(c)
    return json.dumps(body)


def render_headers(route: Route) -> dict[str, str]:
    headers = {}
    for c in route.header_crumbs:
        key = c.name or c.fields.get("k", "X-Custom")
        headers[key] = generate_value(c)
    return headers


# ---------------------------------------------------------------------------
# Safety filtering
# ---------------------------------------------------------------------------

DANGEROUS_KEYWORDS = frozenset({
    "delete", "remove", "destroy", "purge", "drop", "reset", "wipe",
    "clear", "disable", "revoke", "terminate", "kill", "shutdown",
    "deactivate", "suspend", "ban", "block", "erase", "uninstall",
})

_DANGEROUS_RE = re.compile(
    r"(?:^|/)(" + "|".join(re.escape(k) for k in DANGEROUS_KEYWORDS) + r")(?:/|$)",
    re.IGNORECASE,
)


def apply_safety_filter(routes: list[Route], unsafe: bool) -> tuple[list[Route], FilterStats]:
    method_breakdown: dict[str, int] = {}
    for r in routes:
        method_breakdown[r.method] = method_breakdown.get(r.method, 0) + 1

    if unsafe:
        return routes, FilterStats(
            total=len(routes), kept=len(routes),
            method_filtered=0, keyword_filtered=0,
            method_breakdown=method_breakdown,
        )

    method_filtered = 0
    keyword_filtered = 0
    kept: list[Route] = []

    for r in routes:
        if r.method != "GET":
            method_filtered += 1
            continue
        if _DANGEROUS_RE.search(r.template_path):
            keyword_filtered += 1
            continue
        kept.append(r)

    return kept, FilterStats(
        total=len(routes), kept=len(kept),
        method_filtered=method_filtered, keyword_filtered=keyword_filtered,
        method_breakdown=method_breakdown,
    )
