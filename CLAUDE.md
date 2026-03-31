# CLAUDE.md

## Project

apiscan — lightweight API content discovery tool using Kiterunner .kite wordlists.

## Before pushing

Bump the version in all four locations:

- `pyproject.toml` (`version = "X.Y.Z"`)
- `src/apiscan/__init__.py` (`__version__`)
- `src/apiscan/output.py` (banner string)
- `README.md` (banner code block)

## Tests

```
poetry run pytest tests/
```

All tests must pass before pushing. The test suite includes integration tests against a real HTTP server and path validation against both .kite files (kites/ directory, gitignored).

## Structure

- `src/apiscan/kite.py` — protobuf decoder, crumb generation, route rendering, safety filter
- `src/apiscan/scanner.py` — async HTTP engine, baseline detection, validators
- `src/apiscan/output.py` — ANSI terminal output, CSV writer, progress tracker
- `src/apiscan/__main__.py` — CLI (subcommands: `scan`, `download`)
