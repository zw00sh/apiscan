```
 ▄▀█ █▀█ █ █▀ █▀▀ ▄▀█ █▄ █
 █▀█ █▀▀ █ ▄█ █▄▄ █▀█ █ ▀█
 api content discovery · v1.2.0
```

Method-aware API content discovery tool. Ships with curated wordlists built from 26k+ Swagger specs, HTTP Archive traffic data, and SecLists.

## Install

```
pipx install git+https://github.com/zw00sh/apiscan.git
```

Or with poetry for development:

```
git clone https://github.com/zw00sh/apiscan.git
cd apiscan
poetry install
```

## Quick Start

```
apiscan -u https://target.com
```

By default, apiscan uses a built-in 10k-path wordlist. Use `--short` for a fast 1k scan or `--long` for thorough 100k coverage:

```
apiscan -u https://target.com --short
apiscan -u https://target.com --long
```

Or bring your own wordlist:

```
apiscan -u https://target.com -w /path/to/wordlist.txt
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-u, --url` | required | Target base URL |
| `-w, --wordlist` | built-in 10k | Custom wordlist file (one path per line) |
| `--short` | off | Use built-in top 1k wordlist (fast) |
| `--long` | off | Use built-in top 100k wordlist (thorough) |
| `-m, --methods` | GET,POST | HTTP methods to probe (comma-separated) |
| `-c, --concurrency` | 10 | Max concurrent requests |
| `-r, --rate` | unlimited | Requests per second cap |
| `-t, --timeout` | 10s | Per-request timeout |
| `--max-redirects` | 3 | Redirect follow limit |
| `-H, --header K:V` | - | Extra header (repeatable) |
| `--recurse` | off | Re-apply wordlist under discovered handler boundaries |
| `--max-depth` | 2 | Max recursion depth |
| `--lookahead` | off | Probe common segments one level deeper at leaf nodes |
| `-i, --include` | - | Only report these status codes (e.g. `200,301,403`) |
| `-e, --exclude` | - | Never report these status codes (e.g. `429,500`) |
| `-o, --output` | - | Write results to CSV (includes curl replay column) |
| `--replay-proxy` | - | Replay findings through a proxy (e.g. Burp) |
| `-v, --verbose` | off | Show additional details |
| `-q, --quiet` | off | Output only discovered URLs |
| `--no-color` | off | Disable ANSI colors |

## License

AGPL-3.0 -- see [LICENSE](LICENSE).
