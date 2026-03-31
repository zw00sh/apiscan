```
 ▄▀█ █▀█ █ █▀ █▀▀ ▄▀█ █▄ █
 █▀█ █▀▀ █ ▄█ █▄▄ █▀█ █ ▀█
 api content discovery · v0.1.0
```

Lightweight API content discovery tool that uses [Kiterunner](https://github.com/assetnote/kiterunner)'s `.kite` wordlist files to find hidden API endpoints.

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
apiscan scan --url https://target.com
```

On first run, apiscan automatically downloads `routes-large.kite` (~35MB download, ~183MB extracted) from [Assetnote's CDN](https://wordlists-cdn.assetnote.io/data/kiterunner/) and caches it in `~/.cache/apiscan/`.

Use `--fast` to use the smaller wordlist (~1.7MB, 36k routes vs 958k):

```
apiscan scan --url https://target.com --fast
```

Or bring your own `.kite` file:

```
apiscan scan --url https://target.com --kite /path/to/custom.kite
```

You can also pre-download wordlists with `apiscan download`.

By default, apiscan runs in **safe mode**: GET requests only, with dangerous path keywords filtered. Use `--unsafe` to send all HTTP methods from the wordlist.

### Scan Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | required | Target base URL |
| `--kite` | routes-large | Path to `.kite` wordlist (auto-downloads if not cached) |
| `--fast` | off | Use routes-small.kite instead of routes-large.kite |
| `--unsafe` | off | Send all HTTP methods, disable keyword filter |
| `--concurrency` | 10 | Max concurrent requests |
| `--rate` | unlimited | Requests per second cap |
| `--timeout` | 10s | Per-request timeout |
| `--max-redirects` | 3 | Redirect follow limit |
| `--header K:V` | - | Extra header (repeatable) |
| `--status-codes` | - | Whitelist status codes (e.g. `200,301`) |
| `--blacklist-codes` | - | Blacklist status codes (e.g. `404,500`) |
| `--output` | - | Write results to CSV |
| `--no-color` | off | Disable ANSI colors |

## License

AGPL-3.0 -- see [LICENSE](LICENSE).
