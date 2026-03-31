```
 █▄▀ █ ▀█▀ █▀▀ █ █ █ ▄▀█ █   █▄▀ █▀▀ █▀█
 █ █ █  █  ██▄ ▀▄▀▄▀ █▀█ █▄▄ █ █ ██▄ █▀▄
 api content discovery · v0.1.0
```

Lightweight API content discovery tool that uses [Kiterunner](https://github.com/assetnote/kiterunner)'s `.kite` wordlist files to find hidden API endpoints.

## Install

```
pipx install git+https://github.com/zw00sh/kitewalker.git
```

Or with poetry for development:

```
git clone https://github.com/zw00sh/kitewalker.git
cd kitewalker
poetry install
```

## Wordlists

Download `.kite` files from Assetnote's CDN:

https://wordlists-cdn.assetnote.io/data/kiterunner/

`routes-large.kite` (~183MB) and `routes-small.kite` (~1.7MB) are the Swagger-derived wordlists with typed route parameters.

## Usage

```
kitewalker --kite routes-small.kite --url https://target.com
```

By default, kitewalker runs in **safe mode**: GET requests only, with dangerous path keywords filtered. Use `--unsafe` to send all HTTP methods from the wordlist.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--kite` | required | Path to `.kite` wordlist |
| `--url` | required | Target base URL |
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
