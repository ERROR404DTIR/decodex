<p align="center"><img src="assets/banner.svg" alt="decodex" width="100%"></p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8%2B-22d3ee" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/dependencies-none-a78bfa" alt="No dependencies">
  <img src="https://img.shields.io/badge/license-MIT-34d399" alt="MIT">
</p>

**decodex** decodes JWTs, Base64, URL-encoding, hex and Unix timestamps. It auto-detects what you give it. One file, zero dependencies, nothing to install.

## Run it (portable)

Download the single file and run it:

```bash
curl -fsSLO https://raw.githubusercontent.com/ERROR404DTIR/decodex/main/decodex.py
python decodex.py "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE5MzU0MzIwMDB9.sig"
```

## Install (optional)

```bash
pip install git+https://github.com/ERROR404DTIR/decodex
decodex 1700000000
```

## Examples

```bash
decodex <jwt>                      # header, payload, expiry check (signature is NOT verified)
decodex 1700000000                 # Unix time (s / ms / us / ns) to UTC + local
decodex SGVsbG8sIHdvcmxkIQ==       # Base64 (standard or URL-safe) -> text / pretty JSON
decodex "hello%20world%21"         # URL-decode
decodex 68656c6c6f                 # hex -> text
decodex -a 1700000000              # show every interpretation that works
decodex --as b64 SGVsbG8=          # force one decoder
decodex -e b64 "hello"             # encode: b64, url or hex
echo "SGVsbG8=" | decodex          # read from stdin
```

## Options

| Option | Meaning |
|---|---|
| `--as {jwt,ts,url,hex,b64}` | force a decoder |
| `-a`, `--all` | print every interpretation that works |
| `-e`, `--encode {b64,url,hex}` | encode instead of decode |
| `-V`, `--version` | show version |

## License

MIT
