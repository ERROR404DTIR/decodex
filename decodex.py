#!/usr/bin/env python3
"""decodex - decode JWTs, Base64, URL-encoding, hex and Unix timestamps.

One file, zero dependencies. Just run it:  python decodex.py <text>
"""
import argparse
import base64
import json
import re
import sys
import urllib.parse
from datetime import datetime, timezone

__version__ = "1.0.0"


def b64d(s):
    """Decode standard or URL-safe Base64, with or without padding."""
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s)


def to_dt(value):
    """Unix time in s / ms / us / ns -> aware UTC datetime."""
    n = float(value)
    if n > 1e17:
        n /= 1e9
    elif n > 1e14:
        n /= 1e6
    elif n > 1e11:
        n /= 1e3
    try:
        return datetime.fromtimestamp(n, timezone.utc)
    except (OverflowError, OSError):
        raise ValueError("timestamp out of range")


def show_bytes(data):
    """Readable text if possible (JSON gets pretty-printed), else hex."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return "binary data, %d bytes\n%s" % (len(data), data.hex())
    if not all(c.isprintable() or c in "\r\n\t" for c in text):
        return "binary data, %d bytes\n%s" % (len(data), data.hex())
    if text.lstrip()[:1] in "{[":
        try:
            return json.dumps(json.loads(text), indent=2, ensure_ascii=False)
        except ValueError:
            pass
    return text


def d_jwt(s):
    s = s.strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]*)?", s):
        raise ValueError("not a JWT")
    parts = s.split(".")
    header = json.loads(b64d(parts[0]))
    payload = json.loads(b64d(parts[1]))
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("not a JWT")
    out = ["header:", json.dumps(header, indent=2, ensure_ascii=False),
           "payload:", json.dumps(payload, indent=2, ensure_ascii=False)]
    now = datetime.now(timezone.utc)
    times = []
    for key in ("iat", "nbf", "exp"):
        v = payload.get(key)
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            t = to_dt(v)
            note = ""
            if key == "exp":
                note = "  (EXPIRED)" if t < now else "  (still valid)"
            times.append("  %s: %s UTC%s" % (key, t.strftime("%Y-%m-%d %H:%M:%S"), note))
    if times:
        out += ["times:"] + times
    sig = parts[2] if len(parts) == 3 and parts[2] else None
    out.append("signature: " + (sig if sig else "(none)") + "  [not verified]")
    return "\n".join(out)


def d_ts(s):
    s = s.strip()
    if not re.fullmatch(r"\d{9,19}(\.\d+)?", s):
        raise ValueError("not a timestamp")
    t = to_dt(s)
    return "%s UTC\n%s (local)" % (t.strftime("%Y-%m-%d %H:%M:%S"),
                                  t.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"))


def d_url(s):
    if not re.search(r"%[0-9A-Fa-f]{2}", s):
        raise ValueError("no percent-escapes")
    return urllib.parse.unquote_plus(s)


def d_hex(s):
    h = s.strip()
    if h[:2].lower() == "0x":
        h = h[2:]
    h = re.sub(r"[\s:]", "", h)
    if not re.fullmatch(r"([0-9a-fA-F]{2})+", h):
        raise ValueError("not hex")
    return show_bytes(bytes.fromhex(h))


def d_b64(s):
    s = s.strip()
    if len(s) < 4 or not re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", s):
        raise ValueError("not base64")
    return show_bytes(b64d(s))


DECODERS = [("jwt", d_jwt), ("ts", d_ts), ("url", d_url), ("hex", d_hex), ("b64", d_b64)]
ENCODERS = {
    "b64": lambda t: base64.b64encode(t.encode("utf-8")).decode("ascii"),
    "url": lambda t: urllib.parse.quote(t, safe=""),
    "hex": lambda t: t.encode("utf-8").hex(),
}


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    p = argparse.ArgumentParser(
        prog="decodex",
        description="Decode JWTs, Base64, URL-encoding, hex and Unix timestamps (auto-detected).")
    p.add_argument("text", nargs="?", help="text to decode (omit or use '-' to read stdin)")
    p.add_argument("--as", dest="kind", choices=[k for k, _ in DECODERS],
                   help="force one decoder instead of auto-detecting")
    p.add_argument("-a", "--all", action="store_true", help="show every interpretation that works")
    p.add_argument("-e", "--encode", choices=sorted(ENCODERS), help="encode the text instead")
    p.add_argument("-V", "--version", action="version", version="decodex " + __version__)
    a = p.parse_args(argv)

    text = a.text
    if text is None and sys.stdin.isatty():
        p.print_help()
        return 0
    if text is None or text == "-":
        text = sys.stdin.read().strip("\r\n")

    if a.encode:
        print(ENCODERS[a.encode](text))
        return 0

    found = 0
    for key, func in DECODERS:
        if a.kind and key != a.kind:
            continue
        try:
            out = func(text)
        except ValueError:
            continue
        print("[%s]" % key)
        print(out)
        found += 1
        if not a.all:
            break
    if not found:
        print("decodex: could not decode the input", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
