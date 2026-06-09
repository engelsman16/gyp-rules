import base64
import re


def _try_base64(snippet: str) -> str | None:
    # Match standalone base64 tokens ≥20 chars or explicit Buffer.from(...,'base64') pattern
    candidates = re.findall(r"Buffer\.from\(['\"]([A-Za-z0-9+/=]{4,})['\"],\s*['\"]base64['\"]", snippet)
    if not candidates:
        # Fall back to any long-ish token that looks like base64
        candidates = re.findall(r"['\"]([A-Za-z0-9+/=]{20,})['\"]", snippet)
    for candidate in candidates:
        try:
            decoded = base64.b64decode(candidate + "==").decode("utf-8", errors="replace")
            if decoded.isprintable() or "\n" in decoded:
                return decoded
        except Exception:
            continue
    return None


def _try_hex(snippet: str) -> str | None:
    # Match \xNN\xNN... sequences
    hex_seq = re.findall(r"(?:\\x[0-9a-fA-F]{2}){2,}", snippet)
    for seq in hex_seq:
        try:
            raw = bytes(int(b, 16) for b in re.findall(r"[0-9a-fA-F]{2}", seq))
            return raw.decode("utf-8", errors="replace")
        except Exception:
            continue
    return None


def _try_fromcharcode(snippet: str) -> str | None:
    # Match String.fromCharCode(72,101,108,...)
    m = re.search(r"fromCharCode\(([\d,\s]+)\)", snippet)
    if m:
        try:
            return "".join(chr(int(n.strip())) for n in m.group(1).split(",") if n.strip())
        except Exception:
            pass
    return None


def try_decode(snippet: str) -> str | None:
    """Return decoded content if snippet contains an encoded payload, else None."""
    for decoder in (_try_base64, _try_hex, _try_fromcharcode):
        result = decoder(snippet)
        if result is not None:
            return result
    return None
