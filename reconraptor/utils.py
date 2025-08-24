from __future__ import annotations

import json
import socket
import struct
from typing import Any


def safe_str(value: Any) -> str:
    """Return a safe string representation for any value.

        None is ""
        Fallback to empty string on unexpected failures
    """
    if value is None:
        return ""
    try:
        return str(value)
    except Exception:
        return ""


def hash32(value: str) -> int:
    """Deterministic 32-bit signed hash from an input string."""
    h = hash(value) & 0xFFFFFFFF
    if h >= 0x80000000:
        h = -((~h & 0xFFFFFFFF) + 1)
    return h


def ip_to_int(ip: Any) -> int:
    """Convert IPv4 string to 32-bit int; otherwise return hashed fallback."""
    s = safe_str(ip)
    try:
        return struct.unpack("!I", socket.inet_aton(s))[0]
    except Exception:
        return hash32(s)


def user_agent_to_num(ua: Any) -> int:
    """Encode a user-agent into a single numeric feature.

        Combined as: length*65536 + low16(hash32(prefix_4))
    """
    s = safe_str(ua)
    length = len(s)
    prefix = s[:4]
    prefix_hash_low16 = hash32(prefix) & 0xFFFF
    return int(length) * 65536 + int(prefix_hash_low16)


def json_length(value: Any) -> int:
    try:
        return len(json.dumps(value, default=str))
    except Exception:
        return 0


def num_keys(value: Any) -> int:
    return len(value.keys()) if isinstance(value, dict) else 0


def guess_os_from_user_agent(ua: str) -> str:
    s = (ua or "").lower()
    if "windows" in s:
        return "Windows"
    if "mac os" in s or "macintosh" in s or "darwin" in s or "os x" in s:
        return "Mac"
    if "linux" in s:
        return "Linux"
    if "android" in s:
        return "Android"
    if "iphone" in s or "ios" in s or "ipad" in s:
        return "iOS"
    return "Unknown"





__all__ = [
    "safe_str",
    "hash32",
    "ip_to_int",
    "user_agent_to_num",
    "json_length",
    "num_keys",
    "guess_os_from_user_agent",
]



