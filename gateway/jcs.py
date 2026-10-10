"""JSON canonicalization (RFC 8785 / JCS profile) used for every hash and signature.

The gateway, the Python verifier and the Java verifier MUST produce byte-identical output for the
same JSON value, otherwise valid requests are rejected. Profile used across all implementations:

* objects: keys sorted by UTF-16 code units, no whitespace;
* strings: JSON escaping as in ECMAScript JSON.stringify (\\b \\t \\n \\f \\r \\" \\\\ and \\u00xx for
  other control characters, everything else literal UTF-8);
* integers (JSON numbers without fraction/exponent): exact decimal digits, arbitrary size;
* other numbers: IEEE-754 double formatted with the ECMAScript Number::toString algorithm
  (e.g. 1.0 -> "1", 1e-7 -> "1e-7", 0.00001 -> "0.00001");
* NaN / Infinity are rejected.

Recommendation: send money amounts as strings ("12.50") to avoid any floating point ambiguity.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
from decimal import Decimal
from typing import Any


class CanonicalizationError(ValueError):
    pass


def _format_float(value: float) -> str:
    if not math.isfinite(value):
        raise CanonicalizationError("NaN/Infinity cannot be canonicalized")
    if value == 0:
        return "0"
    if value.is_integer() and abs(value) < 1e21:
        return str(int(value))
    sign = "-" if value < 0 else ""
    sign_bit, digits_tuple, exponent = Decimal(repr(abs(value))).as_tuple()
    digits = "".join(str(d) for d in digits_tuple).rstrip("0") or "0"
    # value = 0.digits * 10^n
    n = len("".join(str(d) for d in digits_tuple)) + exponent
    k = len(digits)
    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        mantissa = digits[0] + ("." + digits[1:] if k > 1 else "")
        out = f"{mantissa}e{'+' if e > 0 else '-'}{abs(e)}"
    return sign + out


def _serialize(value: Any, out: list[str]) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int):
        out.append(str(value))
    elif isinstance(value, float):
        out.append(_format_float(value))
    elif isinstance(value, str):
        out.append(json.dumps(value, ensure_ascii=False))
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _serialize(item, out)
        out.append("]")
    elif isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise CanonicalizationError("object keys must be strings")
        out.append("{")
        for i, key in enumerate(sorted(value, key=lambda k: k.encode("utf-16-be"))):
            if i:
                out.append(",")
            out.append(json.dumps(key, ensure_ascii=False))
            out.append(":")
            _serialize(value[key], out)
        out.append("}")
    else:
        raise CanonicalizationError(f"unsupported type: {type(value).__name__}")


def canonicalize(value: Any) -> bytes:
    out: list[str] = []
    _serialize(value, out)
    return "".join(out).encode("utf-8")


def sha256_hex(value: Any) -> str:
    return hashlib.sha256(canonicalize(value)).hexdigest()


def sha256_b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
