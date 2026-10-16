"""Scope string parsing and normalisation.

A scope is a comma-separated list of targets. Each target may be an IPv4/IPv6
address, a CIDR block, a hostname, or one of three range forms, which are
expanded to CIDR before anything downstream sees them:

    192.168.1.*          wildcard trailing octets      -> 192.168.1.0/24
    192.168.*.*          (any trailing run of them)    -> 192.168.0.0/16
    10.0.0.1-10.0.0.50   explicit start-end range      -> the minimal CIDR set
    192.168.1.10-50      last-octet shorthand          -> 192.168.1.10 .. .50

Expansion only ever produces addresses *inside* the range that was written, so a
range token can never widen a scope. A wildcard combined with a prefix length
(``192.168.1.*/25``) is refused rather than guessed, because the two available
readings disagree with each other.

This module is a typo guard, not an access control. The pentest tool server
enforces the real boundary from its own launch environment; everything here
exists so a fat-fingered scope is rejected before it is written anywhere.
"""

from __future__ import annotations

import ipaddress
import re
import socket

__all__ = [
    "ScopeError",
    "parse_scope",
    "normalise_scope",
    "target_in_scope",
    "SOLO_SCOPE",
    "SOLO_ALIASES",
]

SOLO_SCOPE = "127.0.0.1/32"

SOLO_ALIASES = frozenset({"", "solo", "none", "off"})

_HOST_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOSTNAME_RE = re.compile(rf"^{_HOST_LABEL}(?:\.{_HOST_LABEL})*\.?$")

_FORBIDDEN_RE = re.compile(r"[\s\"'`$;&|<>(){}\[\]\\!*?~^#\x00-\x1f]")
#: Digits and dots only: a mistyped address cannot be read as a hostname.
_DOTTED_NUMERIC_RE = re.compile(r"[0-9.]+")
#: Digits, dots and dashes only: a mistyped *range* cannot be read as a hostname.
_RANGE_NUMERIC_RE = re.compile(r"[0-9.\-]+")

#: Ceiling on how many CIDRs one range token may expand into. A legitimate
#: range summarises to a handful; hundreds means the scope is not what was meant.
_MAX_EXPANSION = 256

#: Ceiling on the total number of normalised entries a single scope may hold.
#: The per-token expansion cap bounds one range; this bounds the whole list, so
#: a scope built from hundreds of comma-separated tokens is rejected as a
#: mistake rather than silently recorded.
_MAX_ENTRIES = 256


class ScopeError(ValueError):
    """Raised when a scope string cannot be understood as a target list."""


def _clean_token(token: str) -> str:
    token = token.strip()
    if not token:
        raise ScopeError("empty entry in scope list")
    if token.startswith("*."):
        raise ScopeError(
            f"{token!r} uses wildcard matching, which the tool server cannot enforce"
        )
    if _FORBIDDEN_RE.search(token):
        raise ScopeError(f"{token!r} contains characters that are not valid in a target")
    if len(token) > 253:
        raise ScopeError(f"{token!r} is too long to be a host or network")
    return token


def _expand_wildcard(token: str) -> list[str] | None:
    """``192.168.1.*`` and friends -> one CIDR. None when not this shape.

    The wildcard must be a contiguous run of *trailing* octets: ``192.*.1.*`` has
    no single-CIDR equivalent, so it is left to the caller to reject.
    """
    parts = token.split(".")
    if len(parts) != 4:
        return None

    numeric = 0
    seen_star = False
    for part in parts:
        if part == "*":
            seen_star = True
            continue
        if seen_star:
            return None          # a real octet after a wildcard: not trailing
        if not part.isdigit() or not 0 <= int(part) <= 255:
            return None
        numeric += 1

    if not seen_star or numeric == 0:
        return None              # `*`, `**`, `*.*.*.*` stay rejected

    address = ".".join(parts[:numeric] + ["0"] * (4 - numeric))
    return [f"{address}/{numeric * 8}"]


def _expand_dash_range(token: str) -> list[str] | None:
    """``10.0.0.1-10.0.0.50`` and ``192.168.1.10-50``. None when not this shape."""
    if token.count("-") != 1:
        return None
    left, right = token.split("-")
    if not left or not right:
        return None

    try:
        first = ipaddress.IPv4Address(left)
    except ValueError:
        return None

    if right.isdigit():
        # Last-octet shorthand: carry the prefix across.
        if not 0 <= int(right) <= 255:
            return None
        right = f"{left.rsplit('.', 1)[0]}.{right}"

    try:
        last = ipaddress.IPv4Address(right)
    except ValueError:
        return None

    if int(last) < int(first):
        raise ScopeError(f"{token!r} runs backwards; {right} precedes {left}")

    networks = list(ipaddress.summarize_address_range(first, last))
    if len(networks) > _MAX_EXPANSION:
        raise ScopeError(
            f"{token!r} expands to {len(networks)} networks, more than the "
            f"{_MAX_EXPANSION} allowed; narrow the range"
        )
    return [str(network) for network in networks]


def _expand_token(token: str) -> list[str] | None:
    """Expand a range token to CIDRs, or None when it is not one.

    Returns None rather than raising for anything that merely contains a dash or
    a star, so hostnames like ``my-host.example.com`` fall through untouched.
    """
    has_star = "*" in token
    has_dash = "-" in token
    if not has_star and not has_dash:
        return None

    if has_star and "/" in token:
        raise ScopeError(
            f"{token!r} combines a wildcard with a prefix length, and the two can "
            "disagree; write the network explicitly instead, e.g. 192.168.1.0/25"
        )
    if has_star:
        return _expand_wildcard(token)
    return _expand_dash_range(token)


def _normalise_network(token: str, allow_any: bool) -> str:
    """Canonicalise a CIDR token, refusing one whose host bits widen it."""
    try:
        network = ipaddress.ip_network(token, strict=True)
    except ValueError as exc:
        try:
            relaxed = ipaddress.ip_network(token, strict=False)
        except ValueError:
            raise ScopeError(f"{token!r} is not a valid network") from exc
        raise ScopeError(
            f"{token!r} has host bits set; did you mean {relaxed}?"
        ) from exc

    if network.prefixlen == 0 and not allow_any:
        raise ScopeError(
            f"{token!r} covers every address; pass --allow-any to confirm that is intended"
        )
    return str(network)


def _is_legacy_numeric(token: str) -> bool:
    """True when only a legacy numeric resolver form explains this token.

    ``curl`` and friends read ``0x7f000001`` and ``0x7f.1`` as 127.0.0.1, so a
    token accepted as a hostname here would authorise a host nobody typed.
    """
    try:
        socket.inet_aton(token)
    except OSError:
        return False
    return True


def _normalise_single_token(token: str, allow_any: bool) -> str:
    if "/" in token:
        return _normalise_network(token, allow_any)

    try:
        address = ipaddress.ip_address(token)
    except ValueError:
        pass
    else:
        return f"{address}/{address.max_prefixlen}"

    if _DOTTED_NUMERIC_RE.fullmatch(token):
        raise ScopeError(f"{token!r} looks like an IP address but is not valid")

    if _RANGE_NUMERIC_RE.fullmatch(token):
        raise ScopeError(f"{token!r} looks like a range but is not valid")

    if _is_legacy_numeric(token):
        raise ScopeError(
            f"{token!r} is a legacy numeric address form that resolvers read as a "
            "different host; write it as a dotted-quad address instead"
        )

    if not _HOSTNAME_RE.match(token):
        raise ScopeError(f"{token!r} is not a valid host, IP or CIDR")
    return token.lower().rstrip(".")


def _normalise_token(token: str, allow_any: bool) -> list[str]:
    """Normalise one raw entry, which may legitimately become several networks."""
    token = token.strip()
    if not token:
        raise ScopeError("empty entry in scope list")
    if len(token) > 253:
        raise ScopeError(f"{token!r} is too long to be a host or network")

    expanded = _expand_token(token)
    if expanded is not None:
        return [_normalise_network(entry, allow_any) for entry in expanded]

    return [_normalise_single_token(_clean_token(token), allow_any)]


def parse_scope(raw: str, *, allow_any: bool = False) -> list[str]:
    """Split a raw scope string into normalised target entries."""
    if raw is None:
        raise ScopeError("scope is required")
    text = raw.strip()
    if text.lower() in SOLO_ALIASES:
        return [SOLO_SCOPE]

    seen: dict[str, None] = {}
    for part in text.split(","):
        for entry in _normalise_token(part, allow_any):
            seen.setdefault(entry, None)
            if len(seen) > _MAX_ENTRIES:
                raise ScopeError(
                    f"scope has more than {_MAX_ENTRIES} entries; "
                    "this is almost certainly not the intended target list"
                )
    return list(seen)


def normalise_scope(raw: str, *, allow_any: bool = False) -> str:
    """Return the canonical, comma-joined form of ``raw``."""
    return ",".join(parse_scope(raw, allow_any=allow_any))


def _host_of(target: str) -> str:
    """Return the host part of a ``HOST`` or ``HOST:PORT`` target.

    A bracketed IPv6 literal (``[::1]:443``) keeps its address; a bare token is
    returned unchanged. The port is only ever stripped when it is unambiguous.
    """
    target = target.strip()
    if target.startswith("["):
        end = target.find("]")
        if end != -1:
            return target[1:end]
    # Only treat a trailing ``:digits`` as a port; a bare IPv6 has several colons
    # and no port, so leave it whole.
    head, sep, tail = target.rpartition(":")
    if sep and head and tail.isdigit() and head.count(":") == 0:
        return head
    return target


def target_in_scope(target: str, scope_text: str, *, allow_any: bool = False) -> bool:
    """Whether ``target`` is provably authorised by ``scope_text``.

    Fails closed: an IP target is in scope only when some scope entry is an IP
    network that contains it; a hostname target is in scope only on an exact
    (case-insensitive) match with a hostname entry. Anything unparseable, or a
    family mismatch, answers False rather than guessing. ``scope_text`` is the
    already-recorded scope, so it is re-normalised here to canonical entries.
    """
    host = _host_of(target)
    if not host:
        return False
    try:
        entries = parse_scope(scope_text, allow_any=allow_any)
    except ScopeError:
        return False

    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        addr = None

    lowered_host = host.rstrip(".").lower()
    for entry in entries:
        if "/" in entry:
            if addr is None:
                continue
            try:
                network = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                continue
            if addr.version == network.version and addr in network:
                return True
        else:
            if addr is None and entry.rstrip(".").lower() == lowered_host:
                return True
    return False
