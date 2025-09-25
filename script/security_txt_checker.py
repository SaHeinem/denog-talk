"""Utilities for checking security.txt availability and basic validity."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import ssl
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

PATH = "/.well-known/security.txt"
USER_AGENT = "security-txt-checker/1.0"
MAX_VALIDITY = timedelta(days=366)


@dataclass
class CheckResult:
    """Outcome of checking a single security.txt URL."""

    url: str
    status: int | None
    contact_present: bool
    expires: datetime | None
    expires_ok: bool
    is_valid: bool
    error: str | None = None


def normalize_domain(domain: str) -> str:
    """Return a hostname without scheme or leading www."""

    candidate = domain.strip()
    if not candidate:
        return ""

    # Allow callers to paste full URLs by leaning on urlparse for extraction.
    parsed = urlparse(candidate if "://" in candidate else f"//{candidate}", scheme="")
    host = parsed.hostname or candidate

    if host.startswith("www."):
        host = host[4:]

    return host


def parse_expires(raw_value: str) -> datetime | None:
    """Parse an Expires value into a timezone-aware UTC datetime."""

    value = raw_value.strip()
    if not value:
        return None

    if value.endswith("Z"):
        value = value[:-1] + "+00:00"

    try:
        expires = datetime.fromisoformat(value)
    except ValueError:
        return None

    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)

    return expires.astimezone(timezone.utc)


def evaluate_security_txt(body: str) -> tuple[bool, datetime | None, bool, bool]:
    """Return presence of Contact, Expires, whether Expires is acceptable, and overall validity."""

    contact_present = False
    expires_value: datetime | None = None

    for line in body.splitlines():
        if ":" not in line:
            continue
        field, value = line.split(":", 1)
        field = field.strip().lower()
        value = value.strip()

        # We only care about the first occurrence of these directive names.
        if field == "contact" and value:
            contact_present = True
        elif field == "expires" and value and expires_value is None:
            expires_value = parse_expires(value)

    now = datetime.now(timezone.utc)
    expires_ok = False
    if expires_value is not None:
        valid_duration = expires_value - now
        expires_ok = timedelta(0) <= valid_duration <= MAX_VALIDITY

    is_valid = contact_present and expires_ok

    return contact_present, expires_value, expires_ok, is_valid


def fetch(url: str) -> tuple[int | None, str | None, str | None]:
    """Fetch a URL and return status code, body, and error message."""

    request = Request(url, headers={"User-Agent": USER_AGENT})

    try:
        with urlopen(request, context=ssl.create_default_context()) as response:
            body = response.read().decode("utf-8", errors="replace")
            return response.getcode(), body, None
    except HTTPError as error:
        # We got a response with an HTTP status (e.g., 404), so the error field stays empty.
        return error.code, None, None
    except URLError as error:
        return None, None, str(error.reason)


def check_url(url: str) -> CheckResult:
    """Check a single security.txt URL."""

    status, body, error = fetch(url)

    contact_present = False
    expires_value: datetime | None = None
    expires_ok = False
    is_valid = False

    if status == 200 and body is not None:
        contact_present, expires_value, expires_ok, is_valid = evaluate_security_txt(body)

    return CheckResult(
        url=url,
        status=status,
        contact_present=contact_present,
        expires=expires_value,
        expires_ok=expires_ok,
        is_valid=is_valid,
        error=error,
    )


def check_domain(domain: str, include_www: bool = True) -> list[CheckResult]:
    """Check the canonical security.txt locations for a domain."""

    host = normalize_domain(domain)
    if not host:
        return []

    urls = [f"https://{host}{PATH}"]
    if include_www and host and not host.startswith("www."):
        # Avoid duplicating the www host if the caller already supplied it.
        urls.append(f"https://www.{host}{PATH}")

    return [check_url(url) for url in urls]


def format_result(result: CheckResult) -> Iterable[str]:
    """Yield human-readable lines describing a check result."""

    header = f"{result.url} -> {result.status if result.status is not None else 'error'}"
    yield header

    if result.error:
        yield f"  Error: {result.error}"
        return

    if result.status != 200:
        return

    contact_msg = "found" if result.contact_present else "missing"
    yield f"  Contact: {contact_msg}"

    if result.expires is None:
        yield "  Expires: missing or unparsable"
    else:
        validity_msg = "ok" if result.expires_ok else "invalid range"
        yield f"  Expires: {result.expires.isoformat()} ({validity_msg})"

    if result.is_valid:
        yield "  Valid"


__all__ = [
    "CheckResult",
    "check_domain",
    "check_url",
    "format_result",
    "normalize_domain",
]
