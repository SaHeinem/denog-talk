"""Utilities for checking security.txt availability and basic validity."""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from sectxt import Finding, SecurityTxtReport, analyze_security_txt

PATH = "/.well-known/security.txt"
USER_AGENT = "security-txt-checker/1.0"
REQUEST_TIMEOUT = 10  # seconds
_LABEL_PATTERN = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
_HOSTNAME_RE = re.compile(rf"^{_LABEL_PATTERN}(?:\.{_LABEL_PATTERN})*$")


@dataclass
class CheckResult:
    """Outcome of checking a single security.txt URL."""

    url: str
    status: int | None
    contact_present: bool
    expires: datetime | None
    expires_ok: bool
    is_valid: bool
    canonicals: list[str] | None = None
    pgp_signed: bool = False
    machine_readable: bool = True
    error: str | None = None
    errors: list[Finding] | None = None
    recommendations: list[Finding] | None = None
    notifications: list[Finding] | None = None
    report: SecurityTxtReport | None = None
    final_url: str | None = None


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


def is_hostname(candidate: str) -> bool:
    """Return True when the value looks like a valid DNS hostname."""

    value = candidate.strip().rstrip(".")
    if not value or len(value) > 253:
        return False
    if any(char.isspace() for char in value):
        return False
    return bool(_HOSTNAME_RE.fullmatch(value))


def _empty_lists() -> tuple[list[Finding], list[Finding], list[Finding]]:
    """Provide fresh containers for error, recommendation, and notification lists."""
    return [], [], []


def _normalize_url_for_compare(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme and parsed.netloc:
        path = parsed.path.rstrip("/") or "/"
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{path}"
    return value.strip().rstrip("/").lower()


def fetch(url: str) -> tuple[int | None, str | None, str | None, str | None]:
    """Fetch a URL and return status code, body, error message, and final URL."""

    request = Request(url, headers={"User-Agent": USER_AGENT})

    try:
        with urlopen(
            request,
            context=ssl.create_default_context(),
            timeout=REQUEST_TIMEOUT,
        ) as response:
            body = response.read().decode("utf-8", errors="replace")
            return response.getcode(), body, None, response.geturl()
    except HTTPError as error:
        # We got a response with an HTTP status (e.g., 404), so the error field stays empty.
        return error.code, None, None, error.geturl() if hasattr(error, "geturl") else url
    except (TimeoutError, socket.timeout):
        return None, None, f"Request timed out after {REQUEST_TIMEOUT} seconds", None
    except URLError as error:
        return None, None, str(error.reason), None
    except ValueError as error:
        return None, None, str(error), None
    except OSError as error:
        # Capture socket-level failures such as connection resets.
        return None, None, str(error), None


def check_url(url: str) -> CheckResult:
    """Check a single security.txt URL."""

    status, body, error, final_url = fetch(url)

    contact_present = False
    expires_value: datetime | None = None
    expires_ok = False
    is_valid = False
    canonicals: list[str] | None = None
    pgp_signed = False
    machine_readable = False

    analysis: SecurityTxtReport | None = None
    errors_list, recommendations_list, notifications_list = _empty_lists()

    if status == 200 and body is not None:
        analysis = analyze_security_txt(body)
        contact_present = bool(analysis.contacts)
        expires_value = analysis.expires
        expires_ok = analysis.expires_ok
        is_valid = analysis.is_valid
        canonicals = analysis.canonicals
        pgp_signed = analysis.pgp_signed
        machine_readable = analysis.machine_readable
        errors_list = analysis.errors
        recommendations_list = analysis.recommendations
        notifications_list = analysis.notifications
    else:
        if status is None:
            errors_list.append(
                Finding("network", error or "Request failed before receiving a response")
            )
        elif status != 200:
            errors_list.append(Finding("http_status", f"Received HTTP status {status}"))

    return CheckResult(
        url=url,
        final_url=final_url,
        status=status,
        contact_present=contact_present,
        expires=expires_value,
        expires_ok=expires_ok,
        is_valid=is_valid,
        canonicals=canonicals,
        pgp_signed=pgp_signed,
        machine_readable=machine_readable,
        error=error,
        errors=errors_list,
        recommendations=recommendations_list,
        notifications=notifications_list,
        report=analysis,
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


def compute_flags(results: list[CheckResult]) -> dict[str, bool]:
    """Summarize boolean flags derived from a collection of check results."""

    apex_result = next((item for item in results if "://www." not in item.url), None)
    www_result = next((item for item in results if "://www." in item.url), None)

    def expected_url(result: CheckResult | None) -> str | None:
        if result is None:
            return None
        if result.final_url:
            return result.final_url
        return result.url

    expected_apex_url = expected_url(apex_result)
    expected_www_url = expected_url(www_result)

    def canonical_present(expected_url: str | None) -> bool:
        if not expected_url:
            return False
        target = _normalize_url_for_compare(expected_url)
        for result in results:
            if result.report is None:
                continue
            for candidate in result.report.canonicals:
                if _normalize_url_for_compare(candidate) == target:
                    return True
        return False

    def findings_any(predicate) -> bool:
        for result in results:
            for finding in result.errors or []:
                if predicate(finding):
                    return True
        return False

    has_security_txt = any(result.status == 200 for result in results)
    valid_any = any(result.status == 200 and result.is_valid for result in results)
    machine_readable = has_security_txt and all(
        result.machine_readable for result in results if result.status == 200
    )
    expired = findings_any(lambda finding: finding.code == "expired")
    long_expiry = findings_any(lambda finding: finding.code == "long_validity")
    pgp = any(result.pgp_signed for result in results)
    pgp_errors = findings_any(lambda finding: finding.code.startswith("pgp"))

    return {
        "valid": valid_any,
        "security_txt": has_security_txt,
        "http_canonical_match": canonical_present(expected_apex_url),
        "www_canonical_match": canonical_present(expected_www_url),
        "expired": expired,
        "long_expiery": long_expiry,
        "pgp": pgp,
        "pgp_erros": pgp_errors,
        "machine_readable": machine_readable,
    }


def format_result(result: CheckResult) -> Iterable[str]:
    """Yield human-readable lines describing a check result."""

    header = f"{result.url} -> {result.status if result.status is not None else 'error'}"
    yield header

    if result.error and not (result.errors or result.recommendations or result.notifications):
        yield f"  Error: {result.error}"

    if result.status == 200:
        contact_msg = "found" if result.contact_present else "missing"
        yield f"  Contact: {contact_msg}"

        if result.final_url and _normalize_url_for_compare(result.final_url) != _normalize_url_for_compare(result.url):
            yield f"  Final URL: {result.final_url}"

        if result.expires is None:
            yield "  Expires: missing or unparsable"
        else:
            validity_msg = "ok" if result.expires_ok else "invalid range"
            yield f"  Expires: {result.expires.isoformat()} ({validity_msg})"

        if result.is_valid:
            yield "  Valid"
        elif not result.machine_readable:
            yield "  Not machine readable"

    for finding in result.errors or []:
        yield f"  Error[{finding.code}]: {finding.message}"

    for finding in result.recommendations or []:
        yield f"  Recommendation[{finding.code}]: {finding.message}"

    for finding in result.notifications or []:
        yield f"  Note[{finding.code}]: {finding.message}"


__all__ = [
    "CheckResult",
    "compute_flags",
    "check_domain",
    "check_url",
    "format_result",
    "normalize_domain",
    "is_hostname",
]
