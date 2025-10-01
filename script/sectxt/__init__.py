"""Lightweight security.txt parser inspired by DigitalTrustCenter/sectxt.

This module performs a subset of the validation rules and produces structured
findings that can be surfaced by the checker tooling.

Original project: https://github.com/DigitalTrustCenter/sectxt
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

ISO8601_VARIANTS = (
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S.%f%z",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
)
KNOWN_FIELDS = {
    "acknowledgments",
    "acknowledgements",
    "canonical",
    "contact",
    "encryption",
    "expires",
    "hiring",
    "policy",
    "preferred-languages",
    "csaf",
}
MAX_VALIDITY = timedelta(days=366)
EXPIRY_WARNING = timedelta(days=30)


@dataclass
class Finding:
    code: str
    message: str


@dataclass
class SecurityTxtReport:
    contacts: list[str]
    expires: datetime | None
    expires_ok: bool
    canonicals: list[str]
    pgp_signed: bool
    machine_readable: bool
    errors: list[Finding]
    recommendations: list[Finding]
    notifications: list[Finding]

    @property
    def is_valid(self) -> bool:
        return not self.errors and self.contacts and self.expires_ok


class SecurityTxtParser:
    """Parse a security.txt file into strongly-typed findings."""

    def __init__(self, content: str, now: datetime | None = None):
        self.content = content
        self.now = now or datetime.now(timezone.utc)

    def parse(self) -> SecurityTxtReport:
        contacts: list[str] = []
        canonicals: list[str] = []
        expires_value: datetime | None = None
        errors: list[Finding] = []
        recommendations: list[Finding] = []
        notifications: list[Finding] = []
        pgp_signed = False
        machine_readable = True

        lines = self.content.splitlines()

        in_signature = False
        saw_directive = False
        for line_number, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()

            if line.startswith("-----BEGIN PGP SIGNED MESSAGE-----"):
                pgp_signed = True
                notifications.append(
                    Finding(
                        "pgp_signed",
                        "security.txt is PGP signed; signature ignored for parsing",
                    )
                )
                continue

            if line.lower().startswith("hash:"):
                # Hash metadata belongs to the PGP armor header; ignore it.
                continue

            if line.startswith("-----BEGIN PGP SIGNATURE-----"):
                in_signature = True
                continue

            if line.startswith("-----END PGP SIGNATURE-----"):
                in_signature = False
                continue

            if in_signature:
                # Skip signature payload lines.
                continue

            if not line or ":" not in line:
                if line and line.startswith(("#", "//")):
                    continue
                if line:
                    notifications.append(
                        Finding("unparsable", f"Line {line_number} ignores unexpected content: {line}")
                    )
                continue

            field, value = line.split(":", 1)
            field = field.strip().lower()
            value = value.strip()
            saw_directive = True

            if not value:
                errors.append(Finding("empty_value", f"Line {line_number} for '{field}' has no value"))
                continue

            if field not in KNOWN_FIELDS:
                notifications.append(
                    Finding("unknown_field", f"Line {line_number} uses non-standard field '{field}'")
                )

            if field == "contact":
                contacts.append(value)
            elif field == "canonical":
                canonicals.append(value)
            elif field == "expires" and expires_value is None:
                parsed = self._parse_timestamp(value)
                if parsed is None:
                    errors.append(
                        Finding("invalid_expires", f"Line {line_number} has unparsable Expires '{value}'")
                    )
                else:
                    expires_value = parsed
            elif field == "preferred-languages":
                if "," in value and value.count(",") >= 5:
                    recommendations.append(
                        Finding(
                            "language_list",
                            f"Line {line_number} lists many languages; consider focusing on primary ones",
                        )
                    )

        expires_ok = False
        if expires_value is not None:
            delta = expires_value - self.now
            if delta < timedelta(0):
                errors.append(Finding("expired", "Expires directive is in the past"))
            elif delta > MAX_VALIDITY:
                errors.append(
                    Finding("long_validity", "Expires directive is more than one year in the future")
                )
            else:
                expires_ok = True
                if delta <= EXPIRY_WARNING:
                    recommendations.append(
                        Finding("expires_soon", "Expires directive is approaching; consider updating soon")
                    )
        else:
            errors.append(Finding("missing_expires", "Expires directive not found"))

        if not contacts:
            errors.append(Finding("missing_contact", "At least one Contact directive is required"))

        if not saw_directive:
            errors.append(
                Finding("not_machine_readable", "Response is not machine-readable security.txt content")
            )
            machine_readable = False

        return SecurityTxtReport(
            contacts=contacts,
            expires=expires_value,
            expires_ok=expires_ok,
            canonicals=canonicals,
            pgp_signed=pgp_signed,
            machine_readable=machine_readable,
            errors=errors,
            recommendations=recommendations,
            notifications=notifications,
        )

    def _parse_timestamp(self, value: str) -> datetime | None:
        remainder = value.strip()
        if remainder.endswith("Z"):
            remainder = remainder[:-1] + "+00:00"
        for fmt in ISO8601_VARIANTS:
            try:
                parsed = datetime.strptime(remainder, fmt)
            except ValueError:
                continue
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        return None


def analyze_security_txt(content: str, *, now: datetime | None = None) -> SecurityTxtReport:
    """Return a parsed report with findings for the supplied content."""

    parser = SecurityTxtParser(content, now=now)
    return parser.parse()


__all__ = ["Finding", "SecurityTxtReport", "SecurityTxtParser", "analyze_security_txt"]
