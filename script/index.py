"""Batch security.txt checker for domains listed in input.csv."""

from __future__ import annotations

import csv
import sys
from pathlib import Path

from security_txt_checker import CheckResult, check_domain, compute_flags, format_result

INPUT_FILE = Path(__file__).with_name("input.csv")
OUTPUT_FILE = Path(__file__).with_name("output.csv")
FIELDNAMES = [
    "domain",
    "security txt",
    "valid",
    "http canonical",
    "www canonical",
    "expired",
    "long expiery",
    "pgp",
    "pgp erros",
    "errors",
    "recommendations",
    "notifications",
]


def iter_domains(path: Path) -> list[str]:
    """Load domain names from a CSV file."""

    if not path.exists():
        return []

    domains: list[str] = []

    with path.open(newline="", encoding="utf-8") as handle:
        # Try header-aware parsing first so users get a labeled column.
        reader = csv.DictReader(handle)
        fieldnames = [name.lower() for name in reader.fieldnames or []]
        domain_key = None
        if "domain" in fieldnames and reader.fieldnames is not None:
            domain_key = reader.fieldnames[fieldnames.index("domain")]

        if domain_key is not None:
            # DictReader consumed the header; process each row via the resolved key.
            for row in reader:
                value = (row.get(domain_key) or "").strip()
                if value:
                    domains.append(value)
        else:
            # Fallback: treat the file as a plain single-column CSV without headers.
            handle.seek(0)
            simple_reader = csv.reader(handle)
            header_markers = {"domain", "domains"}
            for row in simple_reader:
                if not row:
                    continue
                candidate = row[0].strip()
                if not candidate or candidate.lower() in header_markers:
                    continue
                domains.append(candidate)

    return domains


def print_results(domain: str, results: list[CheckResult]) -> None:
    """Pretty-print the results for a single domain."""

    print(f"=== {domain} ===")
    if not results:
        print("No URLs generated for this domain.")
        return

    for result in results:
        # Each result yields several formatted lines; forward them verbatim.
        for line in format_result(result):
            print(line)


def summarize_domain(domain: str, results: list[CheckResult]) -> dict[str, object]:
    """Produce a CSV-friendly summary for a domain."""

    apex_result = next((item for item in results if "://www." not in item.url), None)

    def collect(findings_attr: str) -> str:
        """Collect unique finding messages, ignoring www.* URLs."""

        sources = [apex_result] if apex_result is not None else []
        if not sources:
            sources = results

        messages: list[str] = []
        for item in sources:
            if item is None:
                continue
            for finding in getattr(item, findings_attr) or []:
                entry = f"{finding.code}: {finding.message}"
                if entry not in messages:
                    messages.append(entry)
        return "; ".join(messages)

    if apex_result is None and results:
        apex_result = results[0]

    flags = compute_flags(results)

    return {
        "domain": domain,
        "valid": bool(flags.get("valid", False)),
        "security txt": bool(flags.get("security_txt", False)),
        "http canonical": bool(flags.get("http_canonical", False)),
        "www canonical": bool(flags.get("www_canonical", False)),
        "expired": bool(flags.get("expired", False)),
        "long expiery": bool(flags.get("long_expiery", False)),
        "pgp": bool(flags.get("pgp", False)),
        "pgp erros": bool(flags.get("pgp_erros", False)),
        "errors": collect("errors"),
        "recommendations": collect("recommendations"),
        "notifications": collect("notifications"),
    }


def ensure_output_file() -> None:
    """Ensure output.csv exists with the expected header."""

    header_matches = False
    if OUTPUT_FILE.exists() and OUTPUT_FILE.stat().st_size > 0:
        with OUTPUT_FILE.open(newline="", encoding="utf-8") as handle:
            reader = csv.reader(handle)
            existing_header = next(reader, [])
            header_matches = existing_header == FIELDNAMES

    if not header_matches:
        with OUTPUT_FILE.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
            writer.writeheader()


def append_row(row: dict[str, object]) -> None:
    """Append a row to output.csv, assuming header already exists."""

    with OUTPUT_FILE.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
        writer.writerow(row)


def main() -> int:
    domains = iter_domains(INPUT_FILE)
    if not domains:
        print(f"No domains found in {INPUT_FILE}")
        ensure_output_file()
        return 1

    ensure_output_file()

    for domain in domains:
        # Run both apex and www targets for each domain and show the outcome.
        results = check_domain(domain)
        print_results(domain, results)
        append_row(summarize_domain(domain, results))

    return 0


if __name__ == "__main__":
    sys.exit(main())
