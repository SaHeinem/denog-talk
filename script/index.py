"""Batch security.txt checker for domains listed in input.csv."""

from __future__ import annotations

import csv
import sys
from pathlib import Path

from security_txt_checker import CheckResult, check_domain, format_result

INPUT_FILE = Path(__file__).with_name("input.csv")
OUTPUT_FILE = Path(__file__).with_name("output.csv")
FIELDNAMES = [
    "domain",
    "valid_apex",
    "valid_www",
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


def summarize_domain(domain: str, results: list[CheckResult]) -> dict[str, str]:
    """Produce a CSV-friendly summary for a domain."""

    apex_result = next((item for item in results if "://www." not in item.url), None)
    www_result = next((item for item in results if "://www." in item.url), None)

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

    apex_valid = (
        "yes"
        if apex_result and apex_result.status == 200 and apex_result.is_valid
        else "no"
    )
    www_valid = (
        "yes"
        if www_result and www_result.status == 200 and www_result.is_valid
        else "no"
    )

    return {
        "domain": domain,
        "valid_apex": apex_valid,
        "valid_www": www_valid,
        "errors": collect("errors"),
        "recommendations": collect("recommendations"),
        "notifications": collect("notifications"),
    }


def ensure_output_file() -> None:
    """Create output.csv with header if needed."""

    needs_header = True
    if OUTPUT_FILE.exists():
        needs_header = OUTPUT_FILE.stat().st_size == 0

    if needs_header:
        with OUTPUT_FILE.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
            writer.writeheader()


def append_row(row: dict[str, str]) -> None:
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
