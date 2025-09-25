"""Batch security.txt checker for domains listed in input.csv."""

from __future__ import annotations

import csv
import sys
from pathlib import Path

from security_txt_checker import CheckResult, check_domain, format_result

INPUT_FILE = Path(__file__).with_name("input.csv")


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


def main() -> int:
    domains = iter_domains(INPUT_FILE)
    if not domains:
        print(f"No domains found in {INPUT_FILE}")
        return 1

    for domain in domains:
        # Run both apex and www targets for each domain and show the outcome.
        results = check_domain(domain)
        print_results(domain, results)

    return 0


if __name__ == "__main__":
    sys.exit(main())
