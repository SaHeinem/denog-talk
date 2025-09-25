"""Interactive command-line entry point for the security.txt checker."""

from __future__ import annotations

import sys

from security_txt_checker import check_domain, format_result, normalize_domain


PROMPT = "Enter domain (e.g. example.com): "


def main() -> int:
    try:
        user_input = input(PROMPT)
    except EOFError:
        print("No input provided.")
        return 1

    domain = normalize_domain(user_input)
    if not domain:
        print("No valid domain entered.")
        return 1

    results = check_domain(domain)
    if not results:
        # normalize_domain can return an empty string for invalid input.
        print("No URLs generated for this domain.")
        return 1

    print(f"=== {domain} ===")
    for result in results:
        for line in format_result(result):
            print(line)

    return 0


if __name__ == "__main__":
    sys.exit(main())
