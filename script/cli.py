"""Interactive command-line entry point for the security.txt checker."""

from __future__ import annotations

import sys

from security_txt_checker import (
    CheckResult,
    compute_flags,
    check_domain,
    format_result,
    normalize_domain,
)


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
    flags = compute_flags(results)

    apex_result = next((item for item in results if "://www." not in item.url), None)
    primary_result = apex_result if apex_result is not None else (results[0] if results else None)
    www_result = next((item for item in results if "://www." in item.url), None)

    has_security_txt = bool(flags.get("security_txt", False))
    machine_readable = bool(flags.get("machine_readable", False))
    valid_flag = bool(flags.get("valid", False))

    if has_security_txt and not machine_readable:
        valid_value: object = "not machine readable"
    else:
        valid_value = valid_flag

    def status_value(result: CheckResult | None) -> str:
        if result is None or result.status is None:
            return ""
        return str(result.status)

    def canonical_value(result: CheckResult | None) -> str:
        if result is None or result.report is None or not result.report.canonicals:
            return "missing"
        canonicals: list[str] = []
        for candidate in result.report.canonicals:
            if candidate not in canonicals:
                canonicals.append(candidate)
        return "; ".join(canonicals) if canonicals else "missing"

    def collect(findings_attr: str) -> str:
        sources = [primary_result] if primary_result is not None else []
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

    def mark(value: bool) -> str:
        return "[x]" if value else "[ ]"

    print(f"  security txt: {mark(has_security_txt)}")
    if isinstance(valid_value, str):
        print(f"  valid: {valid_value}")
    else:
        print(f"  valid: {mark(bool(valid_value))}")
    print(f"  http status: {status_value(apex_result)}")
    print(f"  www status: {status_value(www_result)}")
    print(f"  http canonical: {canonical_value(apex_result)}")
    print(f"  www canonical: {canonical_value(www_result)}")
    print(f"  http canonical match: {mark(bool(flags.get('http_canonical_match', False)))}")
    print(f"  www canonical match: {mark(bool(flags.get('www_canonical_match', False)))}")
    print(f"  expired: {mark(bool(flags.get('expired', False)))}")
    print(f"  long expiery: {mark(bool(flags.get('long_expiery', False)))}")
    print(f"  pgp: {mark(bool(flags.get('pgp', False)))}")
    print(f"  pgp errors: {mark(bool(flags.get('pgp_erros', False)))}")

    errors_summary = collect("errors")
    recommendations_summary = collect("recommendations")
    notifications_summary = collect("notifications")

    print(f"  errors: {errors_summary}")
    print(f"  recommendations: {recommendations_summary}")
    print(f"  notifications: {notifications_summary}")

    for result in results:
        for line in format_result(result):
            print(line)

    return 0


if __name__ == "__main__":
    sys.exit(main())
