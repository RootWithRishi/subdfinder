#!/usr/bin/env python3
"""
Clean Subdomain HTTP Status Checker
For authorized security testing / bug-bounty programs only.

Output columns:
S.No | Subdomain | Result | Why | Live/Dead

Examples:
200 -> OK -> LIVE
403 -> Forbidden -> LIVE
404 -> Not Found -> LIVE
301 -> Redirect -> LIVE
500 -> Server Error -> LIVE
No response -> Connection/timeout/DNS error -> DEAD
"""

import argparse
import csv
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_TIMEOUT = 8
DEFAULT_WORKERS = 10
USER_AGENT = "Authorized-Bug-Bounty-Subdomain-Checker/2.0"


def clean_target(value):
    value = value.strip()

    if not value:
        return ""

    # Accept both:
    # example.com
    # https://example.com
    if "://" in value:
        parsed = urlparse(value)
        value = parsed.netloc or parsed.path

    # Remove paths/query strings if accidentally supplied.
    value = value.split("/")[0]
    return value.strip()


def read_targets(file_path):
    if file_path:
        path = Path(file_path)

        if not path.is_file():
            raise FileNotFoundError(f"File not found: {path}")

        lines = path.read_text(
            encoding="utf-8",
            errors="ignore"
        ).splitlines()

        targets = [clean_target(line) for line in lines if line.strip()]

    else:
        print("Enter subdomains, one per line.")
        print("Press ENTER on an empty line when finished.\n")

        targets = []

        while True:
            try:
                value = input("> ").strip()
            except EOFError:
                break

            if not value:
                break

            target = clean_target(value)

            if target:
                targets.append(target)

    # Remove duplicates while preserving order.
    return list(dict.fromkeys(targets))


def reason_for_status(status):
    reasons = {
        200: "OK",
        201: "Created",
        202: "Accepted",
        204: "No Content",

        301: "Permanent Redirect",
        302: "Temporary Redirect",
        303: "See Other",
        307: "Temporary Redirect",
        308: "Permanent Redirect",

        400: "Bad Request",
        401: "Unauthorized",
        402: "Payment Required",
        403: "Forbidden",
        404: "Not Found",
        405: "Method Not Allowed",
        406: "Not Acceptable",
        407: "Proxy Authentication Required",
        408: "Request Timeout",
        409: "Conflict",
        410: "Gone",
        411: "Length Required",
        412: "Precondition Failed",
        413: "Payload Too Large",
        414: "URI Too Long",
        415: "Unsupported Media Type",
        416: "Range Not Satisfiable",
        417: "Expectation Failed",
        418: "I'm a Teapot",
        422: "Unprocessable Content",
        423: "Locked",
        424: "Failed Dependency",
        429: "Too Many Requests",

        500: "Internal Server Error",
        501: "Not Implemented",
        502: "Bad Gateway",
        503: "Service Unavailable",
        504: "Gateway Timeout",
        505: "HTTP Version Not Supported",
    }

    if status in reasons:
        return reasons[status]

    if 200 <= status < 300:
        return "Success"

    if 300 <= status < 400:
        return "Redirect"

    if 400 <= status < 500:
        return "Client Error"

    if 500 <= status < 600:
        return "Server Error"

    return "HTTP Response"


def check_url(session, url, timeout):
    try:
        response = session.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=False,
            stream=True,
        )

        status = response.status_code
        response.close()

        return {
            "status": status,
            "reason": reason_for_status(status),
            "live": "LIVE",
        }

    except requests.exceptions.Timeout:
        return {
            "status": "",
            "reason": "Request timed out",
            "live": "DEAD",
        }

    except requests.exceptions.SSLError:
        return {
            "status": "",
            "reason": "TLS/SSL error",
            "live": "DEAD",
        }

    except requests.exceptions.ConnectionError:
        return {
            "status": "",
            "reason": "Connection/DNS error",
            "live": "DEAD",
        }

    except requests.exceptions.RequestException:
        return {
            "status": "",
            "reason": "Request error",
            "live": "DEAD",
        }


def check_target(target, timeout):
    session = requests.Session()
    session.headers.update({
        "User-Agent": USER_AGENT
    })

    # HTTPS first.
    https = check_url(
        session,
        f"https://{target}",
        timeout
    )

    if https["live"] == "LIVE":
        return {
            "target": target,
            "result": https["status"],
            "reason": https["reason"],
            "live": "LIVE",
        }

    # If HTTPS fails, try HTTP.
    http = check_url(
        session,
        f"http://{target}",
        timeout
    )

    if http["live"] == "LIVE":
        return {
            "target": target,
            "result": http["status"],
            "reason": http["reason"],
            "live": "LIVE",
        }

    return {
        "target": target,
        "result": "-",
        "reason": http["reason"],
        "live": "DEAD",
    }


def print_header():
    print()
    print(
        f"{'S.No':<6}"
        f"{'Subdomain':<45}"
        f"{'Result':<10}"
        f"{'Why':<30}"
        f"{'Live/Dead':<10}"
    )
    print("-" * 101)


def print_result(number, result):
    target = result["target"]

    # Keep table readable for very long hostnames.
    if len(target) > 42:
        target = target[:39] + "..."

    print(
        f"{number:<6}"
        f"{target:<45}"
        f"{str(result['result']):<10}"
        f"{result['reason']:<30}"
        f"{result['live']:<10}"
    )


def save_csv(results, output):
    fields = [
        "S.No",
        "Subdomain",
        "Result",
        "Why",
        "Live/Dead",
    ]

    with open(
        output,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)
        writer.writerow(fields)

        for number, result in enumerate(results, 1):
            writer.writerow([
                number,
                result["target"],
                result["result"],
                result["reason"],
                result["live"],
            ])


def main():
    parser = argparse.ArgumentParser(
        description="Clean subdomain HTTP status checker."
    )

    parser.add_argument(
        "-f",
        "--file",
        help="Text file containing one subdomain per line."
    )

    parser.add_argument(
        "-o",
        "--output",
        default="subdomain_results.csv",
        help="CSV output file."
    )

    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help="Number of concurrent requests."
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help="Timeout per request in seconds."
    )

    args = parser.parse_args()

    if args.workers < 1:
        parser.error("--workers must be at least 1")

    if args.timeout < 1:
        parser.error("--timeout must be at least 1")

    try:
        targets = read_targets(args.file)

    except (OSError, FileNotFoundError) as error:
        print(f"\nError: {error}")
        return 1

    if not targets:
        print("\nNo subdomains supplied.")
        return 1

    print()
    print("=" * 101)
    print("             SUBDOMAIN HTTP STATUS CHECKER")
    print("=" * 101)
    print(f"Targets : {len(targets)}")
    print(f"Workers : {args.workers}")
    print(f"Timeout : {args.timeout}s")

    print_header()

    results = []

    with ThreadPoolExecutor(
        max_workers=args.workers
    ) as executor:

        future_map = {
            executor.submit(
                check_target,
                target,
                args.timeout
            ): target

            for target in targets
        }

        for number, future in enumerate(
            as_completed(future_map),
            1
        ):
            target = future_map[future]

            try:
                result = future.result()

            except Exception as error:
                result = {
                    "target": target,
                    "result": "-",
                    "reason": "Unexpected error",
                    "live": "DEAD",
                }

            results.append(result)

            # Temporary live output.
            print_result(number, result)

    # Restore original input order for CSV.
    order = {
        target: index
        for index, target in enumerate(targets)
    }

    results.sort(
        key=lambda item: order.get(
            item["target"],
            999999
        )
    )

    save_csv(results, args.output)

    live_count = sum(
        1 for result in results
        if result["live"] == "LIVE"
    )

    dead_count = len(results) - live_count

    print()
    print("=" * 101)
    print(f"Total : {len(results)}")
    print(f"Live  : {live_count}")
    print(f"Dead  : {dead_count}")
    print(f"CSV   : {args.output}")
    print("=" * 101)

    return 0


if __name__ == "__main__":
    sys.exit(main())
