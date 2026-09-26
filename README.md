# Subdomain Checker

A lightweight and improved Subfinder-style tool for validating subdomains and checking their HTTP/HTTPS status.

It takes a list of subdomains, determines whether each host is **LIVE or DEAD**, identifies HTTP status codes such as `200`, `403`, `404`, and `500`, explains the response, and exports the results to CSV.

> **For authorized security testing and bug-bounty programs only.**

## Features

* Check subdomains from a text file
* Enter subdomains manually
* Automatically checks HTTPS and falls back to HTTP
* Detects HTTP status codes
* Shows whether a host is LIVE or DEAD
* Explains HTTP responses
* Handles timeout, DNS, connection, and TLS errors
* Concurrent checking for faster results
* Clean terminal output
* CSV export

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/subdomain-checker.git
cd subdomain-checker
```

Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the dependency:

```bash
pip install requests
```

## Usage

### Check subdomains from a file

Create `subdomains.txt`:

```text
api.example.com
www.example.com
admin.example.com
dev.example.com
test.example.com
```

Run:

```bash
python3 subdomain_checker_clean.py -f subdomains.txt
```

### Enter subdomains manually

```bash
python3 subdomain_checker_clean.py
```

Enter one subdomain per line and press **Enter twice** when finished.

### Custom options

```bash
python3 subdomain_checker_clean.py -f subdomains.txt -w 10 -t 8 -o results.csv
```

| Option | Description                      |
| ------ | -------------------------------- |
| `-f`   | Input file containing subdomains |
| `-o`   | Output CSV filename              |
| `-w`   | Number of concurrent workers     |
| `-t`   | Request timeout                  |

## Example Output

```text
S.No  Subdomain                  Result    Why                  Live/Dead
---------------------------------------------------------------------------
1     api.example.com            200       OK                   LIVE
2     admin.example.com          403       Forbidden            LIVE
3     old.example.com            404       Not Found             LIVE
4     dev.example.com            -         Connection/DNS error DEAD
```

### What does LIVE mean?

A host is considered **LIVE** when it responds with an HTTP status code, including:

* `200` — OK
* `301/302` — Redirect
* `403` — Forbidden
* `404` — Not Found
* `500` — Server Error

A server returning `403` or `404` is still considered reachable.

### What does DEAD mean?

A host is marked **DEAD** when the tool cannot obtain an HTTP response because of issues such as:

* DNS failure
* Connection failure
* Timeout
* TLS/SSL failure

## CSV Output

Results are automatically saved as:

```text
subdomain_results.csv
```

The CSV contains:

```text
S.No
Subdomain
Result
Why
Live/Dead
```

## Workflow

```text
Subdomain List
      ↓
Clean & Deduplicate
      ↓
HTTPS Check
      ↓
HTTP Fallback
      ↓
HTTP Status Detection
      ↓
LIVE / DEAD Classification
      ↓
CSV Report
```

## Requirements

* Python 3.9+
* `requests`

## Legal Disclaimer

This tool is intended for authorized security testing, bug-bounty programs, and systems you have permission to test.

Do not use it against systems without authorization. The author is not responsible for misuse of this software.

## License

MIT License
