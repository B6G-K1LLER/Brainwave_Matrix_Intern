# PhishDetect URL Analysis Tool

This tool analyzes URLs to detect phishing threats by examining various features and patterns commonly associated with phishing attempts. The tool uses professional table formatting and color-coded results to provide a comprehensive and user-friendly analysis.

## Features

- **IP Address Check**: Detects if a URL contains an IP address instead of a domain name, which is often a sign of malicious activity.
- **At Sign (@)**: Flags URLs containing the "@" symbol, commonly used to bypass filters and confuse users in phishing schemes.
- **URL Length**: Identifies URLs that are unusually long (>= 54 characters), which may indicate obfuscation or deception.
- **URL Depth**: Examines the number of slashes ("/") in the URL path to identify complex, potentially suspicious structures.
- **Redirection**: Flags URLs containing multiple `//` to identify deceptive redirects that might hide the actual destination.
- **HTTPS in Domain**: Checks if the URL contains "https" in the domain, helping verify if the connection is encrypted and secure.
- **Shortened URLs**: Detects the use of URL shorteners, which are often employed to obscure the destination URL in phishing attacks.
- **Prefix/Suffix ("-")**: Flags domains containing hyphens, which are frequently used in fraudulent URLs to mimic legitimate sites.
- **Phishing Keywords**: Searches for common phishing-related keywords like "login", "verify", "secure", and "update" in the URL.
- **Suspicious Patterns**: Identifies URLs with suspicious patterns such as multiple subdomains or IP addresses, often seen in phishing schemes.

## Getting Started

### Prerequisites

Make sure you have the following installed:
- Python 3.6 or higher
- `colorama` library for colored output
- `tabulate` library for table formatting

To install the required libraries, run:

```bash
pip install colorama tabulate
```

### Usage

1. **Single URL Analysis**:
   - Choose option `1` to analyze a single URL.
   - Input the URL you want to analyze and get a detailed report on its safety.

2. **Batch File Analysis**:
   - Choose option `2` to analyze a list of URLs from a file.
   - Ensure the file contains one URL per line, and provide the path to the file.

---

⚠️ **Notice**: While this tool is designed to detect phishing URLs, it may occasionally produce false positives or miss certain phishing attempts. Always verify results with additional checks.

---
