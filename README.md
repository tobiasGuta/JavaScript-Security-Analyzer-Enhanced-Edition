# JavaScript Security Analyzer (Enhanced Edition)

> **Note:** This is a modified version of the original [JS-Analyser](https://github.com/zack0x01/JS-Analyser) by [zack0x01](https://github.com/zack0x01). This version includes enhanced features for WAF evasion, local file analysis, and improved reporting.

A powerful, modern web application and CLI tool for analyzing JavaScript files to detect sensitive data, security vulnerabilities, and potential attack vectors. Perfect for bug bounty hunters, security researchers, and developers.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-3.0+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## New Features in This Version

- **WAF Evasion**: Advanced options to bypass Cloudflare/WAFs using custom headers, cookies, and proxies.
- **Local File Analysis**: Analyze `.js` files directly from your computer (no URL required).
- **Export Results**: Download full analysis reports in JSON format.
- **Unified CLI**: The command-line tool (`js_analyzer.py`) now has parity with the web app, supporting all advanced features.
- **Enhanced Detection**: Improved regex patterns for emails, parameters, and dangerous functions.

## Core Capabilities

- **Security Detection**:
  - **API Keys**: AWS, Google, GitHub, Stripe, PayPal, Slack, Firebase, JWT, etc.
  - **Credentials**: Hardcoded passwords, usernames, database strings.
  - **XSS Vulnerabilities**: `innerHTML`, `document.write()`, `eval()`, `dangerouslySetInnerHTML`.
- **Reconnaissance**:
  - **API Discovery**: Extracts endpoints from `fetch`, `axios`, `jQuery`.
  - **Parameter Analysis**: Finds URL query parameters and function arguments.
  - **Path Discovery**: Extracts file paths and directory structures.
- **Code Analysis**:
  - **Comments**: Extracts TODOs, FIXMEs, and security-related comments.
  - **Emails**: Scrapes email addresses found in the code.

## Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Setup

1. **Clone the repository**
```bash
git clone https://github.com/tobiasGuta/JavaScript-Security-Analyzer-Enhanced-Edition-.git
cd JS-Analyser
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

## Usage

### Web Interface

1. **Start the application**
```bash
python3 app.py
```

2. **Open your browser**
Navigate to `http://127.0.0.1:5000`

3. **Analyze Targets**
   - **Single/Multiple URLs**: Paste links to JS files.
   - **Local File**: Upload a `.js` file from your disk.
   - **Advanced Options**: Click the gear icon to configure:
     - **Custom Headers**: Bypass bot protection (e.g., `{"User-Agent": "MyBot"}`).
     - **Cookies**: Authenticate requests.
     - **Proxy**: Route traffic through Burp Suite or Tor (e.g., `http://127.0.0.1:8080`).

4. **Export**: Click "Export JSON" to save your findings.

### Command Line Interface (CLI)

The `js_analyzer.py` tool allows you to run scans from the terminal with full feature support.

**Basic Scan:**
```bash
python3 js_analyzer.py https://example.com/app.js
```

**Scan with WAF Evasion (Proxy & Headers):**
```bash
python3 js_analyzer.py https://example.com/app.js \
  --proxy "http://127.0.0.1:8080" \
  --headers '{"Authorization": "Bearer token"}'
```

**Scan a Local List of URLs:**
```bash
python3 js_analyzer.py -f urls.txt -o results.json
```

**CLI Arguments:**
- `urls`: One or more URLs to analyze.
- `-f, --file`: File containing a list of URLs.
- `-o, --output`: Save results to a JSON file.
- `--headers`: JSON string of custom headers.
- `--cookies`: JSON string of custom cookies.
- `--proxy`: Proxy URL (HTTP/HTTPS).
- `--no-color`: Disable colored output.

## Use Cases

- **Bug Bounty Hunting**: Quickly scan assets for leaked keys and endpoints, even behind WAFs.
- **Security Audits**: Review local build artifacts before deployment.
- **Penetration Testing**: Map out API structures and find hidden parameters.

## Technical Details

- **Backend**: Flask (Python) - All analysis happens server-side.
- **Analysis Engine**: Regex-based pattern matching with context awareness.
- **Security**: Input validation, server-side processing, and safe file handling.

## Disclaimer

This tool is for **authorized security testing and educational purposes only**. Only use this tool on systems you own or have explicit permission to test. Unauthorized access to computer systems is illegal.

---

**Original Author:** [Zack0X01](https://github.com/zack0X01)

**Modified By:** TobiasGuta
