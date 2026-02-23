# SHCheck-NG

Modern HTTP Security Header Analyzer with AI insights, OSINT support and professional reporting.

---

## Overview

SHCheck-NG is a lightweight security tool designed to analyze HTTP response headers and quickly evaluate the security posture of a web service.

It provides:

- Security header detection
- Missing header identification
- Cookie flag analysis
- Automatic server configuration suggestions
- AI-assisted contextual analysis
- Passive OSINT mode via Shodan
- Professional HTML report generation

This tool focuses specifically on HTTP security headers and related configuration.

---

## Features

### Header Analysis

Checks modern security headers including:

- Content-Security-Policy
- Strict-Transport-Security
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- COOP / COEP / CORP
- Cookie security attributes

---

### AI Security Interpretation (Optional)

Supports local AI endpoints:

- Ollama
- LM Studio
- OpenAI-compatible APIs

Provides contextual analysis based on actual header values and configuration.

---

### Passive OSINT Mode

Using `--osint`:

- Retrieves HTTP header intelligence from Shodan
- Avoids direct requests to the target
- Automatically falls back to active scan if data unavailable

Requires:

```
SHODAN_API_KEY=your_key_here
```

in `.env`.

---

### Professional HTML Reporting

The generated report includes:

- Security score visualization
- Header tables
- AI-generated contextual analysis
- Configuration remediation snippets
- Clean professional layout

---

## Installation

Clone repository:

```
git clone https://github.com/YOUR_USERNAME/shcheck-ng.git
cd shcheck-ng
```

Install dependencies:

```
pip install -r requirements.txt
```

---

## Optional Configuration (.env)

Example:

```
AI_URL=http://localhost:1234
AI_MODEL=openai-gpt-oss-20b
SHODAN_API_KEY=your_key_here
```

All optional.

---

## Usage

### Basic scan

```
python shcheck_ng.py https://example.com
```

### Generate HTML report

```
python shcheck_ng.py https://example.com --report
```

### AI analysis

```
python shcheck_ng.py https://example.com --ai http://localhost:1234
```

or automatically via `.env`.

### Passive OSINT mode

```
python shcheck_ng.py https://example.com --osint
```

---

## Scope

This tool evaluates HTTP security header posture.

It does not perform vulnerability scanning or application testing.

---

## Requirements

Python 3.9+

Dependencies:

- rich
- requests
- python-dotenv

---

## License

MIT License.

---

## Contributions

Contributions are welcome:

- Header analysis improvements
- Additional OSINT providers
- Report enhancements
- Packaging and automation

---

If this project helps you, consider starring the repository.
