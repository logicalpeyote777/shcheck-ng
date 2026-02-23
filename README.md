# SHCheck-NG

Modern HTTP Security Header Analyzer with AI insights, OSINT support and professional HTML reporting.

---

## Features

- Security header detection (modern + legacy)
- Missing header identification
- Cookie security analysis
- AI contextual security analysis (Ollama / LMStudio / OpenAI-compatible APIs)
- Optional OSINT mode via Shodan
- Automatic Nginx / Apache header recommendations
- Professional HTML report generation
- Clean CLI output with rich tables

---

## Installation

### ⭐ Recommended (pipx — safest)

This installs the tool globally but isolated:

```bash
brew install pipx   # macOS
pipx ensurepath
pipx install shcheck-ng
```

Then simply:

```bash
shcheck-ng https://example.com
```

---

### Development install

Clone repo:

```bash
git clone https://github.com/logicalpeyote777/shcheck-ng.git
cd shcheck-ng
```

Create venv:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install:

```bash
pip install -e .
```

---

### Basic pip install (not recommended globally)

```bash
pip install .
```

Use pipx instead if unsure.

---

## Configuration (.env file)

SHCheck-NG supports environment configuration via `.env`.

### Where to place `.env`

Preferred locations:

1. **Directory where you run the command**

```
project/
├── .env
└── your-scan-command
```

2. Or system environment variables (recommended for production).

---

### Example `.env`

```env
AI_URL=http://localhost:1234
AI_MODEL=openai-gpt-oss-20b
SHODAN_API_KEY=your_shodan_api_key_here
```

---

## Environment Variables (alternative to .env)

You can also export variables:

```bash
export AI_URL=http://localhost:1234
export AI_MODEL=llama3
export SHODAN_API_KEY=xxx
```

Then run normally:

```bash
shcheck-ng https://example.com
```

Priority order:

```
CLI flags > Environment variables > .env > defaults
```

---

## Usage

### Basic scan

```bash
shcheck-ng https://example.com
```

### Generate HTML report

```bash
shcheck-ng https://example.com --report
```

### Enable AI analysis

```bash
shcheck-ng https://example.com --ai
```

(Uses `.env` automatically if present.)

---

### OSINT passive mode (Shodan)

```bash
shcheck-ng https://example.com --osint
```

Requires:

```
SHODAN_API_KEY
```

---

## Output

The tool provides:

- Header presence tables
- Security scoring
- AI remediation analysis
- Suggested server configs
- Optional HTML professional report

---

## Scope

This tool evaluates HTTP security header posture only.

It does NOT perform:

- penetration testing
- vulnerability exploitation
- application security testing

---

## Requirements

Python 3.9+

Dependencies handled automatically.

---

## Best Practice Recommendation

For CLI security tools:

- Use `pipx` installation
- Use environment variables for automation
- Avoid system Python modifications

---

## License

MIT License.

---

If this tool helps you:

⭐ Star the repo on GitHub.
