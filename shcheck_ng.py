#!/usr/bin/env python3

import subprocess
import re
import argparse
import requests
import os
import socket
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv
from urllib.parse import urlparse

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from rich.rule import Rule
from rich.columns import Columns

console = Console()

# ----------------------------
# ENV
# ----------------------------

load_dotenv()

ENV_AI_URL = os.getenv("AI_URL")
ENV_AI_MODEL = os.getenv("AI_MODEL")
SHODAN_KEY = os.getenv("SHODAN_API_KEY")

# ----------------------------
# Headers
# ----------------------------

SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
    "x-xss-protection"
]

RECOMMENDED_HEADERS = {
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-embedder-policy": "require-corp",
    "cross-origin-resource-policy": "same-origin",
    "x-frame-options": "DENY",
}

# ----------------------------
# Fetch headers (direct)
# ----------------------------

def get_headers_direct(url):
    res = subprocess.run(
        ["curl", "-k", "-s", "-D", "-", "-o", "/dev/null", url],
        capture_output=True,
        text=True
    )
    return (res.stdout or "").lower()

# ----------------------------
# Fetch headers (Shodan)
# ----------------------------

def get_headers_shodan(url):

    if not SHODAN_KEY:
        console.print("[yellow]No SHODAN_API_KEY found → fallback to direct scan[/yellow]")
        return None

    try:
        hostname = urlparse(url).hostname
        ip = socket.gethostbyname(hostname)

        console.print(f"[cyan]OSINT via Shodan → {hostname} ({ip})[/cyan]")

        r = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_KEY}",
            timeout=10
        )

        data = r.json()

        headers_raw = ""

        for entry in data.get("data", []):
            http = entry.get("http", {})
            headers = http.get("headers")
            if headers:
                for k, v in headers.items():
                    headers_raw += f"{k}: {v}\n"

        if headers_raw:
            return headers_raw.lower()

    except Exception as e:
        console.print(f"[yellow]Shodan error → fallback direct: {e}[/yellow]")

    return None

# ----------------------------
# Utilities
# ----------------------------
def show_tables(url, present, missing):

    console.print(
        Panel.fit(
            f"[bold cyan]SHCHECK-NG[/bold cyan]\n"
            f"Target → [bold]{url}[/bold]"
        )
    )

    present_table = Table(
        title="Present Headers",
        show_lines=True,
        expand=True
    )
    present_table.add_column("Header", style="cyan", no_wrap=True)
    present_table.add_column("Value", style="white")

    for h, v in present.items():
        present_table.add_row(h, v)

    if not present:
        present_table.add_row("-", "None")

    missing_table = Table(
        title="Missing Headers",
        show_lines=True,
        expand=True
    )
    missing_table.add_column("Header", style="red")

    for h in missing:
        missing_table.add_row(h)

    if not missing:
        missing_table.add_row("None")

    console.print(Columns([present_table, missing_table]))

def extract_header_value(raw, header):
    m = re.search(rf"{header}:(.*)", raw)
    return m.group(1).strip() if m else None


def extract_set_cookies(raw):
    return re.findall(r"^set-cookie:.*$", raw, flags=re.MULTILINE)


def cookie_flags_summary(cookies):
    result = []
    for i, c in enumerate(cookies, 1):
        result.append({
            "cookie": f"cookie #{i}",
            "secure": "secure" in c,
            "httponly": "httponly" in c,
            "samesite": "samesite" in c
        })
    return result


# ----------------------------
# Score
# ----------------------------

def calculate_score(present_count, total):
    score = int((present_count / total) * 100)

    if score < 40:
        level = "[red]LOW[/red]"
    elif score < 70:
        level = "[yellow]MEDIUM[/yellow]"
    elif score < 90:
        level = "[green]HIGH[/green]"
    else:
        level = "[bold green]HARDENED[/bold green]"

    bar_len = 30
    filled = int((score / 100) * bar_len)
    bar = "█" * filled + "░" * (bar_len - filled)

    return score, level, bar

# ----------------------------
# Config generation
# ----------------------------

def title_case(name):
    return "-".join(x.capitalize() for x in name.split("-"))


def generate_nginx_config(missing):
    return "\n".join(
        f'add_header {title_case(h)} "{RECOMMENDED_HEADERS[h]}" always;'
        for h in missing if h in RECOMMENDED_HEADERS
    )


def generate_apache_config(missing):
    return "\n".join(
        f'Header always set {title_case(h)} "{RECOMMENDED_HEADERS[h]}"'
        for h in missing if h in RECOMMENDED_HEADERS
    )

# ----------------------------
# AI
# ----------------------------

def detect_ai_backend(url):
    try:
        if requests.get(f"{url}/v1/models", timeout=3).ok:
            return "lmstudio"
    except:
        pass
    try:
        if requests.get(f"{url}/api/tags", timeout=3).ok:
            return "ollama"
    except:
        pass
    return None


def build_ai_prompt(url, present, missing, cookies):

    csp = present.get("content-security-policy", "NOT PRESENT")
    hsts = present.get("strict-transport-security", "NOT PRESENT")

    cookie_text = "\n".join(
        f"- {c['cookie']}: Secure={c['secure']}, HttpOnly={c['httponly']}, SameSite={c['samesite']}"
        for c in cookies
    ) or "- none"

    return f"""
You are a web security reviewer.

Hard rules:
- Do NOT mention penetration testing.
- Do NOT praise configuration.
- Be specific to this site.
- Quote exact header values from the observed data.
- Analyze CSP directive-by-directive if present.
- Evaluate HSTS max-age and subdomain coverage.
- Provide concrete header remediation lines.

Target: {url}

Observed headers:
{present}

Missing headers:
{missing}

Cookies:
{cookie_text}

CSP:
{csp}

HSTS:
{hsts}

Use headings:

## Findings
## Risks
## Remediation
"""


def ai_analysis(ai_url, model, url, present, missing, cookies):

    backend = detect_ai_backend(ai_url)
    if not backend:
        console.print("[red]AI backend not detected[/red]")
        return None

    console.print(Rule("[bold cyan]AI Security Analysis[/bold cyan]"))

    prompt = build_ai_prompt(url, present, missing, cookies)

    try:
        if backend == "ollama":
            r = requests.post(
                f"{ai_url}/api/generate",
                json={"model": model or "llama3", "prompt": prompt, "stream": False},
                timeout=180
            )
            content = r.json().get("response", "")
        else:
            r = requests.post(
                f"{ai_url}/v1/chat/completions",
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}]
                },
                timeout=180
            )
            content = r.json()["choices"][0]["message"]["content"]

        content = re.sub(r"(```.*?```)", r"\1\n", content, flags=re.S)
        console.print(Panel(Markdown(content)))
        return content

    except Exception as e:
        console.print(f"[red]AI error:[/red] {e}")
        return None

# ----------------------------
# HTML REPORT (with Markdown rendering)
# ----------------------------
def generate_html_report(url, present, missing, score, level, nginx_cfg, apache_cfg, ai_md):
    from datetime import datetime
    from pathlib import Path
    import re

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    level_plain = re.sub(r"\[/?[^\]]+\]", "", level)

    present_rows = "\n".join(
        f"<tr><td class='mono'>{k}</td><td class='mono'>{v}</td></tr>"
        for k, v in present.items()
    ) or "<tr><td colspan='2'>None</td></tr>"

    missing_list = "\n".join(
        f"<li>{m}</li>" for m in missing
    ) or "<li>None</li>"

    html = f"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Security Header Assessment</title>
<meta name="viewport" content="width=device-width, initial-scale=1">

<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/highlight.js@11.8.0/lib/common.min.js"></script>
<link rel="stylesheet"
href="https://cdn.jsdelivr.net/npm/highlight.js@11.8.0/styles/github.min.css">

<style>
body {{
    background:#f8fafc;
    color:#1f2937;
    font-family: system-ui, -apple-system, sans-serif;
}}

.card {{
    border:none;
    border-radius:14px;
    box-shadow:0 4px 20px rgba(0,0,0,.08);
}}

.mono {{
    font-family: monospace;
}}

pre {{
    background:#111827;
    color:#f9fafb;
    padding:16px;
    border-radius:10px;
    overflow-x:auto;
}}

.progress {{
    height:12px;
}}

.progress-bar {{
    background:#2563eb;
}}

.table thead th {{
    background:#eef2ff;
}}

h1,h2,h3,h4,h5 {{
    font-weight:600;
}}
</style>
</head>

<body class="py-5">

<div class="container">

<div class="mb-5">
<h1 class="h3">HTTP Security Header Assessment</h1>
<p class="text-muted mb-0">
Target: <span class="mono">{url}</span><br>
Generated: {now}
</p>
</div>

<div class="card p-4 mb-4">
<h5>Security Score</h5>
<div class="progress mb-2">
<div class="progress-bar" style="width:{score}%"></div>
</div>
<strong>{score}% — {level_plain}</strong>
</div>

<div class="row g-4 mb-4">

<div class="col-lg-7">
<div class="card p-4">
<h5>Present Headers</h5>
<table class="table table-striped mt-3">
<thead>
<tr><th>Header</th><th>Value</th></tr>
</thead>
<tbody>
{present_rows}
</tbody>
</table>
</div>
</div>

<div class="col-lg-5">
<div class="card p-4">
<h5>Missing Headers</h5>
<ul class="mt-3">
{missing_list}
</ul>
</div>
</div>

</div>

<div class="card p-4 mb-4">
<h5>AI Security Analysis</h5>
<div id="ai-content"></div>
</div>

<div class="card p-4">
<h5>Recommended Configuration</h5>

<h6 class="mt-3">Nginx</h6>
<pre><code>{nginx_cfg or "None"}</code></pre>

<h6 class="mt-4">Apache</h6>
<pre><code>{apache_cfg or "None"}</code></pre>
</div>

</div>

<script>
const md = `{ai_md.replace("`","\\`") if ai_md else "N/A"}`;
document.getElementById("ai-content").innerHTML = marked.parse(md);
hljs.highlightAll();
</script>

</body>
</html>
"""

    Path("shcheck_report.html").write_text(html, encoding="utf-8")
    print("HTML report generated → shcheck_report.html")
# ----------------------------
# MAIN
# ----------------------------

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument("--osint", action="store_true")
    parser.add_argument("--report", action="store_true")
    parser.add_argument("--ai")
    parser.add_argument("--ai-model")

    args = parser.parse_args()

    ai_url = args.ai or ENV_AI_URL
    ai_model = args.ai_model or ENV_AI_MODEL

    raw = None
    if args.osint:
        raw = get_headers_shodan(args.url)

    if not raw:
        raw = get_headers_direct(args.url)

    present = {
        h: extract_header_value(raw, h)
        for h in SECURITY_HEADERS
        if extract_header_value(raw, h)
    }

    missing = [h for h in SECURITY_HEADERS if h not in present]

    show_tables(args.url, present, missing)

    score, level, bar = calculate_score(len(present), len(SECURITY_HEADERS))
    console.print(f"\nSecurity Score → [{bar}] {score}% {level}\n")

    cookies = cookie_flags_summary(extract_set_cookies(raw))

    ai_text = None
    if ai_url:
        ai_text = ai_analysis(ai_url, ai_model, args.url, present, missing, cookies)

    nginx_cfg = generate_nginx_config(missing)
    apache_cfg = generate_apache_config(missing)

    console.print(Rule("[bold cyan]Suggested Configuration[/bold cyan]"))
    console.print("\n[bold]Nginx[/bold]")
    console.print(nginx_cfg or "None")
    console.print("\n[bold]Apache[/bold]")
    console.print(apache_cfg or "None")

    if args.report:
        generate_html_report(
            args.url,
            present,
            missing,
            score,
            level,
            nginx_cfg,
            apache_cfg,
            ai_text
        )

if __name__ == "__main__":
    main()
