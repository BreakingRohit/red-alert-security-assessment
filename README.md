# Red Alert – Security Assessment CLI

Red Alert is a **Python-based security assessment CLI tool** designed to assist in identifying **potential security risks** across exposed services and web applications.
The tool focuses on **assessment, risk awareness, and structured reporting**, not exploitation.

---

## Important Notice

This tool reports **potential findings only**.
All results **require manual validation**.
The tool does **not confirm exploitation** and does **not perform attacks**.

---

## Features

* Port detection to identify exposed attack surface
* Service enumeration with version identification (Nmap-based)
* CVE lookup with public exploit awareness (informational only)
* OWASP Top 10 behavioral checks
* Clean and summarized CLI output
* Detailed report generation (HTML, TXT, JSON)
* Reduced false positives through grouped detection logic
* Suitable for learning, assessments, and portfolio projects

---

## Assessment Flow

The tool follows a **real-world security assessment workflow**:

```
Port Detection
→ Service Enumeration
→ CVE & Risk Awareness
→ OWASP Top 10 Assessment
→ Executive Summary and Reporting
```

---

## Installation

### Requirements

* Python 3.8 or higher
* Nmap installed and accessible in system PATH

### Install dependencies

```bash
pip install -r requirements.txt
```

---

## Usage

### Basic OWASP assessment

```bash
python3 red_alert.py example.com --owasp
```

### Generate detailed HTML report

```bash
python3 red_alert.py example.com --owasp -o report.html -f html
```

### Note

The CLI displays a summarized view of the assessment.
For full technical details and evidence, enable the report option using `-o/--output`.

---

## Report Output

Supported formats:

* HTML (recommended)
* TXT
* JSON

Reports include:

* Executive summary
* Identified services and versions
* CVE overview (if applicable)
* Grouped OWASP findings
* Risk severity and confidence
* Manual validation guidance

---

## What This Tool Is and Is Not

### This tool is:

* A security assessment assistant
* A learning and portfolio project
* A risk awareness and reporting tool

### This tool is not:

* An exploitation framework
* A vulnerability confirmation tool
* A replacement for manual testing

---

## Ethics and Responsibility

Scan only systems you own or have explicit permission to test.
Unauthorized use is strictly prohibited.
The author is not responsible for misuse.

---

## Final Note

Red Alert is built to demonstrate **real-world security assessment thinking**,
with emphasis on **accuracy, clarity, and professional reporting** rather than noise or exploitation.

