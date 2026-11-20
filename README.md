
# VulnScan Lite – Web Vulnerability Scanner

## Project Overview

VulnScan Lite is a lightweight web security assessment tool developed using Python and Flask.

It helps users identify common website security configuration weaknesses through non-intrusive HTTP checks and generates PDF security assessment reports.

## Features

- Website URL validation
- HTTP and HTTPS assessment
- Security header analysis
- SSL/HTTPS status checking
- Cookie security attribute checking
- Server information disclosure detection
- Vulnerability identification
- Security score calculation
- Risk classification
- SQLite scan history
- Interactive security dashboard
- PDF report generation

## Technologies Used

- Python
- Flask
- HTML5
- CSS3
- JavaScript
- SQLite
- Requests
- ReportLab
- Pytest

## Project Structure

```text
VulnScan-Lite/
│
├── app.py
├── config.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── scanner/
│   ├── __init__.py
│   ├── engine.py
│   ├── headers.py
│   ├── ssl_checker.py
│   ├── vulnerability_checks.py
│   ├── risk_assessment.py
│   ├── database.py
│   └── report_generator.py
│
├── templates/
│   ├── index.html
│   ├── dashboard.html
│   ├── results.html
│   └── history.html
│
├── static/
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── script.js
│
├── reports/
│
└── tests/
    ├── test_scanner.py
    └── test_report.py
```

## Installation

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd VulnScan-Lite
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

### 3. Activate the environment

Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

### 5. Run the application

```bash
python app.py
```

Open your browser:

http://127.0.0.1:5000

## Run Tests

```bash
python -m pytest -v
```

## Security and Ethical Use

This tool is intended for educational purposes and authorized security assessments only.

- Scan only websites you own or have explicit permission to assess.
- Do not use the tool for unauthorized testing.
- The scanner performs lightweight checks and does not guarantee complete vulnerability detection.

## Project Status

Developed as a Cyber Security project for the Persevex internship.

## Author

Vinayak Bahadur
