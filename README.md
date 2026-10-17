# Vulnerability Triage CLI

A Python command-line tool that gathers public vulnerability intelligence for a CVE and produces a prioritisation assessment based on vulnerability severity, known exploitation, exploitation probability, and asset context.

This is a triage aid, not a replacement for a security team's risk assessment or official remediation guidance.

## Features

- Retrieves vulnerability information from the NVD CVE API.
- Checks whether a CVE appears in CISA's Known Exploited Vulnerabilities (KEV) catalogue.
- Retrieves Exploit Prediction Scoring System (EPSS) data from FIRST.
- Calculates a triage priority using vulnerability data and supplied asset context.
- Supports internet exposure, asset criticality, and confirmation of the affected version.
- Generates Markdown reports and supports JSON output.
- Optionally generates an AI-written advisory using a locally running Ollama model.
- Includes automated tests.

## Technology

- Python 3
- Python standard library
- NVD CVE API
- CISA KEV catalogue
- FIRST EPSS
- Optional: Ollama for locally generated AI advisories

The core workflow does not require Ollama.

## Requirements

- Python 3.10 or newer recommended.
- Internet access to retrieve public vulnerability data.
- Ollama and a locally downloaded model only if you use the AI advisory feature.

## Installation

### 1. Clone the repository

    git clone https://github.com/hazard4321/vuln-triage.git
    cd vuln-triage

### 2. Create and activate a virtual environment

    python3 -m venv .venv
    source .venv/bin/activate

If Python's virtual environment support is missing on Ubuntu, install it with:

    sudo apt update
    sudo apt install python3-venv

### 3. Run the application

The core application uses only the Python standard library, so no additional Python packages are required.

    python cli.py --help
    python cli.py CVE-2024-3400

### 4. Run the tests

    python -m unittest discover -s tests -v

### 5. Optional: Enable AI-generated advisories

The AI advisory feature requires Ollama to be installed and running locally, with the configured model available.

The default model configured in `advisory_ai.py` is `llama3.2:3b`.

After setting up Ollama and downloading the model, verify that the model is available:

    ollama list

Then run:

    python cli.py CVE-2024-3400 --ai-advisory

The AI feature is optional; the core vulnerability triage workflow works without it.

## Quick start

Assess a CVE:

    python cli.py CVE-2024-3400

View the available command-line options:

    python cli.py --help

## Usage examples

Assess an internet-facing asset:

    python cli.py CVE-2024-3400 --internet-facing

Set the asset criticality to critical:

    python cli.py CVE-2024-3400 --asset-criticality critical

Confirm that the affected version is present:

    python cli.py CVE-2024-3400 --affected-version-confirmed

Combine asset-context options:

    python cli.py CVE-2024-3400 --internet-facing --asset-criticality critical --affected-version-confirmed

Request JSON output:

    python cli.py CVE-2024-3400 --json

Generate an optional AI advisory:

    python cli.py CVE-2024-3400 --ai-advisory

Combine AI advisory generation with JSON output:

    python cli.py CVE-2024-3400 --ai-advisory --json

Replace the example CVE identifier with the CVE you want to assess.

## Output

Generated reports are saved under the `reports/` directory. The project supports Markdown reports and optional JSON output.

Generated reports are excluded from Git so that machine-generated output is not accidentally committed to the repository.

## Prioritisation model

The current triage logic considers available vulnerability intelligence and supplied asset context, including:

- CVSS severity information
- CISA KEV listing
- EPSS data
- Whether the asset is internet-facing
- Asset criticality
- Whether the affected version has been confirmed

The result is a triage aid, not a universal risk score. Missing or unavailable upstream data can affect the assessment.

The current implementation is an initial model. Future work may refine the decision rules and expand the asset-context model.

## AI advisory

The optional `--ai-advisory` flag uses a locally running Ollama model to draft explanatory guidance.

The AI advisory is supplementary. The Python triage logic remains responsible for the priority assessment.

AI-generated text can be incomplete or incorrect. Review recommendations and verify remediation steps against the affected product's official security guidance before using them operationally.

## Running the tests

Run the automated test suite:

    python -m unittest discover -s tests -v

Check that the Python files compile:

    python -m py_compile cli.py advisory_ai.py tests/test_cli.py tests/test_advisory_ai.py

## Project structure

    .
    ├── advisory_ai.py
    ├── cli.py
    ├── tests/
    │   ├── test_advisory_ai.py
    │   └── test_cli.py
    ├── docs/
    ├── reports/
    └── README.md

The `reports/` directory contains generated output and is ignored by Git. The `docs/` directory is intended for additional project documentation.

## Disclaimer

This project is intended for educational and defensive cybersecurity use. It provides decision support and does not guarantee that a vulnerability is safe or unsafe. Validate findings and remediation recommendations before acting on them in a production environment.
