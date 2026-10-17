# Architecture

## Overview

Vulnerability Triage CLI is a Python command-line application that collects public vulnerability intelligence, evaluates an initial triage priority, and generates reports.

The application is organised around a primary CLI module and an optional AI advisory module.

## Components

### 1. Command-line interface: `cli.py`

The CLI is the main application entry point.

It is responsible for:

- Parsing command-line arguments.
- Validating CVE identifiers.
- Retrieving vulnerability information from the NVD CVE API.
- Checking CISA KEV status.
- Retrieving EPSS data from FIRST.
- Extracting CVSS metrics.
- Calculating an initial priority and recording the reasons.
- Generating Markdown and JSON reports.
- Optionally requesting an AI-written advisory.

### 2. Vulnerability intelligence sources

The application uses three public sources:

| Source | Purpose |
|---|---|
| NVD CVE API | CVE details and available CVSS metrics |
| CISA KEV catalogue | Whether a vulnerability is listed as known exploited |
| FIRST EPSS API | Estimated exploitation probability |

The application retrieves this information when an assessment is run. Results depend on the availability and content of the upstream services.

### 3. Priority assessment

The priority assessment uses vulnerability intelligence together with user-supplied asset context.

Relevant context includes internet exposure, asset criticality, and whether the affected software version has been confirmed.

The decision rules return a priority label and explanatory reasons. The current rules are documented in [Priority Model](priority-model.md).

### 4. Report generation

The application can produce Markdown reports and JSON output.

Reports contain the available vulnerability information, assessment result, and explanatory details. Generated reports are stored under `reports/`, which is excluded from version control.

### 5. Optional AI advisory: `advisory_ai.py`

The AI module builds a prompt from vulnerability facts and requests an advisory from a locally running Ollama service.

This feature is optional. It requires Ollama to be running and a suitable model to be available locally.

The AI advisory is supplementary text. It does not replace the Python priority assessment, and its recommendations should be reviewed by a human.

### 6. Tests

The `tests/` directory contains automated tests for the CLI and AI advisory modules.

The suite covers areas such as:

- CVE identifier validation.
- Priority decision rules.
- Report content and JSON validity.
- Handling selected NVD request failures.
- AI prompt construction and advisory-generation failures.

Run the suite with:

    python -m unittest discover -s tests -v

## Assessment flow

A typical assessment follows this sequence:

1. The user supplies a CVE identifier and optional asset-context flags.
2. The CLI validates the identifier's format.
3. The application retrieves the CVE record from NVD.
4. It checks the CISA KEV catalogue and retrieves EPSS data.
5. It extracts the available CVSS metrics.
6. The priority rules evaluate the available intelligence and asset context.
7. The application generates the requested report.
8. If enabled, the optional AI component generates supplementary advisory text.

The availability of individual intelligence sources can affect the resulting assessment. Missing data should be treated as uncertainty, not proof that a vulnerability is harmless.

## Design principles

### Explainability

The priority function returns explanatory reasons alongside the priority label so that users can see which rules influenced the assessment.

### Graceful handling of unavailable data

The application handles several upstream-service failures and distinguishes some unavailable intelligence from confirmed negative results.

### Minimal dependencies

The core application uses Python's standard library. The optional AI feature communicates with a local Ollama service.

### Separation of responsibilities

The main CLI handles retrieval, assessment, and reporting. The AI advisory functionality is kept in a separate module, and automated tests are organised under `tests/`.

## Current limitations

- The tool does not discover assets or verify installed software.
- Asset context is supplied manually by the user.
- Assessments depend on the availability and quality of external vulnerability intelligence.
- The application does not automatically patch systems.
- AI-generated advisory text can be inaccurate and requires review.
- The priority model is an initial triage mechanism rather than a complete enterprise risk model.

## Future improvements

Potential future work includes:

- Expanding tests for combinations of missing or conflicting intelligence.
- Improving asset-context handling and documenting the rationale for priority thresholds.
- Improving report clarity and the treatment of uncertainty.
- Adding stronger integration tests for external-service responses.
