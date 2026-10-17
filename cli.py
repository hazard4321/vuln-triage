import argparse
import json
from pathlib import Path
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

def is_valid_cve(cve_id):
    """Check whether a CVE identifier follows the expected format."""
    pattern = r"^CVE-[0-9]{4}-[0-9]{4,}$"
    return re.fullmatch(pattern, cve_id) is not None


def fetch_cve(cve_id):
    """Retrieve one CVE record from the NVD API."""
    query = urlencode({"cveId": cve_id})
    url = f"{NVD_API_URL}?{query}"

    request = Request(
        url,
        headers={"User-Agent": "Vuln-Triage/0.1"}
    )

    try:
        with urlopen(request, timeout=20) as response:
            data = json.load(response)

    except HTTPError as error:
        if error.code == 404:
            raise ValueError("The NVD endpoint returned HTTP 404.") from error
        if error.code == 429:
            raise RuntimeError(
                "NVD rate limit reached. Please wait and try again."
            ) from error
        raise RuntimeError(
            f"NVD returned HTTP {error.code}."
        ) from error

    except URLError as error:
        raise RuntimeError(
            f"Could not connect to NVD: {error.reason}"
        ) from error

    except TimeoutError as error:
        raise RuntimeError("The request to NVD timed out.") from error

    except json.JSONDecodeError as error:
        raise RuntimeError("NVD returned invalid JSON.") from error

    vulnerabilities = data.get("vulnerabilities", [])

    if not vulnerabilities:
        raise ValueError(
            f"NVD has no matching record for {cve_id}."
        )

    return vulnerabilities[0]["cve"]

def check_cisa_kev(cve_id):
    """Check whether a CVE appears in CISA's KEV catalogue."""
    request = Request(
        CISA_KEV_URL,
        headers={"User-Agent": "Vuln-Triage/0.1"}
    )

    try:
        with urlopen(request, timeout=20) as response:
            data = json.load(response)

    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError):
        return {
            "status": "UNKNOWN",
            "details": None,
            "catalog_version": None,
        }

    vulnerabilities = data.get("vulnerabilities")

    if not isinstance(vulnerabilities, list):
        return {
            "status": "UNKNOWN",
            "details": None,
            "catalog_version": data.get("catalogVersion"),
        }

    for vulnerability in vulnerabilities:
        if vulnerability.get("cveID") == cve_id:
            return {
                "status": "LISTED",
                "details": vulnerability,
                "catalog_version": data.get("catalogVersion"),
            }

    return {
        "status": "NOT LISTED",
        "details": None,
        "catalog_version": data.get("catalogVersion"),
    }

def fetch_epss(cve_id):
    """Retrieve EPSS probability and percentile for a CVE."""
    query = urlencode({"cve": cve_id})
    url = f"{EPSS_API_URL}?{query}"

    request = Request(
        url,
        headers={"User-Agent": "Vuln-Triage/0.1"}
    )

    try:
        with urlopen(request, timeout=20) as response:
            data = json.load(response)

    except HTTPError as error:
        return {
            "status": "UNKNOWN",
            "score": None,
            "percentile": None,
            "date": None,
        }

    except (URLError, TimeoutError, json.JSONDecodeError):
        return {
            "status": "UNKNOWN",
            "score": None,
            "percentile": None,
            "date": None,
        }

    records = data.get("data", [])

    if not records:
        return {
            "status": "UNKNOWN",
            "score": None,
            "percentile": None,
            "date": None,
        }

    record = records[0]

    try:
        score = float(record["epss"])
        percentile = float(record["percentile"])
    except (KeyError, TypeError, ValueError):
        return {
            "status": "UNKNOWN",
            "score": None,
            "percentile": None,
            "date": record.get("date"),
        }

    return {
        "status": "AVAILABLE",
        "score": score,
        "percentile": percentile,
        "date": record.get("date"),
    }

def get_english_description(cve):
    """Return the English description, if available."""
    for description in cve.get("descriptions", []):
        if description.get("lang") == "en":
            return description.get("value", "Not available")

    return "No English description available."


def get_cvss_metrics(cve):
    """Extract available CVSS scores and their sources."""
    results = []

    for metric_type, assessments in cve.get("metrics", {}).items():
        if not metric_type.lower().startswith("cvss"):
            continue

        for assessment in assessments:
            cvss_data = assessment.get("cvssData", {})

            score = cvss_data.get("baseScore")
            severity = (
                cvss_data.get("baseSeverity")
                or assessment.get("baseSeverity")
            )

            results.append({
                "version": cvss_data.get("version", "Unknown"),
                "score": score,
                "severity": severity,
                "source": assessment.get("source", "Unknown"),
                "type": assessment.get("type", "Unknown"),
            })

    return results

def determine_priority(
    cve,
    kev,
    epss,
    internet_facing=False,
    asset_criticality="medium",
    affected_version_confirmed=False,
):
    """Assign an explainable initial vulnerability triage priority."""
    reasons = []

    metrics = get_cvss_metrics(cve)

    scores = [
        metric["score"]
        for metric in metrics
        if isinstance(metric["score"], (int, float))
    ]

    highest_cvss = max(scores) if scores else None
    epss_score = epss.get("score")
    kev_status = kev.get("status", "UNKNOWN")

    # Record asset context so the analyst can see what was assessed.
    if internet_facing:
        reasons.append("The affected asset is internet-facing.")

    reasons.append(f"Asset criticality: {asset_criticality}.")

    if affected_version_confirmed:
        reasons.append("The affected software version is confirmed.")
    else:
        reasons.append(
            "The affected software version has not been confirmed."
        )

    # Rule 1: Known exploitation takes precedence.
    if kev_status == "LISTED":
        reasons.append(
            "Listed in CISA's Known Exploited Vulnerabilities catalogue."
        )
        return "P1 - URGENT REVIEW", reasons

    # Rule 2: Critical technical severity.
    if highest_cvss is not None and highest_cvss >= 9.0:
        reasons.append(f"Critical CVSS score: {highest_cvss:.1f}.")

    # Rule 3: High estimated exploitation probability.
    if epss_score is not None and epss_score >= 0.5:
        reasons.append(
            f"High EPSS estimate: {epss_score * 100:.2f}%."
        )

    if reasons and (
        (highest_cvss is not None and highest_cvss >= 9.0)
        or (epss_score is not None and epss_score >= 0.5)
    ):
        if kev_status == "UNKNOWN":
            reasons.append(
                "CISA KEV status could not be confirmed; "
                "review the missing intelligence."
            )

        if epss_score is None:
            reasons.append(
                "EPSS data is unavailable; exploitation probability "
                "could not be assessed."
            )

        return "P2 - HIGH PRIORITY", reasons

    # Rule 4: High CVSS severity.
    if highest_cvss is not None and highest_cvss >= 7.0:
        reasons.append(f"High CVSS score: {highest_cvss:.1f}.")
        return "P3 - STANDARD PRIORITY", reasons

    # Rule 5: Escalate when all specified asset-risk conditions hold.
    if (
        internet_facing
        and asset_criticality == "critical"
        and affected_version_confirmed
    ):
        reasons.append(
            "Elevated for a confirmed vulnerability on a critical, "
            "internet-facing asset."
        )
        return "P3 - STANDARD PRIORITY", reasons

    # Missing intelligence must not be interpreted as low risk.
    if kev_status == "UNKNOWN":
        reasons.append(
            "CISA KEV status is unknown because the catalogue "
            "could not be checked."
        )

    if highest_cvss is None:
        reasons.append("No usable CVSS score is available.")

    if epss_score is None:
        reasons.append("No usable EPSS score is available.")

    if reasons and (
        kev_status == "UNKNOWN"
        or highest_cvss is None
        or epss_score is None
    ):
        return "REVIEW - INSUFFICIENT DATA", reasons

    reasons.append(
        "No initial P1, P2, or P3 rule was triggered by the available data."
    )
    return "P4 - ROUTINE REVIEW", reasons

def generate_json_report(
    cve,
    kev,
    epss,
    priority,
    reasons,
    internet_facing=False,
    asset_criticality="medium",
    affected_version_confirmed=False,
):
    """Generate and save a JSON vulnerability triage report."""

    cve_id = cve.get("id", "UNKNOWN")
    metrics = get_cvss_metrics(cve)

    report = {
        "cve_id": cve_id,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "record_status": cve.get("vulnStatus"),
        "description": get_english_description(cve),
        "cvss_assessments": metrics,
        "cisa_kev": {
            "status": kev.get("status", "UNKNOWN"),
            "catalog_version": kev.get("catalog_version"),
            "details": kev.get("details"),
        },
        "epss": {
            "status": epss.get("status", "UNKNOWN"),
            "score": epss.get("score"),
            "percentile": epss.get("percentile"),
            "date": epss.get("date"),
        },
        "asset_context": {
            "internet_facing": internet_facing,
            "criticality": asset_criticality,
            "affected_version_confirmed": affected_version_confirmed,
        },
        "triage": {
            "priority": priority,
            "reasons": reasons,
        },
        "sources": {
            "nvd": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "cisa_kev": (
                "https://www.cisa.gov/"
                "known-exploited-vulnerabilities-catalog"
            ),
            "first_epss": (
                f"https://api.first.org/data/v1/epss?cve={cve_id}"
            ),
        },
        "limitations": (
            "This is an initial, rule-based assessment. "
            "It does not establish risk to a specific organisation."
        ),
    }

    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)

    report_path = reports_dir / f"{cve_id}.json"
    report_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(f"JSON report saved to: {report_path}")

def generate_markdown_report(
    cve,
    kev,
    epss,
    priority,
    reasons,
    internet_facing=False,
    asset_criticality="medium",
    affected_version_confirmed=False,
):
    """Generate and save a Markdown vulnerability triage report."""
    cve_id = cve.get("id", "UNKNOWN")
    description = get_english_description(cve)
    metrics = get_cvss_metrics(cve)

    report_lines = [
        f"# Vulnerability Triage Report: {cve_id}",
        "",
        "> This report is an initial, rule-based assessment. It is not a",
        "> definitive risk rating for a specific organisation.",
        "",
        "## 1. NVD — Vulnerability Details",
        "",
        f"- **CVE ID:** {cve_id}",
        f"- **Published:** {cve.get('published', 'Unknown')}",
        f"- **Last modified:** {cve.get('lastModified', 'Unknown')}",
        f"- **Record status:** {cve.get('vulnStatus', 'Unknown')}",
        "",
        "### Description",
        "",
        description,
        "",
        "### CVSS Assessments",
        "",
    ]

    if metrics:
        for metric in metrics:
            report_lines.extend([
                f"#### CVSS {metric['version']}",
                "",
                f"- **Score:** {metric['score']}",
                f"- **Severity:** {metric['severity'] or 'Not provided'}",
                f"- **Source:** {metric['source']}",
                f"- **Assessment type:** {metric['type']}",
                "",
            ])
    else:
        report_lines.extend([
            "No CVSS assessments were available in the NVD record.",
            "",
        ])

    report_lines.extend([
        "## 2. CISA — Known Exploited Vulnerabilities (KEV)",
        "",
        f"- **Catalogue status:** {kev.get('status', 'UNKNOWN')}",
        f"- **Catalogue version:** {kev.get('catalog_version') or 'Unknown'}",
        "",
    ])

    details = kev.get("details")

    if details:
        report_lines.extend([
            f"- **Vendor:** {details.get('vendorProject', 'Unknown')}",
            f"- **Product:** {details.get('product', 'Unknown')}",
            f"- **Date added:** {details.get('dateAdded', 'Unknown')}",
            (
                "- **Known ransomware campaign use:** "
                f"{details.get('knownRansomwareCampaignUse', 'Unknown')}"
            ),
            (
                "- **Required action:** "
                f"{details.get('requiredAction', 'Not provided')}"
            ),
            "",
        ])
    elif kev.get("status") == "NOT LISTED":
        report_lines.extend([
            "This CVE was not found in the checked CISA KEV catalogue.",
            "",
        ])
    else:
        report_lines.extend([
            "CISA KEV details could not be confirmed.",
            "",
        ])

    report_lines.extend([
        "## 3. FIRST — Exploit Prediction Scoring System (EPSS)",
        "",
    ])

    if epss.get("status") == "AVAILABLE":
        report_lines.extend([
            f"- **EPSS score:** {epss['score']:.5f}",
            f"- **Estimated probability:** {epss['score'] * 100:.3f}%",
            f"- **Percentile:** {epss['percentile'] * 100:.2f}%",
            f"- **Score date:** {epss.get('date') or 'Unknown'}",
            "",
        ])
    else:
        report_lines.extend([
            "**EPSS data is currently unavailable.**",
            "",
        ])
    report_lines.extend([
        "## 4. Triage Assessment",
        "",
        f"**Initial priority: {priority}**",
        "",
        "### Asset Context",
        "",
        (
            f"- **Internet-facing:** "
            f"{'Yes' if internet_facing else 'No'}"
        ),
        f"- **Asset criticality:** {asset_criticality.title()}",
        (
            f"- **Affected software version confirmed:** "
            f"{'Yes' if affected_version_confirmed else 'No'}"
        ),
        "",
        "### Reasons",
        "",
    ])    

    for reason in reasons:
        report_lines.append(f"- {reason}")

    report_lines.extend([
        "",
        "### Limitations",
        "",
        (
            "This priority is produced by the project's rules and is not an "
            "official CISA rating. Confirm the affected software version, "
            "exposure, available mitigations, and asset criticality before "
            "making remediation decisions."
        ),
        "",
        "## 5. Sources",
        "",
        f"- [NVD vulnerability record](https://nvd.nist.gov/vuln/detail/{cve_id})",
        "- [CISA KEV catalogue](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)",
        f"- [FIRST EPSS API](https://api.first.org/data/v1/epss?cve={cve_id})",
        "",
    ])

    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)

    report_path = reports_dir / f"{cve_id}.md"
    report_path.write_text("\n".join(report_lines), encoding="utf-8")

    print(f"\nMarkdown report saved to: {report_path}")

def display_cve(
    cve,
    internet_facing=False,
    asset_criticality="medium",
    affected_version_confirmed=False,
    json_output=False,
):
    """Display a vulnerability summary in a logical triage sequence."""
    cve_id = cve.get("id", "Unknown")

    # Collect threat intelligence once, then present it in the intended order.
    kev = check_cisa_kev(cve_id)
    epss = fetch_epss(cve_id)
    priority, reasons = determine_priority(
    cve,
    kev,
    epss,
    internet_facing=internet_facing,
    asset_criticality=asset_criticality,
    affected_version_confirmed=affected_version_confirmed,
    )
    metrics = get_cvss_metrics(cve)

    # 1. NVD: establish what the vulnerability is and its technical severity.
    print("\n" + "=" * 70)
    print(f"NVD VULNERABILITY DETAILS: {cve_id}")
    print("=" * 70)

    print(f"Published:     {cve.get('published', 'Unknown')}")
    print(f"Last modified: {cve.get('lastModified', 'Unknown')}")
    print(f"Record status: {cve.get('vulnStatus', 'Unknown')}")

    print("\nDESCRIPTION")
    print("-" * 70)
    print(get_english_description(cve))

    print("\nCVSS ASSESSMENTS")
    print("-" * 70)

    if not metrics:
        print("No CVSS assessments were available in this NVD record.")
    else:
        for metric in metrics:
            print(
                f"CVSS {metric['version']} | "
                f"Score: {metric['score']} | "
                f"Severity: {metric['severity'] or 'Not provided'}"
            )
            print(f"  Source: {metric['source']}")
            print(f"  Assessment type: {metric['type']}")

    # 2. CISA KEV: establish whether exploitation is known.
    print("\nCISA KNOWN EXPLOITED VULNERABILITIES (KEV)")
    print("-" * 70)
    print(f"Catalogue status: {kev['status']}")

    if kev.get("catalog_version"):
        print(f"Catalogue version: {kev['catalog_version']}")

    if kev.get("details"):
        details = kev["details"]
        print(f"Vendor: {details.get('vendorProject', 'Unknown')}")
        print(f"Product: {details.get('product', 'Unknown')}")
        print(f"Date added: {details.get('dateAdded', 'Unknown')}")
        print(
            "Known ransomware campaign use: "
            f"{details.get('knownRansomwareCampaignUse', 'Unknown')}"
        )
        print(
            "Required action: "
            f"{details.get('requiredAction', 'Not provided')}"
        )
    elif kev["status"] == "NOT LISTED":
        print("This CVE was not found in the checked CISA KEV catalogue.")
    else:
        print("CISA KEV details could not be confirmed.")

    # 3. FIRST EPSS: show the estimated likelihood of exploitation.
    print("\nFIRST EXPLOIT PREDICTION SCORING SYSTEM (EPSS)")
    print("-" * 70)

    if epss["status"] == "AVAILABLE":
        print(
            f"EPSS score: {epss['score']:.5f} "
            f"({epss['score'] * 100:.3f}%)"
        )
        print(f"Percentile: {epss['percentile'] * 100:.2f}%")
        print(f"Score date: {epss['date'] or 'Unknown'}")
    else:
        print("EPSS data is currently unavailable.")

    # 4. Apply and explain the tool's initial triage rules.
    print("\nTRIAGE ASSESSMENT")
    print("-" * 70)
    print(f"Priority: {priority}")

    for reason in reasons:
        print(f"  - {reason}")

    print(
        "\nImportant: This is an initial, rule-based assessment. "
        "It does not establish risk to a specific organisation. "
        "Confirm affected versions, exposure, available mitigations, "
        "and asset criticality before making remediation decisions."
    )

    # 5. Identify the sources used.
    print("\n" + "=" * 70)
    print("SOURCES")
    print("-" * 70)
    print(f"NVD:       https://nvd.nist.gov/vuln/detail/{cve_id}")
    print("CISA KEV:  https://www.cisa.gov/known-exploited-vulnerabilities-catalog")
    print(f"FIRST EPSS: https://api.first.org/data/v1/epss?cve={cve_id}")
    print("=" * 70)

    generate_markdown_report(
        cve,
        kev,
        epss,
        priority,
        reasons,
        internet_facing=internet_facing,
        asset_criticality=asset_criticality,
        affected_version_confirmed=affected_version_confirmed,
    )
    if json_output:
        generate_json_report(
            cve,
            kev,
            epss,
            priority,
            reasons,
            internet_facing=internet_facing,
            asset_criticality=asset_criticality,
            affected_version_confirmed=affected_version_confirmed,
        )

def main():
    parser = argparse.ArgumentParser(
        description="Vuln-Triage: a CVE vulnerability triage tool"
    )

    parser.add_argument(
        "cve_id",
        help="The CVE identifier to investigate, e.g. CVE-2024-3400"
    )

    parser.add_argument(
        "--internet-facing",
        action="store_true",
        help="Indicate that the affected asset is exposed to the internet",
    )

    parser.add_argument(
        "--asset-criticality",
        choices=["critical", "high", "medium", "low"],
        default="medium",
        help="Business criticality of the affected asset (default: medium)",
    )

    parser.add_argument(
        "--affected-version-confirmed",
        action="store_true",
        help="Confirm that the asset runs an affected software version",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Save the assessment as a JSON report",    
    )

    args = parser.parse_args()

    if not is_valid_cve(args.cve_id):
        print(
            f"Error: '{args.cve_id}' is not a valid CVE identifier format.",
            file=sys.stderr,
        )
        return 1

    print(f"Fetching {args.cve_id} from NVD...")

    try:
        cve = fetch_cve(args.cve_id)
    except (ValueError, RuntimeError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    display_cve(
    cve,
    internet_facing=args.internet_facing,
    asset_criticality=args.asset_criticality,
    affected_version_confirmed=args.affected_version_confirmed,
    json_output=args.json,
    )


if __name__ == "__main__":
    sys.exit(main())
