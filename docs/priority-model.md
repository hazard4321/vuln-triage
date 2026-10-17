# Vulnerability Prioritisation Model

## Purpose

The vulnerability triage tool assigns an initial priority to a CVE using public vulnerability intelligence and manually supplied asset context.

The model is designed to make its decisions explainable. It records reasons for the assigned priority so that an analyst can understand which conditions influenced the result.

This is an initial triage model, not a comprehensive enterprise risk assessment.

## Inputs

The model uses the following inputs:

| Input | Meaning |
|---|---|
| CVSS | Technical severity scores available in the CVE data |
| CISA KEV status | Whether the CVE is listed in CISA's Known Exploited Vulnerabilities catalogue |
| EPSS | FIRST's estimated probability of exploitation, represented as a score between 0 and 1 |
| Internet exposure | Whether the affected asset is internet-facing |
| Asset criticality | The supplied criticality classification, such as critical, high, medium, or low |
| Affected-version confirmation | Whether the affected software version has been confirmed on the asset |

The model uses the highest available numeric CVSS score when multiple scores are present.

## Priority levels and decision rules

The rules are evaluated in order. Earlier matching rules can take precedence over later ones.

### P1 - URGENT REVIEW

**Condition:** The CVE is listed in CISA's Known Exploited Vulnerabilities catalogue.

This rule takes precedence over the other priority rules.

Reason recorded: the CVE is listed in CISA KEV.

### P2 - HIGH PRIORITY

**Condition:** Either of the following is true:

- The highest available CVSS score is at least 9.0.
- The EPSS score is at least 0.5, equivalent to 50%.

The model records the applicable severity or EPSS reason.

If the KEV status is unknown, the report also notes that the missing status should be reviewed. If EPSS data is unavailable, the report notes that exploitation probability could not be assessed.

### P3 - STANDARD PRIORITY

This level can be assigned by either of these rules:

- The highest available CVSS score is at least 7.0, provided an earlier P1 or P2 rule has not matched.
- The asset is internet-facing, its supplied criticality is `critical`, and the affected software version is confirmed, provided no earlier rule has matched.

The second rule is an initial asset-context escalation. In the current implementation, it returns P3 rather than P2.

### REVIEW - INSUFFICIENT DATA

This level is returned when no earlier rule has matched and at least one of the following applies:

- CISA KEV status is `UNKNOWN`.
- No usable CVSS score is available.
- No usable EPSS score is available.

The intent is to avoid treating missing intelligence as proof of low risk.

### P4 - ROUTINE REVIEW

This level is returned when none of the earlier rules matches and the model does not identify the specified missing-data conditions.

The report records that no initial P1, P2, or P3 rule was triggered.

P4 does not mean that a vulnerability is harmless or can safely be ignored.

## Decision order

The current implementation follows this order:

1. Check whether the CVE is listed in CISA KEV. If so, return P1.
2. Check for CVSS of at least 9.0 or EPSS of at least 0.5. If either condition is met, return P2.
3. Check for CVSS of at least 7.0. If met, return P3.
4. Check whether the asset is internet-facing, critical, and has a confirmed affected version. If all conditions hold, return P3.
5. Check for specified missing or unknown intelligence. If found, return REVIEW - INSUFFICIENT DATA.
6. Otherwise, return P4.

## Important implementation details

- Internet exposure and asset criticality are recorded in the reasons, but they do not independently change priority in most cases.
- The explicit asset-context escalation requires all three conditions: internet-facing, critical asset, and confirmed affected version.
- The current rules do not automatically assign P2 simply because an asset is critical.
- The model uses available data. An unavailable or unknown upstream result may lead to a review-required outcome.
- Rule order matters. For example, a CVE listed in KEV receives P1 even if other inputs are missing.
- The model's thresholds and labels are implementation choices, not universal industry standards.

## Limitations

This model does not currently account for every factor that can influence real-world risk, including:

- Business impact and service dependencies
- Availability of vendor patches or effective mitigations
- Compensating security controls
- Exposure details beyond the supplied internet-facing flag
- Vulnerability-specific exploitation conditions
- Organisational risk appetite and remediation deadlines

The tool does not independently verify the software installed on an asset. Asset context must be supplied by the user.

## Future improvements

Potential improvements include:

- Refining how criticality and internet exposure affect priority.
- Separating technical severity from business risk.
- Adding tests for boundary values and combinations of missing data.
- Documenting the rationale for thresholds and priority transitions.
- Making uncertainty and unavailable intelligence more explicit in reports.

Any change to the decision rules should be accompanied by updated tests and documentation.
