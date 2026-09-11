# ============================================================
# SECURITY ACROSS CLOUD STACK
# SECURITY REPORT GENERATOR
# ============================================================

import json
from pathlib import Path


def generate_report(findings):

    severity_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3
    }

    # --------------------------------------------------------
    # RANK FINDINGS
    # --------------------------------------------------------

    findings = sorted(
        findings,
        key=lambda finding: (
            severity_order.get(
                finding["severity"],
                99
            ),
            -finding["risk_score"]
        )
    )

    # --------------------------------------------------------
    # REPORT STRUCTURE
    # --------------------------------------------------------

    report = {

        "project":
            "Security Across Cloud Stack",

        "summary": {

            "total_findings":
                len(findings),

            "critical":
                sum(
                    1
                    for finding in findings
                    if finding["severity"] == "CRITICAL"
                ),

            "high":
                sum(
                    1
                    for finding in findings
                    if finding["severity"] == "HIGH"
                ),

            "medium":
                sum(
                    1
                    for finding in findings
                    if finding["severity"] == "MEDIUM"
                ),

            "low":
                sum(
                    1
                    for finding in findings
                    if finding["severity"] == "LOW"
                )
        },

        "findings": []
    }

    # --------------------------------------------------------
    # ADD FINDINGS
    # --------------------------------------------------------

    for index, finding in enumerate(
        findings,
        start=1
    ):

        report["findings"].append({

            "rank":
                index,

            "finding_id":
                f"SCS-{index:03d}",

            "severity":
                finding["severity"],

            "risk_score":
                finding["risk_score"],

            "risk_factors":
                finding.get(
                    "risk_factors",
                    []
                ),

            "title":
                finding["title"],

            "entry_point":
                finding["entry_point"],

            "permission":
                finding["role"],

            "target":
                finding["target"],

            "reason":
                finding["reason"],

            "impact":
                finding["impact"],

            "recommendation":
                finding["recommendation"],

            # ------------------------------------------------
            # REMEDIATION
            # ------------------------------------------------

            "remediation":
                finding.get(
                    "remediation",
                    {}
                )
        })

    return report


# ============================================================
# SAVE REPORT
# ============================================================


def save_report(
    report,
    path="security_report.json"
):

    output_path = (
        Path(__file__).parent / path
    )

    with open(
        output_path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4
        )

    return output_path