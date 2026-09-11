import json
from pathlib import Path


# ============================================================
# PROJECT ROOT
# ============================================================

# cross_model_analyzer.py is inside:
# docs/iam_analyzer/
#
# parents[2] points to:
# security-across-the-cloud-stack/
#
# That is where the three JSON reports are generated.

BASE = Path(__file__).resolve().parents[2]


# ============================================================
# LOAD JSON REPORT
# ============================================================

def load_json(filename):
    path = BASE / filename

    if not path.exists():
        raise FileNotFoundError(
            f"\n[!] Required report not found:\n"
            f"    {path}\n\n"
            f"Make sure the corresponding analyzer has been run first."
        )

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


# ============================================================
# BUILD MODEL SUMMARY
# ============================================================

def model_summary(report, model):

    findings = report.get("findings", [])

    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
    }

    # Reports use two compatible formats:
    # 1. findings as a list of finding objects
    # 2. findings as a summary object containing severity counts
    if isinstance(findings, dict):
        summary_counts = findings.get("counts", {})

        if isinstance(summary_counts, dict):
            for severity in counts:
                try:
                    counts[severity] = int(
                        summary_counts.get(severity, 0)
                    )
                except (TypeError, ValueError):
                    counts[severity] = 0

        total_findings = findings.get("total")
        if not isinstance(total_findings, int):
            total_findings = sum(counts.values())

    elif isinstance(findings, list):
        for finding in findings:
            if not isinstance(finding, dict):
                continue

            severity = str(
                finding.get("severity", "INFO")
            ).upper()

            if severity not in counts:
                counts[severity] = 0

            counts[severity] += 1

        total_findings = len(findings)

    else:
        total_findings = 0

    return {
        "model": model,
        "risk_score": report.get("risk_score", 0),
        "risk_rating": report.get(
            "risk_rating",
            "UNKNOWN"
        ),
        "finding_counts": counts,
        "total_findings": total_findings
    }


# ============================================================
# CROSS-MODEL COMPARISON
# ============================================================

def main():

    print("=" * 70)
    print("       SECURITY ACROSS CLOUD STACK")
    print("             CROSS-MODEL COMPARISON")
    print("=" * 70)

    # --------------------------------------------------------
    # LOAD EXISTING REPORTS
    # --------------------------------------------------------

    print("\n[+] Loading security reports...")

    iaas_report = load_json(
        "security_report.json"
    )

    paas_report = load_json(
        "paas_security_report.json"
    )

    saas_report = load_json(
        "saas_security_report.json"
    )

    # --------------------------------------------------------
    # BUILD SUMMARIES
    # --------------------------------------------------------

    models = [

        model_summary(
            iaas_report,
            "IaaS"
        ),

        model_summary(
            paas_report,
            "PaaS"
        ),

        model_summary(
            saas_report,
            "SaaS"
        )

    ]

    # --------------------------------------------------------
    # OVERALL RISK
    # --------------------------------------------------------

    highest = max(
        models,
        key=lambda item: item["risk_score"]
    )

    lowest = min(
        models,
        key=lambda item: item["risk_score"]
    )

    total_findings = sum(
        item["total_findings"]
        for item in models
    )

    average_risk = round(
        sum(
            item["risk_score"]
            for item in models
        ) / len(models),
        2
    )

    # --------------------------------------------------------
    # SHARED RESPONSIBILITY COMPARISON
    # --------------------------------------------------------

    responsibility_comparison = {

        "IaaS": {

            "customer_control": "HIGH",

            "primary_security_focus": [

                "VM and operating system hardening",

                "Network segmentation and NSGs",

                "Public exposure",

                "SSH/RDP access",

                "Identity and RBAC"

            ]
        },

        "PaaS": {

            "customer_control": "MEDIUM",

            "primary_security_focus": [

                "Application configuration",

                "Authentication and authorization",

                "Managed identity",

                "Secrets and Key Vault",

                "Network and access restrictions"

            ]
        },

        "SaaS": {

            "customer_control": "LOW",

            "primary_security_focus": [

                "Users and guest accounts",

                "MFA and authentication",

                "Privileged roles",

                "Applications and service principals",

                "Tenant configuration"

            ]
        }
    }

    # --------------------------------------------------------
    # SECURITY RESPONSIBILITY SHIFT
    # --------------------------------------------------------

    security_model = {

        "IaaS":
            "Customer has the greatest responsibility "
            "for infrastructure, operating systems, "
            "network configuration and access control.",

        "PaaS":
            "The cloud provider manages more of the "
            "underlying infrastructure. The customer "
            "focuses on application security, identity, "
            "configuration and secrets.",

        "SaaS":
            "The provider manages most infrastructure "
            "and platform components. The customer "
            "focuses primarily on users, identity, "
            "access and tenant configuration."
    }

    # --------------------------------------------------------
    # BUILD FINAL REPORT
    # --------------------------------------------------------

    comparison_report = {

        "project":
            "Security Across the Cloud Stack",

        "models":
            models,

        "overall": {

            "average_risk_score":
                average_risk,

            "highest_risk_model":
                highest["model"],

            "highest_risk_score":
                highest["risk_score"],

            "lowest_risk_model":
                lowest["model"],

            "lowest_risk_score":
                lowest["risk_score"],

            "total_findings":
                total_findings
        },

        "responsibility_comparison":
            responsibility_comparison,

        "security_model":
            security_model
    }

    # --------------------------------------------------------
    # SAVE REPORT
    # --------------------------------------------------------

    output_file = (
        BASE /
        "cross_model_report.json"
    )

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            comparison_report,
            file,
            indent=4
        )

    # ========================================================
    # DISPLAY RESULTS
    # ========================================================

    print("\nMODEL RISK")
    print("-" * 70)

    for model in models:

        print(
            f"{model['model']}: "
            f"{model['risk_score']}/100 "
            f"({model['risk_rating']}) "
            f"- {model['total_findings']} findings"
        )

    # --------------------------------------------------------
    # FINDING COUNTS
    # --------------------------------------------------------

    print("\nFINDING COUNTS")
    print("-" * 70)

    for model in models:

        counts = model["finding_counts"]

        print(
            f"{model['model']}: "
            f"CRITICAL={counts['CRITICAL']} "
            f"HIGH={counts['HIGH']} "
            f"MEDIUM={counts['MEDIUM']} "
            f"LOW={counts['LOW']} "
            f"INFO={counts['INFO']}"
        )

    # --------------------------------------------------------
    # OVERALL
    # --------------------------------------------------------

    print("\nOVERALL")
    print("-" * 70)

    print(
        f"Average risk score: "
        f"{average_risk}/100"
    )

    print(
        f"Highest-risk model: "
        f"{highest['model']} "
        f"({highest['risk_score']}/100)"
    )

    print(
        f"Lowest-risk model: "
        f"{lowest['model']} "
        f"({lowest['risk_score']}/100)"
    )

    print(
        f"Total findings: "
        f"{total_findings}"
    )

    # --------------------------------------------------------
    # RESPONSIBILITY
    # --------------------------------------------------------

    print("\nSECURITY RESPONSIBILITY")
    print("-" * 70)

    for model, data in responsibility_comparison.items():

        print(
            f"\n{model}:"
        )

        print(
            f"  Customer control: "
            f"{data['customer_control']}"
        )

        print(
            "  Security focus:"
        )

        for focus in data[
            "primary_security_focus"
        ]:

            print(
                f"    - {focus}"
            )

    # --------------------------------------------------------
    # OUTPUT
    # --------------------------------------------------------

    print("\n[+] Cross-model comparison complete.")

    print(
        f"[+] Report: "
        f"{output_file.name}"
    )

    print("\n" + "=" * 70)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()