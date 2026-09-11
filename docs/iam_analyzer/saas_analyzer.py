import json
from pathlib import Path


# ============================================================
# SECURITY ACROSS CLOUD STACK
# SAAS / MICROSOFT ENTRA SECURITY ANALYZER
# ============================================================

INPUT_FILE = "azure_inventory.json"
OUTPUT_FILE = "saas_security_report.json"


PRIVILEGED_ROLE_NAMES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
    "User Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "Conditional Access Administrator",
    "Authentication Administrator",
}


SEVERITY_WEIGHT = {
    "CRITICAL": 30,
    "HIGH": 20,
    "MEDIUM": 10,
    "LOW": 5,
    "INFO": 0,
}


def load_inventory():
    path = Path(INPUT_FILE)
    if not path.exists():
        raise FileNotFoundError(
            f"{INPUT_FILE} not found. Run azure_collector.py first."
        )

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def add_finding(findings, severity, title, description, recommendation):
    findings.append({
        "severity": severity,
        "title": title,
        "description": description,
        "recommendation": recommendation,
    })


def analyze_users(saas, findings):
    users = saas.get("users", [])
    guests = saas.get("guests", [])
    disabled_users = saas.get("disabled_users", [])

    if not saas.get("collection_status", {}).get("users", False):
        add_finding(
            findings,
            "MEDIUM",
            "User inventory could not be verified",
            "Microsoft Graph did not provide the tenant user inventory.",
            "Grant the required Microsoft Graph directory-read permissions and rerun the collector.",
        )
        return

    if guests:
        add_finding(
            findings,
            "INFO",
            "Guest accounts detected",
            f"{len(guests)} guest account(s) were discovered in Microsoft Entra.",
            "Review guest accounts regularly and remove guests that no longer require access.",
        )
    else:
        add_finding(
            findings,
            "INFO",
            "No guest accounts detected",
            "No Microsoft Entra guest accounts were present in the collected inventory.",
            "Continue reviewing external identities as the tenant changes.",
        )

    if disabled_users:
        add_finding(
            findings,
            "INFO",
            "Disabled accounts detected",
            f"{len(disabled_users)} disabled account(s) were discovered.",
            "Periodically review disabled accounts and remove stale identities according to the organization's lifecycle policy.",
        )


def analyze_privileged_roles(saas, findings):
    roles = saas.get("privileged_roles", [])
    status = saas.get("collection_status", {})

    if not status.get("directory_roles", False):
        add_finding(
            findings,
            "MEDIUM",
            "Privileged directory roles could not be verified",
            "Microsoft Graph did not provide the directory-role inventory.",
            "Grant the required Microsoft Graph directory-role permissions and rerun the collector.",
        )
        return

    if not status.get("directory_role_members", False):
        add_finding(
            findings,
            "MEDIUM",
            "Privileged role membership could not be fully verified",
            "One or more directory-role membership requests were unavailable.",
            "Grant the required directory-role read permissions and rerun the collector before treating the tenant as secure.",
        )

    privileged_member_count = 0
    global_admin_members = []

    for role in roles:
        name = role.get("display_name", "Unknown")
        members = role.get("members", [])
        if name in PRIVILEGED_ROLE_NAMES:
            privileged_member_count += len(members)
        if name == "Global Administrator":
            global_admin_members.extend(members)

    if global_admin_members:
        add_finding(
            findings,
            "HIGH",
            "Global Administrator assignments detected",
            f"{len(global_admin_members)} account(s) were found in the Global Administrator role.",
            "Minimize standing Global Administrator access. Use least privilege and privileged-access controls where available.",
        )
    else:
        add_finding(
            findings,
            "INFO",
            "No Global Administrator members detected",
            "No Global Administrator role members were returned by the collected directory-role data.",
            "Continue monitoring privileged role membership.",
        )

    if privileged_member_count > 5:
        add_finding(
            findings,
            "HIGH",
            "Large privileged-role footprint",
            f"{privileged_member_count} membership record(s) were found across the configured privileged roles.",
            "Review privileged assignments and remove unnecessary standing administrative access.",
        )
    elif privileged_member_count > 0:
        add_finding(
            findings,
            "INFO",
            "Privileged role assignments detected",
            f"{privileged_member_count} membership record(s) were found across the configured privileged roles.",
            "Validate each privileged assignment against least-privilege requirements.",
        )


def analyze_service_principals(saas, findings):
    service_principals = saas.get("service_principals", [])
    status = saas.get("collection_status", {})

    if not status.get("service_principals", False):
        add_finding(
            findings,
            "MEDIUM",
            "Service-principal inventory could not be verified",
            "Microsoft Graph did not provide the tenant service-principal inventory.",
            "Grant the required application/service-principal read permissions and rerun the collector.",
        )
        return

    disabled = [
        sp for sp in service_principals
        if sp.get("account_enabled") is False
    ]

    if disabled:
        add_finding(
            findings,
            "INFO",
            "Disabled service principals detected",
            f"{len(disabled)} disabled service principal(s) were discovered.",
            "Review disabled applications and remove stale registrations when they are no longer required.",
        )

    add_finding(
        findings,
        "INFO",
        "Service principals inventoried",
        f"{len(service_principals)} service principal(s) were collected from Microsoft Entra.",
        "Review application identities periodically and restrict permissions to the minimum required scope.",
    )


def analyze_mfa(saas, findings):
    status = saas.get("collection_status", {})
    mfa_records = saas.get("mfa_registration", [])

    if not status.get("mfa_registration", False):
        add_finding(
            findings,
            "MEDIUM",
            "MFA registration status could not be verified",
            "The Microsoft Graph authentication-method registration report was unavailable.",
            "Grant the required reporting permissions and rerun the collector. Do not interpret missing MFA data as MFA being enabled.",
        )
        return

    if not mfa_records:
        add_finding(
            findings,
            "MEDIUM",
            "No MFA registration records were collected",
            "The MFA registration report returned no user records.",
            "Verify Graph reporting permissions and tenant reporting availability before relying on this result.",
        )
        return

    not_registered = [
        user for user in mfa_records
        if user.get("mfa_registered") is False
    ]

    if not_registered:
        add_finding(
            findings,
            "HIGH",
            "Users without registered MFA detected",
            f"{len(not_registered)} user(s) were reported as not having MFA registered.",
            "Require MFA for appropriate users through Microsoft Entra authentication policies and Conditional Access.",
        )
    else:
        add_finding(
            findings,
            "INFO",
            "MFA registration present for collected users",
            "No collected MFA registration record reported a user as lacking MFA registration.",
            "Continue enforcing MFA with appropriate Conditional Access policies rather than relying only on registration.",
        )


def calculate_risk_score(findings):
    # Score represents accumulated security exposure, capped at 100.
    score = sum(SEVERITY_WEIGHT.get(f["severity"], 0) for f in findings)
    return min(score, 100)


def risk_rating(score):
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "SECURE"


def main():
    print("=" * 70)
    print("       SECURITY ACROSS CLOUD STACK")
    print("          SAAS / ENTRA SECURITY ANALYZER")
    print("=" * 70)

    inventory = load_inventory()
    saas = inventory.get("saas")

    if not saas:
        raise RuntimeError(
            "No 'saas' section found in azure_inventory.json. "
            "Run the updated azure_collector.py first."
        )

    findings = []

    analyze_users(saas, findings)
    analyze_privileged_roles(saas, findings)
    analyze_service_principals(saas, findings)
    analyze_mfa(saas, findings)

    score = calculate_risk_score(findings)
    rating = risk_rating(score)

    counts = {
        severity: sum(1 for f in findings if f["severity"] == severity)
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    }

    report = {
        "service_model": "SaaS",
        "platform": "Microsoft 365 / Microsoft Entra",
        "tenant_id": inventory.get("tenant_id"),
        "risk_score": score,
        "risk_rating": rating,
        "total_findings": len(findings),
        "finding_counts": counts,
        "inventory_summary": {
            "users": len(saas.get("users", [])),
            "guests": len(saas.get("guests", [])),
            "disabled_users": len(saas.get("disabled_users", [])),
            "service_principals": len(saas.get("service_principals", [])),
            "privileged_roles": len(saas.get("privileged_roles", [])),
            "mfa_records": len(saas.get("mfa_registration", [])),
        },
        "collection_status": saas.get("collection_status", {}),
        "findings": findings,
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print(f"\nSaaS risk score: {score}/100")
    print(f"SaaS risk rating: {rating}")
    print(f"Total findings: {len(findings)}")

    print("\nFinding counts:")
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        print(f"{severity}: {counts[severity]}")

    print(f"\nReport: {OUTPUT_FILE}")
    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
