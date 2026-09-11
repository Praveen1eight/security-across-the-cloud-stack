# ============================================================
# SECURITY ACROSS CLOUD STACK
# REMEDIATION ENGINE
# ============================================================


def generate_remediation(finding):

    role = finding.get(
        "role",
        "Unknown Role"
    )

    target = finding.get(
        "target",
        "Unknown Target"
    )

    entry_point = finding.get(
        "entry_point",
        "Unknown Entry Point"
    )

    title = finding.get(
        "title",
        ""
    )

    # --------------------------------------------------------
    # MANAGED IDENTITY REMEDIATION
    # --------------------------------------------------------

    if "Managed identity" in title:

        action = (
            f"Review the '{role}' assignment for "
            f"'{entry_point}' and remove the role if "
            f"the workload does not require access to "
            f"'{target}'."
        )

        least_privilege = (
            "If access is required, replace the broad "
            "role with the minimum permission needed "
            "for the workload."
        )

        verification = (
            f"Verify that '{entry_point}' can no longer "
            f"reach '{target}' through an unnecessary "
            "role assignment."
        )

    # --------------------------------------------------------
    # DIRECT IDENTITY REMEDIATION
    # --------------------------------------------------------

    else:

        action = (
            f"Review the '{role}' role assigned to "
            f"'{entry_point}' and remove the assignment "
            f"if access to '{target}' is not required."
        )

        least_privilege = (
            "If access is required, replace the role "
            "with the least-privileged role that "
            "provides only the required operation."
        )

        verification = (
            f"Verify that '{entry_point}' no longer has "
            f"unnecessary access to '{target}'."
        )

    # --------------------------------------------------------
    # RETURN REMEDIATION
    # --------------------------------------------------------

    return {
        "action": action,
        "least_privilege": least_privilege,
        "verification": verification
    }


def display_remediation(remediation):

    print("\n" + "=" * 70)
    print("REMEDIATION")
    print("=" * 70)

    print("\nRecommended Action:")

    print(
        f"  {remediation['action']}"
    )

    print("\nLeast Privilege:")

    print(
        f"  {remediation['least_privilege']}"
    )

    print("\nVerification:")

    print(
        f"  {remediation['verification']}"
    )

    print("\n" + "=" * 70)