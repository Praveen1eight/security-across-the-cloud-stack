# ============================================================
# SECURITY ACROSS CLOUD STACK
# RISK / FINDING ENGINE
# ============================================================


ROLE_RISK = {
    "Owner": 40,
    "Key Vault Secrets Officer": 35,
    "Key Vault Secrets User": 30,
}


def get_node_name(graph, node_id):

    node = graph["nodes"].get(
        node_id,
        {}
    )

    return node.get(
        "name",
        node.get(
            "principal_id",
            node_id
        )
    )


def get_role_name(graph, path):

    for edge in path:

        if edge["relationship"] != "ASSIGNED_ROLE":
            continue

        role = graph["nodes"].get(
            edge["target"],
            {}
        )

        return role.get(
            "name",
            "Unknown Role"
        )

    return "Unknown Role"


# ============================================================
# RISK SCORE CALCULATION
# ============================================================


def calculate_risk_score(graph, path):

    score = 0

    risk_factors = []

    relationships = [
        edge["relationship"]
        for edge in path
    ]

    role_name = get_role_name(
        graph,
        path
    )

    # --------------------------------------------------------
    # 1. Sensitive secret target
    # --------------------------------------------------------

    if "CONTAINS" in relationships:

        points = 30

        score += points

        risk_factors.append({
            "points": points,
            "reason": "Sensitive secret target"
        })

    # --------------------------------------------------------
    # 2. Secret access permission
    # --------------------------------------------------------

    if "CAN_ACCESS" in relationships:

        points = 20

        score += points

        risk_factors.append({
            "points": points,
            "reason": "Direct secret access"
        })

    # --------------------------------------------------------
    # 3. RBAC privilege
    # --------------------------------------------------------

    role_points = ROLE_RISK.get(
        role_name,
        15
    )

    score += role_points

    risk_factors.append({
        "points": role_points,
        "reason": f"Privileged role: {role_name}"
    })

    # --------------------------------------------------------
    # 4. Managed identity path
    # --------------------------------------------------------

    if (
        "USES_IDENTITY" in relationships
        and
        "IDENTITY_PRINCIPAL" in relationships
    ):

        points = 10

        score += points

        risk_factors.append({
            "points": points,
            "reason": "Managed identity attack path"
        })

    # --------------------------------------------------------
    # 5. Direct identity path
    # --------------------------------------------------------

    elif (
        "USES_IDENTITY" not in relationships
        and
        "IDENTITY_PRINCIPAL" not in relationships
    ):

        points = 5

        score += points

        risk_factors.append({
            "points": points,
            "reason": "Direct identity path"
        })

    # --------------------------------------------------------
    # Maximum score
    # --------------------------------------------------------

    score = min(
        score,
        100
    )

    return score, risk_factors


# ============================================================
# SEVERITY
# ============================================================


def severity_from_score(score):

    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 40:
        return "MEDIUM"

    return "LOW"


# ============================================================
# PATH ANALYSIS
# ============================================================


def analyze_path(graph, path):

    relationships = [
        edge["relationship"]
        for edge in path
    ]

    # --------------------------------------------------------
    # Entry point
    # --------------------------------------------------------

    entry_point = get_node_name(
        graph,
        path[0]["source"]
    )

    # --------------------------------------------------------
    # Target
    # --------------------------------------------------------

    target = get_node_name(
        graph,
        path[-1]["target"]
    )

    # --------------------------------------------------------
    # Role
    # --------------------------------------------------------

    role_name = get_role_name(
        graph,
        path
    )

    # --------------------------------------------------------
    # Risk analysis
    # --------------------------------------------------------

    score, risk_factors = calculate_risk_score(
        graph,
        path
    )

    severity = severity_from_score(
        score
    )

    # --------------------------------------------------------
    # Finding type
    # --------------------------------------------------------

    if (
        "USES_IDENTITY" in relationships
        and
        "IDENTITY_PRINCIPAL" in relationships
    ):

        title = (
            "Managed identity can reach a sensitive secret"
        )

        reason = (
            f"The workload '{entry_point}' uses a managed "
            f"identity that is assigned the '{role_name}' "
            f"role. That role provides access to the "
            f"Key Vault containing '{target}'."
        )

        impact = (
            "If the workload or its managed identity is "
            "compromised, an attacker may be able to "
            "access the sensitive secret."
        )

        recommendation = (
            "Review whether this workload requires "
            f"'{role_name}' access. Apply least privilege "
            "and remove unnecessary Key Vault permissions."
        )

    else:

        title = (
            "Identity has direct access to a sensitive secret"
        )

        reason = (
            f"The identity '{entry_point}' has the "
            f"'{role_name}' role, which provides access "
            f"to the Key Vault containing '{target}'."
        )

        impact = (
            "Compromise of this identity could allow "
            "an attacker to access sensitive Key Vault data."
        )

        recommendation = (
            f"Review the '{role_name}' assignment and "
            "reduce permissions to the minimum required."
        )

    # --------------------------------------------------------
    # Return finding
    # --------------------------------------------------------

    return {
        "severity": severity,
        "risk_score": score,
        "risk_factors": risk_factors,
        "title": title,
        "entry_point": entry_point,
        "role": role_name,
        "target": target,
        "reason": reason,
        "impact": impact,
        "recommendation": recommendation
    }


# ============================================================
# DISPLAY FINDING
# ============================================================


def display_finding(finding):

    print("\n" + "=" * 70)
    print("SECURITY FINDING")
    print("=" * 70)

    print(
        f"\nRisk Score   : "
        f"{finding['risk_score']}/100"
    )

    print(
        f"Severity     : "
        f"{finding['severity']}"
    )

    print(
        f"Title        : "
        f"{finding['title']}"
    )

    print(
        f"Entry Point  : "
        f"{finding['entry_point']}"
    )

    print(
        f"Permission   : "
        f"{finding['role']}"
    )

    print(
        f"Target       : "
        f"{finding['target']}"
    )

    # --------------------------------------------------------
    # Risk factor breakdown
    # --------------------------------------------------------

    print("\nRisk Factors:")

    for factor in finding["risk_factors"]:

        print(
            f"  +{factor['points']:02d}  "
            f"{factor['reason']}"
        )

    print(
        f"  {'-' * 30}"
    )

    print(
        f"  {finding['risk_score']:02d}   "
        f"Total Risk"
    )

    # --------------------------------------------------------
    # Explanation
    # --------------------------------------------------------

    print("\nWhy it matters:")

    print(
        f"  {finding['reason']}"
    )

    print("\nPotential impact:")

    print(
        f"  {finding['impact']}"
    )

    print("\nRecommendation:")

    print(
        f"  {finding['recommendation']}"
    )

    print("\n" + "=" * 70)