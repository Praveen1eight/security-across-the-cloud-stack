import json
from pathlib import Path


# ============================================================
# SECURITY ACROSS CLOUD STACK
# SECURITY GRAPH / ATTACK PATH ENGINE
# ============================================================


# ============================================================
# LOAD INVENTORY
# ============================================================

def load_inventory(path=None):

    if path is None:
        path = Path(__file__).parent / "azure_inventory.json"

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


# ============================================================
# HELPERS
# ============================================================

def normalize_scope(scope):

    if not scope:
        return ""

    return str(scope).lower().rstrip("/")


def role_name_from_id(role_id):

    role_names = {

        "8e3af657-a8ff-443c-a75c-2fe8c4bcb635":
            "Owner",

        "4633458b-17de-408a-b874-0445c86b69e6":
            "Key Vault Secrets User",

        "b86a8fe4-44ce-4948-aee5-eccb2c155cd7":
            "Key Vault Secrets Officer"
    }

    return role_names.get(
        role_id,
        f"Role:{role_id}"
    )


def add_node(
    graph,
    node_id,
    node_type,
    name,
    **extra
):

    if not node_id:
        return

    graph["nodes"][node_id] = {
        "type": node_type,
        "name": name,
        **extra
    }


def add_edge(
    graph,
    source,
    target,
    relationship
):

    if not source or not target:
        return

    edge = {
        "source": normalize_scope(source),
        "target": normalize_scope(target),
        "relationship": relationship
    }

    if edge not in graph["edges"]:

        graph["edges"].append(edge)


# ============================================================
# RESOURCE LOOKUP
# ============================================================

def find_resource_by_id(
    inventory,
    resource_id
):

    resource_id = normalize_scope(
        resource_id
    )

    for resource in inventory.get(
        "resources",
        []
    ):

        if normalize_scope(
            resource.get("id")
        ) == resource_id:

            return resource

    return None


def find_resource_by_name(
    inventory,
    name
):

    if not name:
        return None

    for resource in inventory.get(
        "resources",
        []
    ):

        if str(
            resource.get("name", "")
        ).lower() == str(name).lower():

            return resource

    return None


# ============================================================
# BUILD SECURITY GRAPH
# ============================================================

def build_graph(inventory):

    graph = {
        "nodes": {},
        "edges": []
    }

    # ========================================================
    # AZURE RESOURCES
    # ========================================================

    for resource in inventory.get(
        "resources",
        []
    ):

        resource_id = normalize_scope(
            resource.get("id")
        )

        if not resource_id:
            continue

        add_node(
            graph,
            resource_id,
            resource.get(
                "type",
                "AzureResource"
            ),
            resource.get(
                "name",
                resource_id
            )
        )

    # ========================================================
    # INTERNET
    # ========================================================

    internet_node = "internet"

    add_node(
        graph,
        internet_node,
        "Internet",
        "Internet"
    )

    # ========================================================
    # PUBLIC IP -> INTERNET
    # ========================================================

    for resource in inventory.get(
        "resources",
        []
    ):

        resource_type = str(
            resource.get("type", "")
        ).lower()

        if resource_type == (
            "microsoft.network/publicipaddresses"
        ):

            public_ip_id = normalize_scope(
                resource.get("id")
            )

            add_edge(
                graph,
                internet_node,
                public_ip_id,
                "EXPOSED_TO_INTERNET"
            )

    # ========================================================
    # NETWORK RELATIONSHIPS FROM COLLECTOR
    # ========================================================
    #
    # Actual inventory structure:
    #
    # inventory["network"]["relationships"]
    #
    # Examples collected:
    #
    # NIC -> Subnet
    # Subnet -> VNet
    # Public IP -> NIC
    # VM -> NIC
    # NSG -> Subnet
    #
    # ========================================================

    network_data = inventory.get(
        "network",
        {}
    )

    network_relationships = network_data.get(
        "relationships",
        []
    )

    for relationship in network_relationships:

        if not isinstance(
            relationship,
            dict
        ):
            continue

        source = relationship.get(
            "source"
        )

        target = relationship.get(
            "target"
        )

        relation = relationship.get(
            "relationship"
        )

        if source and target:

            # Keep the collector relationship exactly as collected.
            add_edge(
                graph,
                source,
                target,
                relation or "NETWORK_ACCESS"
            )

            # Derived traversal edges used by the attack-path engine.
            # The collector stores VM -> NIC, but an inbound path
            # reaching a NIC must be able to continue to the VM.
            if relation == "uses_nic":
                add_edge(
                    graph,
                    target,
                    source,
                    "NIC_TO_VM"
                )

            # The collector stores Public IP -> NIC.
            # Attack-path traversal needs the reverse direction so that
            # Internet -> Public IP can continue to the NIC.
            elif relation == "attached_to_nic":
                add_edge(
                    graph,
                    target,
                    source,
                    "NIC_TO_PUBLIC_IP"
                )

            # The collector stores NIC -> Subnet, but a public subnet
            # exposure must be able to continue from the subnet to NICs.
            elif relation == "connected_to_subnet":
                add_edge(
                    graph,
                    target,
                    source,
                    "SUBNET_TO_NIC"
                )

            # Derived attack-path traversal edges.
            # The collector stores resource association direction,
            # while attack paths need forward reachability direction.
            if relation == "uses_nic":
                add_edge(
                    graph,
                    target,
                    source,
                    "NIC_TO_VM"
                )

            elif relation == "connected_to_subnet":
                add_edge(
                    graph,
                    target,
                    source,
                    "SUBNET_TO_NIC"
                )

    # ========================================================
    # NETWORK FINDINGS
    # ========================================================
    #
    # network_analyzer.py produces:
    #
    # network_findings.json
    #
    # We load that file separately because the findings are
    # not stored at the top level of azure_inventory.json.
    #
    # ========================================================

    findings_path = (
        Path(__file__).parent
        / "network_findings.json"
    )

    network_findings = []

    if findings_path.exists():

        try:

            with open(
                findings_path,
                "r",
                encoding="utf-8"
            ) as file:

                network_findings = json.load(
                    file
                )

        except (
            json.JSONDecodeError,
            OSError
        ):

            network_findings = []

    # ========================================================
    # PUBLIC NETWORK EXPOSURE
    # ========================================================
    #
    # For a finding such as:
    #
    # Publicly exposed TCP/80 service
    #
    # connect Internet to the affected subnet.
    #
    # ========================================================

    for finding in network_findings:

        if not isinstance(
            finding,
            dict
        ):
            continue

        if finding.get(
            "type"
        ) != "PublicNetworkExposure":

            continue

        exposed_subnets = finding.get(
            "exposed_subnets",
            []
        )

        for subnet_id in exposed_subnets:

            subnet_id = normalize_scope(
                subnet_id
            )

            if not subnet_id:
                continue

            add_edge(
                graph,
                internet_node,
                subnet_id,
                "PUBLIC_NETWORK_EXPOSURE"
            )

    # ========================================================
    # MANAGED IDENTITIES
    # ========================================================

    for identity in inventory.get(
        "managed_identities",
        []
    ):

        principal_id = identity.get(
            "principal_id"
        )

        resource_name = identity.get(
            "resource"
        )

        if not principal_id:
            continue

        identity_node = (
            f"identity:{principal_id}"
        )

        principal_node = (
            f"principal:{principal_id}"
        )

        add_node(
            graph,
            identity_node,
            "ManagedIdentity",
            resource_name,
            principal_id=principal_id
        )

        resource = find_resource_by_name(
            inventory,
            resource_name
        )

        if resource:

            resource_id = normalize_scope(
                resource.get("id")
            )

            # Resource -> Managed Identity

            add_edge(
                graph,
                resource_id,
                identity_node,
                "USES_IDENTITY"
            )

            # Managed Identity -> Principal

            add_edge(
                graph,
                identity_node,
                principal_node,
                "IDENTITY_PRINCIPAL"
            )

    # ========================================================
    # RBAC ROLE ASSIGNMENTS
    # ========================================================

    for assignment in inventory.get(
        "role_assignments",
        []
    ):

        principal_id = assignment.get(
            "principal_id"
        )

        scope = normalize_scope(
            assignment.get("scope")
        )

        if not principal_id or not scope:
            continue

        role_definition_id = assignment.get(
            "role_definition_id",
            ""
        )

        role_id = (
            role_definition_id
            .split("/")[-1]
            .lower()
        )

        principal_node = (
            f"principal:{principal_id}"
        )

        role_node = (
            f"role:{role_id}"
        )

        principal_name = assignment.get(
            "principal_name",
            principal_id
        )

        role_name = assignment.get(
            "role_name"
        )

        if not role_name:

            role_name = role_name_from_id(
                role_id
            )

        # Principal

        add_node(
            graph,
            principal_node,
            assignment.get(
                "principal_type",
                "Principal"
            ),
            principal_name,
            principal_id=principal_id
        )

        # Role

        add_node(
            graph,
            role_node,
            "Role",
            role_name,
            role_definition_id=role_id
        )

        # Principal -> Role

        add_edge(
            graph,
            principal_node,
            role_node,
            "ASSIGNED_ROLE"
        )

        # Role -> Scope

        add_edge(
            graph,
            role_node,
            scope,
            "CAN_ACCESS"
        )

    # ========================================================
    # KEY VAULT -> SECRET
    # ========================================================

    for secret in inventory.get(
        "secrets",
        []
    ):

        secret_id = normalize_scope(
            secret.get("id")
        )

        if not secret_id:
            continue

        add_node(
            graph,
            secret_id,
            "Secret",
            secret.get(
                "name",
                secret_id
            )
        )

        # Key Vault ID is everything before /secrets/

        if "/secrets/" in secret_id:

            vault_id = secret_id.split(
                "/secrets/",
                1
            )[0]

            add_edge(
                graph,
                vault_id,
                secret_id,
                "CONTAINS"
            )

    return graph


# ============================================================
# FIND ATTACK PATHS
# ============================================================

def find_paths(
    graph,
    start_node,
    target_node
):

    paths = []

    start_node = normalize_scope(
        start_node
    )

    target_node = normalize_scope(
        target_node
    )

    def dfs(
        current,
        path,
        visited
    ):

        if current == target_node:

            paths.append(
                path.copy()
            )

            return

        for edge in graph["edges"]:

            if normalize_scope(
                edge["source"]
            ) != current:

                continue

            next_node = normalize_scope(
                edge["target"]
            )

            if next_node in visited:
                continue

            visited.add(
                next_node
            )

            path.append(
                edge
            )

            dfs(
                next_node,
                path,
                visited
            )

            path.pop()

            visited.remove(
                next_node
            )

    dfs(
        start_node,
        [],
        {start_node}
    )

    return paths


# ============================================================
# DISPLAY ATTACK PATH
# ============================================================

def display_path(
    graph,
    path
):

    print("\n" + "=" * 70)
    print("ATTACK PATH")
    print("=" * 70)

    if not path:

        print(
            "\n[!] Empty attack path."
        )

        return

    first_source = graph[
        "nodes"
    ].get(
        path[0]["source"],
        {}
    )

    first_name = first_source.get(
        "name",
        path[0]["source"]
    )

    print(
        f"\nENTRY: {first_name}"
    )

    for edge in path:

        target = graph[
            "nodes"
        ].get(
            edge["target"],
            {}
        )

        target_name = target.get(
            "name",
            edge["target"]
        )

        relationship = edge.get(
            "relationship",
            "UNKNOWN"
        )

        print("    │")

        print(
            f"    └── {relationship}"
        )

        print(
            "          ↓"
        )

        print(
            f"      {target_name}"
        )

    print(
        "\n" + "=" * 70
    )

# ============================================================
# DETAILED ANALYSIS / CLI
# ============================================================

def node_name(graph, node_id):
    node = graph.get("nodes", {}).get(node_id, {})
    return node.get("name", node_id)


def discover_sensitive_targets(graph):
    """Return real protected assets, not IAM permission nodes."""
    targets = []

    sensitive_types = {
        "secret",
        "microsoft.keyvault/vaults",
    }

    sensitive_keywords = (
        "key vault",
        "secret",
        "storage",
        "database",
        "sql",
    )

    for node_id, node in graph.get("nodes", {}).items():
        node_type = str(node.get("type", "")).lower()
        name = str(node.get("name", "")).lower()

        # Roles, principals, identities and other permission nodes are
        # deliberately not treated as sensitive targets.
        if node_type in sensitive_types:
            targets.append(node_id)
        elif node_type not in {"role", "user", "serviceprincipal", "managedidentity"}:
            if any(keyword in name for keyword in sensitive_keywords):
                targets.append(node_id)

    return targets


def print_detailed_inventory(inventory):
    print("\n" + "=" * 70)
    print("INVENTORY SUMMARY")
    print("=" * 70)

    print(f"\n[+] Azure resources           : {len(inventory.get('resources', []))}")
    print(f"[+] Managed identities        : {len(inventory.get('managed_identities', []))}")
    print(f"[+] RBAC assignments          : {len(inventory.get('role_assignments', []))}")

    network = inventory.get("network", {})
    print(f"[+] Network relationships     : {len(network.get('relationships', []))}")


def print_detailed_graph(graph):
    print("\n" + "=" * 70)
    print("SECURITY GRAPH")
    print("=" * 70)

    print(f"\n[+] Graph nodes               : {len(graph.get('nodes', {}))}")
    print(f"[+] Graph edges               : {len(graph.get('edges', []))}")

    print("\n--- Nodes ---")
    for node_id, node in graph.get("nodes", {}).items():
        node_type = node.get("type", "Unknown")
        name = node.get("name", node_id)
        print(f"  [{node_type}] {name}")

    print("\n--- Relationships ---")
    for edge in graph.get("edges", []):
        source = node_name(graph, edge.get("source", ""))
        target = node_name(graph, edge.get("target", ""))
        relationship = edge.get("relationship", "UNKNOWN")
        print(f"  {source} --[{relationship}]--> {target}")


def print_sensitive_targets(graph, targets):
    print("\n" + "=" * 70)
    print("SENSITIVE TARGETS")
    print("=" * 70)

    if not targets:
        print("\n[!] No sensitive targets discovered.")
        return

    for index, target in enumerate(targets, 1):
        node = graph.get("nodes", {}).get(target, {})
        print(f"\n[{index}] {node.get('name', target)}")
        print(f"    ID   : {target}")
        print(f"    Type : {node.get('type', 'Unknown')}")


def write_security_report(
    inventory,
    graph,
    sensitive_targets,
    all_paths
):
    """Write the IaaS + Identity analysis result for cross-model comparison."""

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
    }

    # Network findings are the concrete security findings available to
    # this analyzer. Preserve their original data and count severities
    # when present.
    network_findings = []
    findings_path = Path(__file__).parent / "network_findings.json"

    if findings_path.exists():
        try:
            with open(
                findings_path,
                "r",
                encoding="utf-8"
            ) as file:
                loaded_findings = json.load(file)

            if isinstance(loaded_findings, list):
                network_findings = loaded_findings

        except (
            json.JSONDecodeError,
            OSError
        ):
            network_findings = []

    for finding in network_findings:
        if not isinstance(finding, dict):
            continue

        severity = str(
            finding.get("severity", "")
        ).upper()

        if severity in severity_counts:
            severity_counts[severity] += 1

    total_findings = sum(severity_counts.values())

    # Derive a bounded risk score from the findings and attack paths.
    # An absence of reachable attack paths must not itself create a
    # false positive.
    risk_score = (
        severity_counts["CRITICAL"] * 30
        + severity_counts["HIGH"] * 20
        + severity_counts["MEDIUM"] * 10
        + severity_counts["LOW"] * 5
    )

    risk_score += min(len(all_paths) * 20, 40)
    risk_score = min(risk_score, 100)

    if risk_score >= 80:
        risk_rating = "CRITICAL"
    elif risk_score >= 60:
        risk_rating = "HIGH"
    elif risk_score >= 30:
        risk_rating = "MEDIUM"
    elif risk_score > 0:
        risk_rating = "LOW"
    else:
        risk_rating = "SECURE"

    attack_path_reports = []

    for target, path in all_paths:
        attack_path_reports.append({
            "target": target,
            "target_name": node_name(graph, target),
            "length": len(path),
            "path": [
                {
                    "source": edge.get("source"),
                    "source_name": node_name(
                        graph,
                        edge.get("source", "")
                    ),
                    "target": edge.get("target"),
                    "target_name": node_name(
                        graph,
                        edge.get("target", "")
                    ),
                    "relationship": edge.get(
                        "relationship",
                        "UNKNOWN"
                    )
                }
                for edge in path
            ]
        })

    report = {
        "model": "IaaS",
        "scope": "IaaS + Identity",
        "risk_score": risk_score,
        "risk_rating": risk_rating,

        "findings": {
            "total": total_findings,
            "counts": severity_counts,
            "network_findings": network_findings
        },

        "inventory": {
            "resources": len(
                inventory.get("resources", [])
            ),
            "managed_identities": len(
                inventory.get("managed_identities", [])
            ),
            "rbac_assignments": len(
                inventory.get("role_assignments", [])
            ),
            "network_relationships": len(
                inventory.get("network", {}).get(
                    "relationships",
                    []
                )
            )
        },

        "graph": {
            "nodes": len(
                graph.get("nodes", {})
            ),
            "edges": len(
                graph.get("edges", [])
            )
        },

        "sensitive_targets": [
            {
                "id": target,
                "name": node_name(graph, target),
                "type": graph.get(
                    "nodes",
                    {}
                ).get(
                    target,
                    {}
                ).get(
                    "type",
                    "Unknown"
                )
            }
            for target in sensitive_targets
        ],

        "attack_paths": {
            "count": len(all_paths),
            "paths": attack_path_reports
        }
    }

    output_path = Path(__file__).parent / "security_report.json"

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

    print(
        f"\n[+] IaaS security report: {output_path}"
    )

    return report


def run_analyzer():
    print("\n" + "=" * 70)
    print("SECURITY ACROSS CLOUD STACK")
    print("IaaS + IDENTITY SECURITY ANALYZER")
    print("=" * 70)

    inventory = load_inventory()
    graph = build_graph(inventory)
    sensitive_targets = discover_sensitive_targets(graph)

    print_detailed_inventory(inventory)
    print_detailed_graph(graph)
    print_sensitive_targets(graph, sensitive_targets)

    print("\n" + "=" * 70)
    print("ATTACK PATH ANALYSIS")
    print("=" * 70)

    print("\n[+] Entry point              : Internet")
    print(f"[+] Sensitive targets checked: {len(sensitive_targets)}")

    all_paths = []

    for target in sensitive_targets:
        paths = find_paths(
            graph,
            "internet",
            target
        )

        for path in paths:
            all_paths.append((target, path))

    print(f"[+] Attack paths discovered  : {len(all_paths)}")

    if not all_paths:
        print("\n[!] No attack paths discovered from Internet to sensitive targets.")
        print("[+] This means the current graph contains no reachable")
        print("    Internet-to-sensitive-target path.")
    else:
        for index, (target, path) in enumerate(all_paths, 1):
            print(f"\n[+] Path #{index} reaches: {node_name(graph, target)}")
            display_path(graph, path)

    write_security_report(
        inventory,
        graph,
        sensitive_targets,
        all_paths
    )

    print("\n" + "=" * 70)
    print("ANALYSIS COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    run_analyzer()
