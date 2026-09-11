from analyzer import (
    load_inventory,
    build_graph,
    find_paths,
    display_path
)

from risk_engine import (
    analyze_path,
    display_finding
)

from report_generator import (
    generate_report,
    save_report
)

from remediation_engine import (
    generate_remediation,
    display_remediation
)


def main():

    print("=" * 70)
    print("       SECURITY ACROSS CLOUD STACK")
    print("             ATTACK PATH DETECTOR")
    print("=" * 70)

    # ========================================================
    # LOAD INVENTORY
    # ========================================================

    inventory = load_inventory()

    # ========================================================
    # BUILD SECURITY GRAPH
    # ========================================================

    graph = build_graph(
        inventory
    )

    print(
        f"\n[+] Graph nodes : "
        f"{len(graph['nodes'])}"
    )

    print(
        f"[+] Graph edges : "
        f"{len(graph['edges'])}"
    )

    # ========================================================
    # SENSITIVE TARGETS
    # ========================================================

    secrets = inventory.get(
        "secrets",
        []
    )

    if not secrets:

        print(
            "\n[!] No sensitive targets discovered."
        )

        return

    print(
        f"[+] Sensitive targets discovered: "
        f"{len(secrets)}"
    )

    # ========================================================
    # ENTRY POINTS
    # ========================================================

    entry_points = []

    # --------------------------------------------------------
    # INTERNET
    # --------------------------------------------------------

    entry_points.append(
        "internet"
    )

    # --------------------------------------------------------
    # USERS
    # --------------------------------------------------------

    for node_id, node in graph["nodes"].items():

        if node.get("type") == "User":

            if node_id not in entry_points:

                entry_points.append(
                    node_id
                )

    # --------------------------------------------------------
    # MANAGED IDENTITY WORKLOADS
    # --------------------------------------------------------

    for identity in inventory.get(
        "managed_identities",
        []
    ):

        resource_name = identity.get(
            "resource"
        )

        resource = next(
            (
                resource
                for resource in inventory.get(
                    "resources",
                    []
                )
                if resource.get("name")
                == resource_name
            ),
            None
        )

        if resource:

            resource_id = (
                resource.get("id", "")
                .lower()
                .rstrip("/")
            )

            if (
                resource_id
                and resource_id not in entry_points
            ):

                entry_points.append(
                    resource_id
                )

    print(
        f"[+] Entry points discovered: "
        f"{len(entry_points)}"
    )

    # ========================================================
    # FIND ATTACK PATHS
    # ========================================================

    findings = []

    for entry in entry_points:

        for secret in secrets:

            target = (
                secret.get("id", "")
                .lower()
                .rstrip("/")
            )

            if not target:
                continue

            paths = find_paths(
                graph,
                entry,
                target
            )

            for path in paths:

                # --------------------------------------------
                # DISPLAY ATTACK PATH
                # --------------------------------------------

                display_path(
                    graph,
                    path
                )

                # --------------------------------------------
                # ANALYZE PATH
                # --------------------------------------------

                finding = analyze_path(
                    graph,
                    path
                )

                findings.append(
                    finding
                )

                # --------------------------------------------
                # DISPLAY SECURITY FINDING
                # --------------------------------------------

                display_finding(
                    finding
                )

                # --------------------------------------------
                # GENERATE REMEDIATION
                # --------------------------------------------

                remediation = generate_remediation(
                    finding
                )

                finding["remediation"] = remediation

                # --------------------------------------------
                # DISPLAY REMEDIATION
                # --------------------------------------------

                display_remediation(
                    remediation
                )

    # ========================================================
    # GENERATE SECURITY REPORT
    # ========================================================

    report = generate_report(
        findings
    )

    report_path = save_report(
        report
    )

    # ========================================================
    # FINAL SUMMARY
    # ========================================================

    print("\n" + "=" * 70)
    print("SECURITY ANALYSIS COMPLETE")
    print("=" * 70)

    print(
        f"\n[+] Attack paths detected : "
        f"{len(findings)}"
    )

    print(
        f"[+] Critical findings     : "
        f"{report['summary']['critical']}"
    )

    print(
        f"[+] High findings         : "
        f"{report['summary']['high']}"
    )

    print(
        f"[+] Medium findings       : "
        f"{report['summary']['medium']}"
    )

    print(
        f"[+] Low findings          : "
        f"{report['summary']['low']}"
    )

    print(
        "\n[+] Security report written to:"
    )

    print(
        f"    {report_path}"
    )

    print("\n" + "=" * 70)


if __name__ == "__main__":

    main()