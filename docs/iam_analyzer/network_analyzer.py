# ============================================================
# SECURITY ACROSS CLOUD STACK
# IaaS NETWORK SECURITY ANALYZER
# ============================================================

import ipaddress
import json
from pathlib import Path


DANGEROUS_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    3389: "RDP",
    445: "SMB",
    139: "NetBIOS",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
}


# ============================================================
# HELPERS
# ============================================================

def is_public_source(source):
    """
    Returns True only when the rule allows traffic
    from the entire public internet.
    """

    if not source:
        return False

    if isinstance(source, list):
        return any(
            is_public_source(item)
            for item in source
        )

    source = str(source).strip()

    unrestricted_sources = {
        "*",
        "0.0.0.0/0",
        "::/0",
        "Internet",
        "Any",
    }

    return source in unrestricted_sources

def parse_ports(rule):
    """Extract destination ports from an NSG rule."""

    ports = []

    single_port = (
        rule.get("destinationPortRange")
        or rule.get("destination_port")
    )

    multiple_ports = (
        rule.get("destinationPortRanges")
        or rule.get("destination_ports")
        or []
    )

    if single_port:
        ports.append(str(single_port))

    if isinstance(multiple_ports, list):
        ports.extend(str(port) for port in multiple_ports)

    return ports


def get_source(rule):
    """Support both Azure CLI-style and collector-style fields."""

    return (
        rule.get("sourceAddressPrefix")
        or rule.get("source_address_prefix")
        or rule.get("source")
    )


def get_destination_port(rule):
    return (
        rule.get("destinationPortRange")
        or rule.get("destination_port")
    )


def port_description(port):
    try:
        port_number = int(port)
        return DANGEROUS_PORTS.get(
            port_number,
            f"TCP/{port_number}"
        )
    except (ValueError, TypeError):
        return str(port)


# ============================================================
# ANALYZE ONE NSG RULE
# ============================================================

def analyze_nsg_rule(nsg, rule):
    """
    Detect inbound NSG rules that expose services publicly.
    """

    direction = (
        rule.get("direction")
        or rule.get("direction")
    )

    access = (
        rule.get("access")
        or rule.get("access")
    )

    if direction != "Inbound":
        return []

    if access != "Allow":
        return []

    source = get_source(rule)

    if not is_public_source(source):
        return []

    ports = parse_ports(rule)

    findings = []

    for port in ports:

        if port == "*":
            findings.append({
                "type": "PublicNetworkExposure",
                "severity": "CRITICAL",
                "nsg": nsg.get("name"),
                "rule": rule.get("name"),
                "source": source,
                "protocol": rule.get("protocol"),
                "port": "*",
                "service": "ALL PORTS",
                "title": (
                    "Network security group allows all "
                    "inbound ports from the internet"
                ),
            })
            continue

        try:
            port_number = int(port)
        except (ValueError, TypeError):
            continue

        severity = (
            "CRITICAL"
            if port_number in DANGEROUS_PORTS
            else "HIGH"
        )

        findings.append({
            "type": "PublicNetworkExposure",
            "severity": severity,
            "nsg": nsg.get("name"),
            "rule": rule.get("name"),
            "source": source,
            "protocol": rule.get("protocol"),
            "port": port_number,
            "service": port_description(port_number),
            "title": (
                f"Publicly exposed "
                f"{port_description(port_number)} service"
            ),
        })

    return findings


# ============================================================
# ANALYZE ALL NSGs
# ============================================================

def analyze_network_security(inventory):
    """
    Analyze NSGs from the new Azure collector format.

    Expected:
        inventory["network"]["nsgs"]
    """

    findings = []

    # New collector format
    nsgs = (
        inventory
        .get("network", {})
        .get("nsgs", [])
    )

    # Backward compatibility with the old format
    if not nsgs:
        nsgs = inventory.get(
            "network_security_groups",
            []
        )

    for nsg in nsgs:

        # New collector format uses "rules"
        rules = nsg.get("rules", [])

        # Backward compatibility with Azure CLI format
        if not rules:
            rules = nsg.get(
                "securityRules",
                []
            )

        for rule in rules:
            findings.extend(
                analyze_nsg_rule(
                    nsg,
                    rule
                )
            )

    return findings


# ============================================================
# NETWORK ATTACK-PATH CONTEXT
# ============================================================

def build_exposure_context(inventory, findings):
    """
    Connect public exposure findings to the collected
    VM/NIC/subnet topology.
    """

    network = inventory.get("network", {})

    vnets = network.get("vnets", [])
    nics = network.get("network_interfaces", [])
    vms = network.get("virtual_machines", [])
    public_ips = network.get("public_ips", [])
    relationships = network.get("relationships", [])

    exposed_subnets = set()

    for nsg in network.get("nsgs", []):
        nsg_name = nsg.get("name")

        if any(
            finding.get("nsg") == nsg_name
            for finding in findings
        ):
            for subnet_id in nsg.get("subnet_ids", []):
                exposed_subnets.add(subnet_id)

    exposed_nics = set()
    exposed_vms = set()

    for relationship in relationships:

        if (
            relationship.get("relationship")
            == "connected_to_subnet"
            and relationship.get("target")
            in exposed_subnets
        ):
            exposed_nics.add(
                relationship.get("source")
            )

    for relationship in relationships:

        if (
            relationship.get("relationship")
            == "uses_nic"
            and relationship.get("target")
            in exposed_nics
        ):
            exposed_vms.add(
                relationship.get("source")
            )

    for finding in findings:

        finding["exposed_subnets"] = list(
            exposed_subnets
        )

        finding["exposed_nics"] = list(
            exposed_nics
        )

        finding["exposed_vms"] = list(
            exposed_vms
        )

    return findings


# ============================================================
# DISPLAY FINDINGS
# ============================================================

def display_network_findings(findings):

    print("\n" + "=" * 70)
    print("IaaS NETWORK SECURITY")
    print("=" * 70)

    if not findings:
        print(
            "\n[+] No public network exposures detected."
        )
        return

    for finding in findings:

        print("\n" + "-" * 70)

        print(
            f"Severity : {finding['severity']}"
        )

        print(
            f"Title    : {finding['title']}"
        )

        print(
            f"NSG      : {finding['nsg']}"
        )

        print(
            f"Rule     : {finding['rule']}"
        )

        print(
            f"Source   : {finding['source']}"
        )

        print(
            f"Protocol : {finding['protocol']}"
        )

        print(
            f"Port     : {finding['port']}"
        )

        print(
            f"Service  : {finding['service']}"
        )

        exposed_vms = finding.get(
            "exposed_vms",
            []
        )

        if exposed_vms:
            print(
                f"VM Path  : {len(exposed_vms)} VM(s) "
                "reachable through exposed subnet"
            )

        print("\nWhy it matters:")

        print(
            "  The NSG permits inbound traffic "
            "from a public source."
        )

        print("\nRecommendation:")

        print(
            "  Restrict the source to only the "
            "required IP range or trusted network."
        )

    print("\n" + "=" * 70)


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print("       SECURITY ACROSS CLOUD STACK")
    print("          IaaS NETWORK ANALYZER")
    print("=" * 70)

    inventory_file = Path("azure_inventory.json")

    if not inventory_file.exists():
        print(
            f"\n[!] {inventory_file} was not found."
        )
        print(
            "[!] Run 'python azure_collector.py' first."
        )
        return

    print(
        f"\n[+] Loading {inventory_file}..."
    )

    with inventory_file.open(
        "r",
        encoding="utf-8"
    ) as file:
        inventory = json.load(file)

    print("[+] Analyzing NSG rules...")

    findings = analyze_network_security(
        inventory
    )

    findings = build_exposure_context(
        inventory,
        findings
    )

    print(
        f"[+] Network findings: {len(findings)}"
    )

    display_network_findings(
        findings
    )

    output_file = Path(
        "network_findings.json"
    )

    with output_file.open(
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            findings,
            file,
            indent=4
        )

    print(
        f"\n[+] Output: {output_file}"
    )


if __name__ == "__main__":
    main()
