import json
import os

INPUT_FILE = "azure_inventory.json"
OUTPUT_FILE = "paas_security_report.json"


# ============================================================
# HELPERS
# ============================================================

def load_inventory():
    if not os.path.exists(INPUT_FILE):
        raise FileNotFoundError(
            f"{INPUT_FILE} not found. Run azure_collector.py first."
        )

    with open(INPUT_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def add_finding(findings, severity, title, description, recommendation):
    findings.append({
        "severity": severity,
        "title": title,
        "description": description,
        "recommendation": recommendation
    })


def severity_weight(severity):
    return {
        "CRITICAL": 10,
        "HIGH": 7,
        "MEDIUM": 4,
        "LOW": 2,
        "INFO": 0
    }.get(severity, 0)


def normalize(value):
    if value is None:
        return None
    return str(value).strip().lower()


def has_allow_all_rule(rules):
    for rule in rules or []:
        if not isinstance(rule, dict):
            continue

        ip = normalize(rule.get("ipAddress"))
        action = normalize(rule.get("action"))

        if action == "allow" and ip in ("any", "*", "0.0.0.0/0", "::/0"):
            return True

    return False


# ============================================================
# PAAS ANALYSIS
# ============================================================

def analyze_app_service(paas, findings):
    app = paas.get("app_service", {})
    config = app.get("site_config", {}) or {}

    # HTTPS
    https_only = app.get("https_only")
    if https_only is False:
        add_finding(
            findings,
            "HIGH",
            "HTTPS-only is disabled",
            "The App Service can accept HTTP traffic without enforcing HTTPS.",
            "Enable HTTPS Only so client traffic is redirected to HTTPS."
        )
    elif https_only is True:
        add_finding(
            findings,
            "INFO",
            "HTTPS-only is enabled",
            "The App Service enforces HTTPS for client connections.",
            "Keep HTTPS-only enabled."
        )
    else:
        add_finding(
            findings,
            "MEDIUM",
            "HTTPS-only setting could not be verified",
            "The collector did not return an explicit HTTPS-only value.",
            "Verify the App Service HTTPS-only setting manually."
        )

    # TLS
    tls = normalize(config.get("min_tls_version"))
    if tls in ("1.0", "1.1"):
        add_finding(
            findings,
            "HIGH",
            "Weak minimum TLS version",
            f"The App Service minimum TLS version is {config.get('min_tls_version')}.",
            "Raise the minimum TLS version to TLS 1.2 or stronger where supported."
        )
    elif tls in ("1.2", "1.3"):
        add_finding(
            findings,
            "INFO",
            "Strong minimum TLS version",
            f"The App Service minimum TLS version is {config.get('min_tls_version')}.",
            "Keep the minimum TLS version at a modern secure level."
        )
    else:
        add_finding(
            findings,
            "MEDIUM",
            "Minimum TLS version could not be verified",
            "No recognized minimum TLS version was returned.",
            "Configure and verify a modern minimum TLS version."
        )

    # FTP
    ftps = normalize(config.get("ftps_state"))
    if ftps in ("allallowed", "ftp"):
        add_finding(
            findings,
            "HIGH",
            "Insecure FTP access is allowed",
            f"The App Service FTP/FTPS state is {config.get('ftps_state')}.",
            "Disable FTP or restrict deployment access to FTPS only."
        )
    elif ftps in ("ftpsonly", "disabled"):
        add_finding(
            findings,
            "INFO",
            "FTP deployment channel is restricted",
            f"The App Service FTP/FTPS state is {config.get('ftps_state')}.",
            "Keep FTP disabled or FTPS-only."
        )
    else:
        add_finding(
            findings,
            "MEDIUM",
            "FTP/FTPS configuration could not be verified",
            "No recognized FTP/FTPS state was returned.",
            "Verify the deployment protocol configuration."
        )

    # HTTP/2
    http2 = config.get("http20_enabled")
    if http2 is True:
        add_finding(
            findings,
            "INFO",
            "HTTP/2 is enabled",
            "The App Service supports HTTP/2.",
            "Keep HTTP/2 enabled if compatible with the application."
        )

    # Remote debugging
    debugging = config.get("remote_debugging_enabled")
    if debugging is True:
        add_finding(
            findings,
            "HIGH",
            "Remote debugging is enabled",
            "Remote debugging increases the attack surface of the App Service.",
            "Disable remote debugging when it is not actively required."
        )
    elif debugging is False:
        add_finding(
            findings,
            "INFO",
            "Remote debugging is disabled",
            "Remote debugging is not enabled on the App Service.",
            "Keep remote debugging disabled in production."
        )

    # Public network access
    public_access = normalize(app.get("public_network_access"))
    if public_access in ("enabled", "true"):
        add_finding(
            findings,
            "MEDIUM",
            "App Service has public network access",
            "The App Service is reachable through its public network endpoint.",
            "If public exposure is unnecessary, restrict access using network controls such as access restrictions or private connectivity."
        )
    elif public_access in ("disabled", "false"):
        add_finding(
            findings,
            "INFO",
            "Public network access is disabled",
            "The App Service is configured without public network access.",
            "Keep public access disabled when the application does not require internet exposure."
        )
    else:
        add_finding(
            findings,
            "LOW",
            "Public network access could not be verified",
            "The collector did not return a recognized public network access state.",
            "Verify the App Service network exposure."
        )

    # Client certificates
    client_cert = app.get("client_cert_enabled")
    if client_cert is True:
        add_finding(
            findings,
            "INFO",
            "Client certificate authentication is enabled",
            "The App Service has client certificate support enabled.",
            "Keep this enabled when mutual TLS is part of the application's security design."
        )

    # Access restrictions
    ip_rules = config.get("ip_security_restrictions") or []
    if has_allow_all_rule(ip_rules):
        add_finding(
            findings,
            "HIGH",
            "App Service access restrictions allow everyone",
            "An allow rule accepts traffic from any IP address.",
            "Replace broad allow rules with only the trusted networks or addresses required by the application."
        )
    elif ip_rules:
        add_finding(
            findings,
            "INFO",
            "App Service access restrictions are configured",
            f"{len(ip_rules)} App Service access restriction rule(s) were collected.",
            "Review the rules periodically and remove unnecessary sources."
        )
    else:
        add_finding(
            findings,
            "LOW",
            "No App Service access restrictions were collected",
            "No IP access restriction rules were returned.",
            "Consider access restrictions when the application should only be reachable from trusted sources."
        )

    scm_rules = config.get("scm_ip_security_restrictions") or []
    if has_allow_all_rule(scm_rules):
        add_finding(
            findings,
            "HIGH",
            "SCM endpoint allows everyone",
            "An SCM access restriction allows traffic from any IP address.",
            "Restrict the deployment/SCM endpoint to trusted administrator or CI/CD networks."
        )


def analyze_authentication(paas, findings):
    auth = paas.get("authentication", {}) or {}

    enabled = auth.get("platform_enabled")
    action = normalize(auth.get("unauthenticated_action"))
    providers = auth.get("identity_providers") or {}

    if enabled is False:
        add_finding(
            findings,
            "MEDIUM",
            "App Service authentication is disabled",
            "The App Service authentication platform is not enabled.",
            "Enable platform authentication when the application requires authenticated access."
        )
    elif enabled is True:
        add_finding(
            findings,
            "INFO",
            "App Service authentication is enabled",
            "The App Service authentication platform is enabled.",
            "Keep authentication enabled and review configured identity providers."
        )

        if action in ("allowanonymous", "allow_anonymous"):
            add_finding(
                findings,
                "MEDIUM",
                "Unauthenticated access is allowed",
                "The authentication configuration permits unauthenticated clients.",
                "Require authentication if the application contains protected functionality or sensitive data."
            )

    configured_providers = []
    if isinstance(providers, dict):
        for name, value in providers.items():
            if isinstance(value, dict) and value:
                configured_providers.append(name)

    if configured_providers:
        add_finding(
            findings,
            "INFO",
            "Identity providers are configured",
            "Configured identity providers: " + ", ".join(configured_providers),
            "Review provider configuration and ensure only required providers are enabled."
        )


def analyze_settings(paas, findings):
    settings = paas.get("app_settings") or []

    key_vault_refs = [
        item for item in settings
        if isinstance(item, dict) and item.get("key_vault_reference") is True
    ]

    if key_vault_refs:
        add_finding(
            findings,
            "INFO",
            "Key Vault references detected in App Settings",
            f"{len(key_vault_refs)} App Setting(s) appear to use Azure Key Vault references.",
            "Prefer managed identity plus Key Vault references instead of storing long-lived secrets directly in application configuration."
        )

    non_kv_settings = [
        item for item in settings
        if isinstance(item, dict) and item.get("key_vault_reference") is False
    ]

    if non_kv_settings:
        add_finding(
            findings,
            "MEDIUM",
            "Application settings are present outside Key Vault references",
            f"{len(non_kv_settings)} App Setting(s) were collected without a detected Key Vault reference. Values were intentionally not stored.",
            "Review these settings for secrets and move sensitive values to Key Vault references."
        )

    connection_strings = paas.get("connection_strings") or []
    if connection_strings:
        add_finding(
            findings,
            "MEDIUM",
            "Connection strings are configured",
            f"{len(connection_strings)} connection string(s) were detected. Values were intentionally not collected.",
            "Review connection strings for sensitive credentials and prefer managed identity or Key Vault where supported."
        )
    else:
        add_finding(
            findings,
            "INFO",
            "No connection strings were detected",
            "The collector did not find App Service connection strings.",
            "Continue using identity-based authentication where possible."
        )


# ============================================================
# RISK SCORE
# ============================================================

def calculate_score(findings):
    weighted = sum(severity_weight(f["severity"]) for f in findings)

    # Keep the score bounded and easy to explain.
    score = min(100, weighted * 5)

    if score >= 80:
        rating = "CRITICAL"
    elif score >= 60:
        rating = "HIGH"
    elif score >= 30:
        rating = "MEDIUM"
    elif score > 0:
        rating = "LOW"
    else:
        rating = "SECURE"

    return score, rating


# ============================================================
# MAIN
# ============================================================

def main():
    print("=" * 70)
    print("       SECURITY ACROSS CLOUD STACK")
    print("              PAAS SECURITY ANALYZER")
    print("=" * 70)

    inventory = load_inventory()
    paas = inventory.get("paas")

    if not paas:
        print("\n[!] No PaaS data found in azure_inventory.json")
        print("[!] Run the updated azure_collector.py first.")
        return

    findings = []

    analyze_app_service(paas, findings)
    analyze_authentication(paas, findings)
    analyze_settings(paas, findings)

    score, rating = calculate_score(findings)

    report = {
        "service_model": "PaaS",
        "platform": "Azure App Service",
        "app_service": paas.get("app_service", {}).get("name"),
        "risk_score": score,
        "risk_rating": rating,
        "summary": {
            "total_findings": len(findings),
            "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high": sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "low": sum(1 for f in findings if f["severity"] == "LOW"),
            "info": sum(1 for f in findings if f["severity"] == "INFO")
        },
        "findings": findings
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print("\n" + "=" * 70)
    print("                    PAAS SECURITY RESULT")
    print("=" * 70)

    print(f"\n[+] App Service: {report['app_service']}")
    print(f"[+] Risk score: {score}/100")
    print(f"[+] Risk rating: {rating}")
    print(f"[+] Total findings: {len(findings)}")

    print("\n[+] Findings:")
    for number, finding in enumerate(findings, 1):
        print(
            f"    {number}. "
            f"[{finding['severity']}] "
            f"{finding['title']}"
        )

    print("\n[+] Finding counts:")
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        print(
            f"    {severity}: "
            f"{report['summary'][severity.lower()]}"
        )

    print("\n[+] Report:")
    print(f"    {OUTPUT_FILE}")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
