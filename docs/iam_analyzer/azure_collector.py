import json
import requests

from azure.identity import AzureCliCredential


# ============================================================
# AZURE CONFIGURATION
# ============================================================

SUBSCRIPTION_ID = "158f991b-d057-49dc-9bf0-2249fb1e289c"
TENANT_ID = "5f859e40-73a7-46b8-8484-6bf437063399"

RESOURCE_GROUP = "rg-security-cloud-stack"
APP_NAME = "security-cloud-stack-app-01"
KEY_VAULT_NAME = "kvseccloud01"


# ============================================================
# AZURE CLI AUTHENTICATION
# ============================================================

def get_credential():
    return AzureCliCredential()


def get_token():
    print("\n[+] Getting Azure access token...")

    try:
        credential = get_credential()
        token = credential.get_token(
            "https://management.azure.com/.default"
        )

        if not token or not token.token:
            raise RuntimeError("Azure access token was empty.")

        print("[+] Azure authentication successful.")
        return token.token

    except Exception as e:
        print("\n[!] Failed to obtain Azure access token.")
        print(f"[!] {e}")
        raise RuntimeError(
            "Azure authentication failed. "
            "Run 'az login --tenant "
            f"{TENANT_ID}' and try again."
        )


def get_graph_token():
    print("\n[+] Getting Microsoft Graph access token...")

    try:
        credential = get_credential()
        token = credential.get_token(
            "https://graph.microsoft.com/.default"
        )

        if not token or not token.token:
            raise RuntimeError(
                "Microsoft Graph access token was empty."
            )

        print("[+] Microsoft Graph authentication successful.")
        return token.token

    except Exception as e:
        print("\n[!] Microsoft Graph authentication failed.")
        print(f"[!] {e}")
        return None


# ============================================================
# GENERIC HTTP GET
# ============================================================

def azure_get(url, token):
    response = requests.get(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        },
        timeout=30
    )

    response.raise_for_status()
    return response.json()


def safe_azure_get(url, token):
    """
    Same as azure_get, but returns an empty Azure response
    instead of stopping the entire collector for optional data.
    """
    try:
        return azure_get(url, token)
    except requests.HTTPError as e:
        print(f"[!] Azure API request failed: {e}")
        return {"value": []}
    except requests.RequestException as e:
        print(f"[!] Azure API request failed: {e}")
        return {"value": []}


def azure_post(url, token):
    """
    POST helper for Azure endpoints that expose list operations
    through POST, such as App Service appsettings and
    connectionstrings.
    """
    response = requests.post(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        },
        json={},
        timeout=30
    )

    response.raise_for_status()
    return response.json()


def safe_azure_post(url, token):
    """
    Optional POST request helper. Returns an empty response instead
    of stopping the collector if the endpoint is unavailable.
    """
    try:
        return azure_post(url, token)
    except requests.HTTPError as e:
        print(f"[!] Azure API request failed: {e}")
        return {"properties": {}}
    except requests.RequestException as e:
        print(f"[!] Azure API request failed: {e}")
        return {"properties": {}}


# ============================================================
# COLLECT AZURE RESOURCES
# ============================================================

def collect_resources(token):
    print("[+] Collecting resources...")

    url = (
        "https://management.azure.com/subscriptions/"
        f"{SUBSCRIPTION_ID}/resources"
        "?api-version=2021-04-01"
    )

    data = azure_get(url, token)

    resources = []

    for resource in data.get("value", []):
        resources.append({
            "name": resource.get("name"),
            "type": resource.get("type"),
            "id": resource.get("id"),
            "resource_group": resource.get("resourceGroup"),
            "location": resource.get("location")
        })

    return resources


# ============================================================
# COLLECT RBAC ROLE ASSIGNMENTS
# ============================================================

def collect_role_assignments(token):
    print("[+] Collecting RBAC assignments...")

    url = (
        "https://management.azure.com/subscriptions/"
        f"{SUBSCRIPTION_ID}/providers/"
        "Microsoft.Authorization/roleAssignments"
        "?api-version=2022-04-01"
    )

    data = azure_get(url, token)

    assignments = []

    for item in data.get("value", []):
        properties = item.get("properties", {})

        assignments.append({
            "principal_id": properties.get("principalId"),
            "principal_type": properties.get("principalType"),
            "role_definition_id": properties.get("roleDefinitionId"),
            "scope": properties.get("scope")
        })

    return assignments


# ============================================================
# RESOLVE ROLE NAMES
# ============================================================

def collect_role_names(token, assignments):
    print("[+] Resolving RBAC role names...")

    for assignment in assignments:
        role_definition_id = assignment.get("role_definition_id")

        if not role_definition_id:
            assignment["role_name"] = "Unknown"
            continue

        role_id = role_definition_id.split("/")[-1]

        url = (
            "https://management.azure.com/subscriptions/"
            f"{SUBSCRIPTION_ID}/providers/"
            "Microsoft.Authorization/roleDefinitions/"
            f"{role_id}"
            "?api-version=2022-04-01"
        )

        try:
            data = azure_get(url, token)
            assignment["role_name"] = (
                data.get("properties", {}).get("roleName", role_id)
            )
        except requests.HTTPError:
            assignment["role_name"] = role_id

    return assignments


# ============================================================
# RESOLVE PRINCIPAL NAMES
# ============================================================

def collect_principal_names(graph_token, assignments):
    print("[+] Resolving principal names...")

    if not graph_token:
        print("[!] Graph token unavailable.")
        return assignments

    for assignment in assignments:
        principal_id = assignment.get("principal_id")
        assignment["principal_name"] = principal_id

        principal_type = assignment.get("principal_type")

        if principal_type == "ServicePrincipal":
            url = (
                "https://graph.microsoft.com/v1.0/"
                f"servicePrincipals/{principal_id}"
            )
        elif principal_type == "User":
            url = (
                "https://graph.microsoft.com/v1.0/"
                f"users/{principal_id}"
            )
        else:
            continue

        try:
            data = azure_get(url, graph_token)
            assignment["principal_name"] = (
                data.get("displayName")
                or data.get("userPrincipalName")
                or principal_id
            )
        except requests.HTTPError:
            pass

    return assignments


# ============================================================
# COLLECT APP SERVICE MANAGED IDENTITY
# ============================================================

def collect_app_identity(token):
    print("[+] Collecting App Service identity...")

    url = (
        "https://management.azure.com/subscriptions/"
        f"{SUBSCRIPTION_ID}/resourceGroups/"
        f"{RESOURCE_GROUP}/providers/"
        "Microsoft.Web/sites/"
        f"{APP_NAME}"
        "?api-version=2023-12-01"
    )

    data = azure_get(url, token)

    identity = data.get("identity", {})

    return {
        "resource": APP_NAME,
        "type": identity.get("type"),
        "principal_id": identity.get("principalId"),
        "tenant_id": identity.get("tenantId")
    }


# ============================================================
# COLLECT PAAS / APP SERVICE SECURITY CONFIGURATION
# ============================================================

def collect_paas_security(token):
    """
    Collect security-relevant Azure App Service configuration.

    Secret values are intentionally never written to the inventory.
    App settings are recorded only by name and whether they appear to
    contain an Azure Key Vault reference.
    """
    print("[+] Collecting PaaS App Service security configuration...")

    site_url = (
        "https://management.azure.com/subscriptions/"
        f"{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/"
        f"Microsoft.Web/sites/{APP_NAME}"
        "?api-version=2023-12-01"
    )

    site = safe_azure_get(site_url, token)
    properties = site.get("properties", {})
    site_config = properties.get("siteConfig") or {}

    # The site resource does not always return the complete web/siteConfig
    # security configuration. Query the dedicated /config/web endpoint so
    # TLS, FTPS and access restrictions can be assessed reliably.
    web_config_url = (
        "https://management.azure.com/subscriptions/"
        f"{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/"
        f"Microsoft.Web/sites/{APP_NAME}/config/web"
        "?api-version=2022-03-01"
    )
    web_config = safe_azure_get(web_config_url, token)
    web_config_properties = web_config.get("properties", {}) or {}

    # Prefer explicitly returned /config/web values, while retaining values
    # from the site resource when the dedicated endpoint omits a field.
    for key, value in web_config_properties.items():
        if value is not None:
            site_config[key] = value

    # Authentication configuration (optional for the lab App Service).
    auth_url = (
        "https://management.azure.com/subscriptions/"
        f"{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/"
        f"Microsoft.Web/sites/{APP_NAME}/config/authsettingsV2/list"
        "?api-version=2022-03-01"
    )
    auth = safe_azure_get(auth_url, token)

    # App settings can contain secrets. We collect names only.
    settings_url = (
        "https://management.azure.com/subscriptions/"
        f"{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/"
        f"Microsoft.Web/sites/{APP_NAME}/config/appsettings/list"
        "?api-version=2022-03-01"
    )
    settings_response = safe_azure_post(settings_url, token)
    settings = settings_response.get("properties", {}) or {}

    app_settings = []
    for name, value in settings.items():
        value_text = str(value or "")
        app_settings.append({
            "name": name,
            "key_vault_reference": value_text.startswith(
                "@Microsoft.KeyVault("
            )
        })

    # Connection strings are also sensitive; collect names/types only.
    connection_strings_url = (
        "https://management.azure.com/subscriptions/"
        f"{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}/providers/"
        f"Microsoft.Web/sites/{APP_NAME}/config/connectionstrings/list"
        "?api-version=2022-03-01"
    )
    connection_response = safe_azure_post(
        connection_strings_url,
        token
    )
    connection_strings = connection_response.get("properties", {}) or {}

    connection_string_metadata = []
    for name, config in connection_strings.items():
        if isinstance(config, dict):
            connection_string_metadata.append({
                "name": name,
                "type": config.get("type")
            })
        else:
            connection_string_metadata.append({
                "name": name,
                "type": None
            })

    return {
        "app_service": {
            "name": site.get("name") or APP_NAME,
            "id": site.get("id"),
            "kind": site.get("kind"),
            "state": properties.get("state"),
            "default_host_name": properties.get("defaultHostName"),
            "https_only": properties.get("httpsOnly"),
            "public_network_access": properties.get(
                "publicNetworkAccess"
            ),
            "client_cert_enabled": properties.get("clientCertEnabled"),
            "client_cert_mode": properties.get("clientCertMode"),
            "site_config": {
                "min_tls_version": site_config.get("minTlsVersion"),
                "ftps_state": site_config.get("ftpsState"),
                "http20_enabled": site_config.get("http20Enabled"),
                "always_on": site_config.get("alwaysOn"),
                "remote_debugging_enabled": site_config.get(
                    "remoteDebuggingEnabled"
                ),
                "ip_security_restrictions": site_config.get(
                    "ipSecurityRestrictions", []
                ),
                "scm_ip_security_restrictions": site_config.get(
                    "scmIpSecurityRestrictions", []
                )
            }
        },
        "authentication": {
            "platform_enabled": auth.get("properties", {}).get(
                "platform", {}
            ).get("enabled"),
            "unauthenticated_action": auth.get("properties", {}).get(
                "globalValidation", {}
            ).get("unauthenticatedClientAction"),
            "identity_providers": auth.get("properties", {}).get(
                "identityProviders", {}
            )
        },
        "app_settings": app_settings,
        "connection_strings": connection_string_metadata
    }


# ============================================================
# COLLECT KEY VAULT
# ============================================================

def collect_key_vault(token):
    print("[+] Collecting Key Vault...")

    url = (
        "https://management.azure.com/subscriptions/"
        f"{SUBSCRIPTION_ID}/resourceGroups/"
        f"{RESOURCE_GROUP}/providers/"
        "Microsoft.KeyVault/vaults/"
        f"{KEY_VAULT_NAME}"
        "?api-version=2023-07-01"
    )

    data = azure_get(url, token)

    return {
        "name": data.get("name"),
        "id": data.get("id"),
        "type": data.get("type")
    }


# ============================================================
# COLLECT KEY VAULT SECRET METADATA
# ============================================================

def collect_secrets(token):
    print("[+] Collecting Key Vault secret metadata...")

    url = (
        "https://management.azure.com/subscriptions/"
        f"{SUBSCRIPTION_ID}/resourceGroups/"
        f"{RESOURCE_GROUP}/providers/"
        "Microsoft.KeyVault/vaults/"
        f"{KEY_VAULT_NAME}/secrets"
        "?api-version=2023-07-01"
    )

    data = safe_azure_get(url, token)

    secrets = []

    for secret in data.get("value", []):
        secrets.append({
            "name": secret.get("name"),
            "id": secret.get("id")
        })

    return secrets


# ============================================================
# NETWORK: VNETS AND SUBNETS
# ============================================================

def collect_vnets(token):
    print("[+] Collecting VNet and subnet topology...")

    url = (
        "https://management.azure.com/subscriptions/"
        f"{SUBSCRIPTION_ID}/providers/"
        "Microsoft.Network/virtualNetworks"
        "?api-version=2023-09-01"
    )

    data = safe_azure_get(url, token)
    vnets = []

    for vnet in data.get("value", []):
        vnet_item = {
            "name": vnet.get("name"),
            "id": vnet.get("id"),
            "resource_group": vnet.get("resourceGroup"),
            "location": vnet.get("location"),
            "address_space": (
                vnet.get("properties", {})
                .get("addressSpace", {})
                .get("addressPrefixes", [])
            ),
            "subnets": []
        }

        for subnet in vnet.get("properties", {}).get("subnets", []):
            subnet_props = subnet.get("properties", {})

            nsg_id = (
                subnet_props.get("networkSecurityGroup", {})
                .get("id")
            )

            vnet_item["subnets"].append({
                "name": subnet.get("name"),
                "id": subnet.get("id"),
                "address_prefixes": subnet_props.get(
                    "addressPrefixes",
                    []
                ) or (
                    [subnet_props.get("addressPrefix")]
                    if subnet_props.get("addressPrefix")
                    else []
                ),
                "nsg_id": nsg_id,
                "private_endpoint_network_policies": subnet_props.get(
                    "privateEndpointNetworkPolicies"
                )
            })

        vnets.append(vnet_item)

    return vnets


# ============================================================
# NETWORK: NSGS AND SECURITY RULES
# ============================================================

def collect_nsgs(token):
    print("[+] Collecting NSGs and security rules...")

    url = (
        "https://management.azure.com/subscriptions/"
        f"{SUBSCRIPTION_ID}/providers/"
        "Microsoft.Network/networkSecurityGroups"
        "?api-version=2023-09-01"
    )

    data = safe_azure_get(url, token)
    nsgs = []

    for nsg in data.get("value", []):
        props = nsg.get("properties", {})
        rules = []

        for rule in props.get("securityRules", []):
            rp = rule.get("properties", {})

            rules.append({
                "name": rule.get("name"),
                "priority": rp.get("priority"),
                "direction": rp.get("direction"),
                "access": rp.get("access"),
                "protocol": rp.get("protocol"),
                "source": (
                    rp.get("sourceAddressPrefix")
                    or rp.get("sourceAddressPrefixes")
                ),
                "source_port": (
                    rp.get("sourcePortRange")
                    or rp.get("sourcePortRanges")
                ),
                "destination": (
                    rp.get("destinationAddressPrefix")
                    or rp.get("destinationAddressPrefixes")
                ),
                "destination_port": (
                    rp.get("destinationPortRange")
                    or rp.get("destinationPortRanges")
                )
            })

        subnet_ids = [
            subnet.get("id")
            for subnet in props.get("subnets", [])
        ]

        nsgs.append({
            "name": nsg.get("name"),
            "id": nsg.get("id"),
            "resource_group": nsg.get("resourceGroup"),
            "location": nsg.get("location"),
            "subnet_ids": subnet_ids,
            "rules": rules
        })

    return nsgs


# ============================================================
# NETWORK: PUBLIC IP ADDRESSES
# ============================================================

def collect_public_ips(token):
    print("[+] Collecting public IP addresses...")

    url = (
        "https://management.azure.com/subscriptions/"
        f"{SUBSCRIPTION_ID}/providers/"
        "Microsoft.Network/publicIPAddresses"
        "?api-version=2023-09-01"
    )

    data = safe_azure_get(url, token)
    public_ips = []

    for item in data.get("value", []):
        props = item.get("properties", {})
        ip_config = props.get("ipConfiguration") or {}

        public_ips.append({
            "name": item.get("name"),
            "id": item.get("id"),
            "resource_group": item.get("resourceGroup"),
            "ip_address": props.get("ipAddress"),
            "allocation_method": props.get("publicIPAllocationMethod"),
            "sku": item.get("sku", {}).get("name"),
            "ip_configuration_id": ip_config.get("id")
        })

    return public_ips


# ============================================================
# NETWORK: NETWORK INTERFACES
# ============================================================

def collect_nics(token):
    print("[+] Collecting network interfaces...")

    url = (
        "https://management.azure.com/subscriptions/"
        f"{SUBSCRIPTION_ID}/providers/"
        "Microsoft.Network/networkInterfaces"
        "?api-version=2023-09-01"
    )

    data = safe_azure_get(url, token)
    nics = []

    for nic in data.get("value", []):
        props = nic.get("properties", {})
        ip_configs = []

        for config in props.get("ipConfigurations", []):
            cp = config.get("properties", {})
            subnet = cp.get("subnet") or {}
            public_ip = cp.get("publicIPAddress") or {}

            ip_configs.append({
                "name": config.get("name"),
                "private_ip": cp.get("privateIPAddress"),
                "private_ip_allocation": cp.get(
                    "privateIPAllocationMethod"
                ),
                "subnet_id": subnet.get("id"),
                "public_ip_id": public_ip.get("id")
            })

        nics.append({
            "name": nic.get("name"),
            "id": nic.get("id"),
            "resource_group": nic.get("resourceGroup"),
            "location": nic.get("location"),
            "network_security_group_id": (
                props.get("networkSecurityGroup", {})
                .get("id")
            ),
            "ip_configurations": ip_configs,
            "virtual_machine_id": (
                props.get("virtualMachine", {})
                .get("id")
            )
        })

    return nics


# ============================================================
# COMPUTE: VIRTUAL MACHINES
# ============================================================

def collect_vms(token):
    print("[+] Collecting virtual machines...")

    url = (
        "https://management.azure.com/subscriptions/"
        f"{SUBSCRIPTION_ID}/providers/"
        "Microsoft.Compute/virtualMachines"
        "?api-version=2024-03-01"
    )

    data = safe_azure_get(url, token)
    vms = []

    for vm in data.get("value", []):
        props = vm.get("properties", {})
        network_profile = props.get("networkProfile", {})
        security_profile = props.get("securityProfile", {})
        os_profile = props.get("osProfile", {})
        linux_config = os_profile.get("linuxConfiguration", {})

        nic_ids = [
            nic.get("id")
            for nic in network_profile.get("networkInterfaces", [])
            if nic.get("id")
        ]

        vms.append({
            "name": vm.get("name"),
            "id": vm.get("id"),
            "resource_group": vm.get("resourceGroup"),
            "location": vm.get("location"),
            "vm_size": (
                props.get("hardwareProfile", {})
                .get("vmSize")
            ),
            "os_type": (
                props.get("storageProfile", {})
                .get("osDisk", {})
                .get("osType")
            ),
            "nic_ids": nic_ids,
            "security_type": security_profile.get("securityType"),
            "secure_boot": (
                security_profile.get("uefiSettings", {})
                .get("secureBootEnabled")
            ),
            "v_tpm": (
                security_profile.get("uefiSettings", {})
                .get("vTpmEnabled")
            ),
            "password_authentication_disabled": (
                linux_config.get("disablePasswordAuthentication")
            )
        })

    return vms


# ============================================================
# BUILD NETWORK ATTACK-PATH RELATIONSHIPS
# ============================================================

def build_network_relationships(vnets, nsgs, public_ips, nics, vms):
    """
    Convert raw Azure network objects into relationships that
    the attack-path engine can consume later.
    """

    relationships = []

    subnet_to_vnet = {}
    for vnet in vnets:
        for subnet in vnet.get("subnets", []):
            subnet_to_vnet[subnet.get("id")] = vnet.get("id")

    nic_map = {
        nic.get("id"): nic
        for nic in nics
        if nic.get("id")
    }

    public_ip_map = {
        item.get("id"): item
        for item in public_ips
        if item.get("id")
    }

    for nic in nics:
        nic_id = nic.get("id")

        for config in nic.get("ip_configurations", []):
            subnet_id = config.get("subnet_id")
            public_ip_id = config.get("public_ip_id")

            if subnet_id and nic_id:
                relationships.append({
                    "source": nic_id,
                    "relationship": "connected_to_subnet",
                    "target": subnet_id
                })

            if subnet_id and subnet_id in subnet_to_vnet:
                relationships.append({
                    "source": subnet_id,
                    "relationship": "inside_vnet",
                    "target": subnet_to_vnet[subnet_id]
                })

            if public_ip_id and public_ip_id in public_ip_map:
                relationships.append({
                    "source": public_ip_id,
                    "relationship": "attached_to_nic",
                    "target": nic_id
                })

    for vm in vms:
        vm_id = vm.get("id")

        for nic_id in vm.get("nic_ids", []):
            if nic_id in nic_map:
                relationships.append({
                    "source": vm_id,
                    "relationship": "uses_nic",
                    "target": nic_id
                })

    for nsg in nsgs:
        nsg_id = nsg.get("id")

        for subnet_id in nsg.get("subnet_ids", []):
            relationships.append({
                "source": nsg_id,
                "relationship": "protects_subnet",
                "target": subnet_id
            })

    return relationships


# ============================================================
# RESOLVE KNOWN PRINCIPAL NAMES
# ============================================================

def resolve_known_principal_names(assignments, managed_identities):
    identity_names = {
        identity.get("principal_id"):
            identity.get("resource")
        for identity in managed_identities
        if identity.get("principal_id")
    }

    for assignment in assignments:
        principal_id = assignment.get("principal_id")

        if principal_id in identity_names:
            assignment["principal_name"] = identity_names[principal_id]

        elif principal_id == (
            "fc6c7c41-492f-4e70-a594-b797432fa644"
        ):
            assignment["principal_name"] = "Current Azure User"

    return assignments


# ============================================================
# SAAS / MICROSOFT ENTRA SECURITY COLLECTION
# ============================================================

def graph_get(url, token):
    response = requests.get(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        },
        timeout=30
    )
    response.raise_for_status()
    return response.json()


def safe_graph_get(url, token, label="Graph request"):
    if not token:
        return {"value": [], "_available": False, "_error": "Graph token unavailable"}
    try:
        data = graph_get(url, token)
        data["_available"] = True
        return data
    except requests.HTTPError as e:
        status = e.response.status_code if e.response is not None else None
        print(f"[!] {label} unavailable (HTTP {status}).")
        return {"value": [], "_available": False, "_error": f"HTTP {status}"}
    except requests.RequestException as e:
        print(f"[!] {label} unavailable: {e}")
        return {"value": [], "_available": False, "_error": str(e)}


def graph_get_all(url, token, label="Graph collection"):
    """Collect all Graph pages while preserving graceful permission failures."""
    if not token:
        return {"items": [], "available": False, "error": "Graph token unavailable"}

    items = []
    next_url = url
    first = True

    while next_url:
        data = safe_graph_get(next_url, token, label)
        if not data.get("_available"):
            return {"items": items, "available": False, "error": data.get("_error")}

        items.extend(data.get("value", []))
        next_url = data.get("@odata.nextLink")
        first = False

    return {"items": items, "available": True, "error": None}


def collect_saas_security(graph_token):
    """
    Collect Microsoft Entra / Microsoft 365 security-relevant metadata.

    No passwords, secrets, access tokens, or authentication secrets are stored.
    Graph permission failures are reported as unavailable instead of being
    treated as secure.
    """
    print("[+] Collecting SaaS / Microsoft Entra security data...")

    base = "https://graph.microsoft.com/v1.0"

    users_url = (
        f"{base}/users"
        "?$select=id,displayName,userPrincipalName,userType,accountEnabled,"
        "createdDateTime,mail"
    )
    users_result = graph_get_all(users_url, graph_token, "Entra users")
    users = users_result["items"]

    guests = [
        {
            "id": u.get("id"),
            "display_name": u.get("displayName"),
            "user_principal_name": u.get("userPrincipalName"),
            "account_enabled": u.get("accountEnabled"),
            "created_date_time": u.get("createdDateTime")
        }
        for u in users
        if str(u.get("userType", "")).lower() == "guest"
    ]

    disabled_users = [
        {
            "id": u.get("id"),
            "display_name": u.get("displayName"),
            "user_principal_name": u.get("userPrincipalName")
        }
        for u in users
        if u.get("accountEnabled") is False
    ]

    sp_url = (
        f"{base}/servicePrincipals"
        "?$select=id,displayName,appId,accountEnabled,servicePrincipalType,"
        "appOwnerOrganizationId"
    )
    sp_result = graph_get_all(sp_url, graph_token, "Entra service principals")
    service_principals = [
        {
            "id": sp.get("id"),
            "display_name": sp.get("displayName"),
            "app_id": sp.get("appId"),
            "account_enabled": sp.get("accountEnabled"),
            "service_principal_type": sp.get("servicePrincipalType"),
            "app_owner_organization_id": sp.get("appOwnerOrganizationId")
        }
        for sp in sp_result["items"]
    ]

    roles_url = f"{base}/directoryRoles"
    roles_result = graph_get_all(roles_url, graph_token, "Entra directory roles")
    privileged_roles = []
    role_members_available = True
    role_errors = []

    privileged_role_names = {
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

    for role in roles_result["items"]:
        role_name = role.get("displayName") or "Unknown"
        members_url = f"{base}/directoryRoles/{role.get('id')}/members"
        members_result = graph_get_all(
            members_url,
            graph_token,
            f"Members of directory role {role_name}"
        )

        if not members_result["available"]:
            role_members_available = False
            role_errors.append({
                "role": role_name,
                "error": members_result.get("error")
            })

        if role_name in privileged_role_names or members_result["items"]:
            members = []
            for member in members_result["items"]:
                members.append({
                    "id": member.get("id"),
                    "display_name": member.get("displayName"),
                    "user_principal_name": member.get("userPrincipalName"),
                    "type": member.get("@odata.type"),
                    "account_enabled": member.get("accountEnabled")
                })

            privileged_roles.append({
                "id": role.get("id"),
                "display_name": role_name,
                "description": role.get("description"),
                "members": members
            })

    # Microsoft Graph authentication-method registration report is optional
    # because tenant permissions may not include Reports.Read.All.
    mfa_url = (
        f"{base}/reports/authenticationMethods/userRegistrationDetails"
        "?$select=id,userPrincipalName,userDisplayName,isMfaRegistered,"
        "isMfaCapable,methodsRegistered"
    )
    mfa_result = graph_get_all(
        mfa_url,
        graph_token,
        "MFA registration report"
    )
    mfa_users = [
        {
            "id": item.get("id"),
            "user_principal_name": item.get("userPrincipalName"),
            "display_name": item.get("userDisplayName"),
            "mfa_registered": item.get("isMfaRegistered"),
            "mfa_capable": item.get("isMfaCapable"),
            "methods_registered": item.get("methodsRegistered", [])
        }
        for item in mfa_result["items"]
    ]

    return {
        "users": [
            {
                "id": u.get("id"),
                "display_name": u.get("displayName"),
                "user_principal_name": u.get("userPrincipalName"),
                "user_type": u.get("userType"),
                "account_enabled": u.get("accountEnabled"),
                "created_date_time": u.get("createdDateTime"),
                "mail": u.get("mail")
            }
            for u in users
        ],
        "guests": guests,
        "disabled_users": disabled_users,
        "service_principals": service_principals,
        "privileged_roles": privileged_roles,
        "mfa_registration": mfa_users,
        "collection_status": {
            "users": users_result["available"],
            "service_principals": sp_result["available"],
            "directory_roles": roles_result["available"],
            "directory_role_members": role_members_available,
            "mfa_registration": mfa_result["available"]
        },
        "collection_errors": {
            "users": users_result.get("error"),
            "service_principals": sp_result.get("error"),
            "directory_roles": roles_result.get("error"),
            "directory_role_members": role_errors,
            "mfa_registration": mfa_result.get("error")
        }
    }


# ============================================================
# MAIN
# ============================================================

def main():
    print("=" * 70)
    print("       SECURITY ACROSS CLOUD STACK")
    print("              AZURE COLLECTOR")
    print("=" * 70)

    # --------------------------------------------------------
    # AUTHENTICATION
    # --------------------------------------------------------

    token = get_token()
    graph_token = get_graph_token()

    # --------------------------------------------------------
    # SAAS / MICROSOFT ENTRA SECURITY
    # --------------------------------------------------------

    saas_security = collect_saas_security(graph_token)

    # --------------------------------------------------------
    # RESOURCE INVENTORY
    # --------------------------------------------------------

    resources = collect_resources(token)

    # --------------------------------------------------------
    # RBAC
    # --------------------------------------------------------

    assignments = collect_role_assignments(token)
    assignments = collect_role_names(token, assignments)

    # --------------------------------------------------------
    # MANAGED IDENTITY
    # --------------------------------------------------------

    identity = collect_app_identity(token)
    managed_identities = [identity]

    # --------------------------------------------------------
    # PAAS / APP SERVICE SECURITY
    # --------------------------------------------------------

    paas_security = collect_paas_security(token)

    # --------------------------------------------------------
    # PRINCIPAL NAMES
    # --------------------------------------------------------

    if graph_token:
        assignments = collect_principal_names(
            graph_token,
            assignments
        )

    assignments = resolve_known_principal_names(
        assignments,
        managed_identities
    )

    # --------------------------------------------------------
    # KEY VAULT
    # --------------------------------------------------------

    key_vault = collect_key_vault(token)
    secrets = collect_secrets(token)

    # --------------------------------------------------------
    # NETWORK / COMPUTE
    # --------------------------------------------------------

    vnets = collect_vnets(token)
    nsgs = collect_nsgs(token)
    public_ips = collect_public_ips(token)
    nics = collect_nics(token)
    vms = collect_vms(token)

    network_relationships = build_network_relationships(
        vnets,
        nsgs,
        public_ips,
        nics,
        vms
    )

    # --------------------------------------------------------
    # BUILD INVENTORY
    # --------------------------------------------------------

    inventory = {
        "subscription_id": SUBSCRIPTION_ID,
        "tenant_id": TENANT_ID,
        "resource_group": RESOURCE_GROUP,

        "resources": resources,

        "role_assignments": assignments,

        "managed_identities": managed_identities,

        "paas": paas_security,

        "saas": saas_security,

        "key_vaults": [
            key_vault
        ],

        "secrets": secrets,

        "network": {
            "vnets": vnets,
            "nsgs": nsgs,
            "public_ips": public_ips,
            "network_interfaces": nics,
            "virtual_machines": vms,
            "relationships": network_relationships
        }
    }

    # --------------------------------------------------------
    # SAVE INVENTORY
    # --------------------------------------------------------

    output_file = "azure_inventory.json"

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            inventory,
            file,
            indent=4
        )

    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------

    print("\n[+] Azure collection complete.")
    print(f"[+] Resources: {len(resources)}")
    print(f"[+] RBAC assignments: {len(assignments)}")
    print(f"[+] Managed identities: {len(managed_identities)}")
    print("[+] PaaS App Service security configuration: collected")
    print(f"[+] SaaS users: {len(saas_security.get('users', []))}")
    print(f"[+] SaaS guests: {len(saas_security.get('guests', []))}")
    print(f"[+] SaaS service principals: {len(saas_security.get('service_principals', []))}")
    print(f"[+] SaaS privileged roles: {len(saas_security.get('privileged_roles', []))}")
    print(f"[+] SaaS MFA records: {len(saas_security.get('mfa_registration', []))}")
    print(f"[+] App settings discovered: {len(paas_security.get('app_settings', []))}")
    print(f"[+] Connection strings discovered: {len(paas_security.get('connection_strings', []))}")
    print(f"[+] Key Vaults: 1")
    print(f"[+] Secrets discovered: {len(secrets)}")
    print(f"[+] VNets: {len(vnets)}")
    print(f"[+] NSGs: {len(nsgs)}")
    print(f"[+] Public IPs: {len(public_ips)}")
    print(f"[+] Network interfaces: {len(nics)}")
    print(f"[+] Virtual machines: {len(vms)}")
    print(f"[+] Network relationships: {len(network_relationships)}")

    print("\n[+] Output:")
    print(f"    {output_file}")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
