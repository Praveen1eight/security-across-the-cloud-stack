@"
# Microsoft Defender for Cloud

## Objective

Assess the security posture of the Azure environment using Microsoft Defender for Cloud security recommendations and assessments.

## Defender Pricing

The following Defender plans were checked:

| Workload | Pricing Tier |
|---|---|
| Virtual Machines | Free |
| App Services | Free |
| Key Vaults | Free |

The project did not enable paid Defender plans.

## Security Assessment

Defender for Cloud assessments were reviewed across the project resources.

### Healthy Security Controls

The environment had successful assessments for controls including:

- Network Watcher
- IP forwarding disabled on the VM
- Management ports protected
- Network Security Group restrictions
- Internet-facing VM protected by NSG
- VM migrated to ARM
- Secure Boot enabled
- vTPM enabled
- App Service remote debugging disabled
- App Service CORS configuration
- App Service HTTPS
- App Service managed identity
- App Service TLS configuration
- FTPS required
- Key Vault soft delete
- Key Vault RBAC

### Security Recommendations

Defender for Cloud also identified areas requiring additional hardening, including:

- Multiple subscription owners
- Defender CSPM not enabled
- Missing security contact email
- High-severity alert email notifications not configured
- Defender protection not enabled for some workloads
- VM backup not enabled
- Guest Configuration and Guest Attestation
- System update monitoring
- VM encryption / EncryptionAtHost
- Key Vault diagnostic logging
- Key Vault deletion protection
- Key Vault private endpoint
- Key Vault firewall configuration

Some recommendations were marked NotApplicable depending on the resource or service.

## Project Decision

Paid Defender plans were not enabled because the project was developed using an Azure for Students subscription.

The purpose of this phase was to demonstrate security posture assessment and identify additional hardening opportunities rather than enabling paid security services.

## Result

Microsoft Defender for Cloud was used to assess the security posture of the Azure environment and identify both existing security controls and remaining hardening opportunities.
"@ | Set-Content docs\DefenderForCloud.md