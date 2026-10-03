@"
# Azure Services

This document lists the Azure services and security capabilities used or assessed in the project.

| Azure Service / Capability | Purpose | Status |
|---|---|---|
| Resource Group | Organize project resources | Implemented |
| Virtual Network | Network isolation and segmentation | Implemented |
| Network Security Group | Control inbound network traffic | Implemented |
| Ubuntu Virtual Machine | IaaS security demonstration | Implemented |
| Azure App Service | PaaS security demonstration | Implemented |
| Azure Key Vault | Secure secrets and credentials | Implemented |
| Microsoft Entra ID | Identity and access management | Implemented |
| Azure RBAC | Authorization and privilege management | Implemented |
| Managed Identity | Passwordless service authentication | Implemented |
| Azure Policy | Governance and compliance | Assessed |
| Resource Locks | Protect resources from accidental deletion | Implemented |
| Microsoft Defender for Cloud | Security posture assessment | Assessed |
| Azure Bicep | Infrastructure as Code | Implemented |
| Azure Monitor | Monitoring and diagnostics | Implemented |
| Log Analytics | Centralized log analysis | Implemented |
| Diagnostic Settings | Route platform logs to Log Analytics | Implemented |
| Azure Activity Log | Subscription-level activity monitoring | Implemented |

## Security Analysis Components

The project also includes custom security-analysis components for:

- Azure resource inventory
- RBAC analysis
- Managed identity analysis
- Network security analysis
- Security graph construction
- Attack path detection
- Sensitive target identification
- Risk scoring
- Security findings
- Remediation recommendations
- Cross-model security comparison

## Cloud Service Models

The project demonstrates security across:

- IaaS
- PaaS
- SaaS
- Identity

These components are analyzed using Microsoft's Shared Responsibility Model.
"@ | Set-Content docs\AzureServices.md