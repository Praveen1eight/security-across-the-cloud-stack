@"
# Security Across the Cloud Stack

## Project Name

Security Across the Cloud Stack

## Platform

Microsoft Azure

## Objective

Demonstrate security across:

- Infrastructure as a Service (IaaS)
- Platform as a Service (PaaS)
- Software as a Service (SaaS)
- Microsoft Entra ID

using Microsoft's Shared Responsibility Model.

## Architecture

The project implements security controls and analysis across multiple Azure service models.

### IaaS

The IaaS layer contains:

- Azure Virtual Network
- Management and web subnets
- Network Security Group
- Ubuntu Linux Virtual Machine
- Static Public IP
- Network Interface
- Trusted Launch
- Secure Boot
- vTPM
- SSH restriction

Security analysis includes:

- Resource inventory
- RBAC analysis
- Managed identity analysis
- Network analysis
- Security graph construction
- Attack path detection
- Sensitive target identification
- Risk scoring
- Remediation analysis

### PaaS

The PaaS layer contains:

- Azure App Service
- App Service Plan
- System-assigned Managed Identity
- Microsoft Entra authentication
- HTTPS-only access
- TLS 1.2
- FTPS-only deployment
- IP access restrictions
- SCM access restrictions
- Azure Key Vault integration

The App Service security posture is evaluated before and after security remediation.

### SaaS

The SaaS layer focuses on Microsoft Entra ID and Microsoft 365-related identity security analysis.

The SaaS analysis includes:

- User accounts
- Guest users
- Disabled users
- Privileged directory roles
- Service principals
- MFA registration information
- Identity security findings

### Identity

Microsoft Entra ID provides the identity and authorization layer across the environment.

Identity security analysis includes:

- Azure RBAC assignments
- Privileged roles
- Managed identities
- Service principals
- Authentication configuration
- Access relationships

### Governance

Governance controls include:

- Azure Policy assessment
- Resource tagging
- Resource Group protection
- CanNotDelete resource lock

### Monitoring

Monitoring and logging are implemented using:

- Azure Monitor
- Log Analytics
- Diagnostic Settings
- Azure Activity Log
- KQL queries

Logs are collected from Azure subscription activity, Azure Key Vault, and Azure App Service.

### Infrastructure as Code

Azure Bicep is used to define the infrastructure and security configuration.

The main template is:

`infrastructure/main.bicep`

## Security Analysis Flow

The overall security-analysis workflow is:

Azure Environment
→ Resource Collection
→ Security Analysis
→ Security Graph
→ Attack Path Detection
→ Risk Scoring
→ Remediation
→ Re-validation
→ Cross-Model Comparison

## Shared Responsibility Model

The project demonstrates how security responsibilities differ across IaaS, PaaS, and SaaS.

As the cloud service model moves from IaaS toward SaaS, Azure assumes more responsibility for the underlying infrastructure while the customer remains responsible for areas such as identity, configuration, data, and access control.

## Architecture Summary

The project combines Azure infrastructure, platform services, identity controls, governance, monitoring, Infrastructure as Code, and custom security analysis into a single cloud security environment.

The architecture is designed to demonstrate practical cloud security controls rather than only theoretical differences between cloud service models.
"@ | Set-Content docs\Architecture.md