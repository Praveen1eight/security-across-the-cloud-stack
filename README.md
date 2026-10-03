@"
# Security Across the Cloud Stack

> Securing IaaS, PaaS, SaaS, and Identity on Microsoft Azure

---

## Overview

Security Across the Cloud Stack is a hands-on Microsoft Azure cloud security project demonstrating security across IaaS, PaaS, SaaS, and Microsoft Entra ID using Microsoft's Shared Responsibility Model.

The project combines Azure security controls with custom security analysis, risk scoring, attack-path detection, governance, monitoring, and Infrastructure as Code.

---

## Objectives

- Build and secure Azure infrastructure
- Demonstrate Microsoft Entra ID and RBAC
- Secure workloads across IaaS, PaaS, and SaaS
- Analyze cloud security relationships and attack paths
- Identify sensitive resources and security risks
- Apply security remediation and re-validation
- Implement Azure governance controls
- Assess security posture using Microsoft Defender for Cloud
- Implement centralized monitoring and logging
- Define infrastructure using Azure Bicep
- Document the complete security architecture

---

## Architecture

The project covers four major security areas:

### IaaS

- Azure Virtual Network
- Subnets
- Network Security Group
- Ubuntu Linux Virtual Machine
- SSH access restrictions
- Trusted Launch
- Secure Boot
- vTPM
- Network security analysis

### PaaS

- Azure App Service
- Managed Identity
- Microsoft Entra authentication
- HTTPS-only access
- TLS 1.2
- FTPS-only deployment
- IP access restrictions
- SCM endpoint restrictions
- Azure Key Vault integration

### SaaS

Microsoft Entra / SaaS identity analysis covering:

- User accounts
- Guest users
- Disabled users
- Privileged directory roles
- Service principals
- MFA registration information

### Identity

- Azure RBAC
- Microsoft Entra ID
- Managed identities
- Service principals
- Privileged access analysis

---

## Security Analysis Engine

The project includes a custom security-analysis workflow:

```text
Azure Environment
       |
       v
Resource Collection
       |
       v
Security Analysis
       |
       v
Security Graph
       |
       v
Attack Path Detection
       |
       v
Risk Scoring
       |
       v
Remediation
       |
       v
Re-validation
       |
       v
Cross-Model Comparison
