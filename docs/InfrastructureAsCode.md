@"
# Infrastructure as Code

## Objective

Define and manage the Azure infrastructure using Azure Bicep so that the security architecture can be reproduced through declarative infrastructure code.

## Technology

- Azure Bicep
- Azure Resource Manager
- Azure CLI

Bicep CLI version used:

`0.47.16`

## Bicep Template

The main infrastructure template is:

`infrastructure/main.bicep`

The template defines the core Azure resources used by the project.

## Resources Defined

The Bicep template covers:

- Virtual Network
- Subnets
- Network Security Group
- Public IP
- Network Interface
- Ubuntu Virtual Machine
- App Service Plan
- Azure App Service
- App Service authentication configuration
- Azure Key Vault
- Resource Group deletion lock

## Security Configuration

The infrastructure definition includes security controls such as:

- SSH password authentication disabled
- SSH restricted to the configured administrator IP
- HTTP network access controlled through the NSG
- Trusted Launch for the VM
- Secure Boot enabled
- vTPM enabled
- Boot diagnostics enabled
- HTTPS-only App Service
- TLS 1.2 minimum
- FTPS-only deployment
- App Service IP restrictions
- SCM endpoint restrictions
- App Service authentication through Microsoft Entra ID
- System-assigned managed identity
- Key Vault RBAC authorization
- Key Vault soft delete
- Resource Group CanNotDelete lock

## Parameterization

Environment-specific values are parameterized where appropriate, including:

- SSH public key
- Administrator username
- Administrator IP address
- App Service allowed IP address
- Project tags

This avoids embedding sensitive credentials in the infrastructure template.

## Validation

The Bicep template was successfully compiled using the Azure Bicep CLI.

A deployment What-If operation was also performed against the existing environment.

The final What-If analysis showed:

- 5 resources with modifications
- 5 resources with no changes
- 2 resources ignored
- No resources created
- No resources deleted

The remaining modification entries were primarily Azure-generated or default resource properties, while the intended security configuration was explicitly represented in the Bicep template.

## Result

Infrastructure as Code was implemented using Azure Bicep, providing a reproducible definition of the project's Azure security architecture and its associated security controls.
"@ | Set-Content docs\InfrastructureAsCode.md