@"
# Governance and Compliance

## Objective

Implement Azure governance controls to improve resource organization, deployment control, and protection against accidental deletion.

---

## Azure Policy

The subscription was reviewed for existing Azure Policy assignments.

Existing policy assignments included:

- Allowed resource deployment regions
- Azure Security Center / Defender for Cloud default audit policies

These policies provide governance and security-policy enforcement at the subscription level.

---

## Resource Group Governance

The project resource group is:

`rg-security-cloud-stack`

The following tags were applied:

| Tag | Value |
|---|---|
| Environment | SecurityLab |
| Project | SecurityAcrossCloudStack |
| Owner | Student |
| ManagedBy | Azure |

These tags provide consistent identification and ownership metadata for the project resources.

---

## Resource Group Lock

A `CanNotDelete` resource lock was applied to the project resource group.

**Lock name:**

`SecurityLab-ResourceGroup-Lock`

**Lock type:**

`CanNotDelete`

This prevents accidental deletion of the resource group while still allowing resource configuration changes.

---

## Governance Verification

The policy assignments were verified using Azure CLI:

```powershell
az policy assignment list --scope /subscriptions/<subscription-id> -o table