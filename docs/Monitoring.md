@"
# Monitoring and Logging

## Objective

Implement centralized monitoring and logging for the Azure environment using Azure Monitor and Log Analytics.

## Log Analytics Workspace

A Log Analytics workspace was created for centralized log collection.

**Workspace:**

`law-security-cloud-stack`

**Resource Group:**

`rg-security-cloud-stack`

**Region:**

`malaysiawest`

**Retention:**

30 days

**SKU:**

PerGB2018

The workspace provides a centralized destination for Azure monitoring and diagnostic data.

## Key Vault Monitoring

Diagnostic logging was configured for:

`kvseccloud01`

A diagnostic setting named:

`KeyVault-to-LogAnalytics`

was created to send Key Vault audit logs to the Log Analytics workspace.

## App Service Monitoring

Diagnostic logging was configured for:

`security-cloud-stack-app-01`

Diagnostic setting:

`AppService-to-LogAnalytics`

The following categories were enabled:

- AppServiceAppLogs
- AppServiceHTTPLogs
- AppServicePlatformLogs
- AppServiceAuthenticationLogs
- AppServiceAuditLogs
- AppServiceIPSecAuditLogs

## Azure Activity Log

Subscription-level Activity Log diagnostics were configured using:

`ActivityLog-to-LogAnalytics`

The following categories were enabled:

- Administrative
- Security
- ServiceHealth
- Alert
- Recommendation
- Policy
- ResourceHealth

This provides centralized visibility into subscription-level administrative and security-related activity.

## Monitoring Queries

Reusable KQL queries are stored in:

`docs/monitoring/monitoring_queries.kql`

The queries cover:

- Recent Azure activity
- Administrative changes
- Failed Azure operations
- Security-related activity
- Key Vault activity
- App Service activity
- Authentication-related events
- Events from the previous 24 hours

## VM Monitoring

The Azure Monitor Agent was not installed on the Linux VM because the VM was deallocated during the monitoring implementation.

The installation attempt returned an Azure error indicating that VM extensions cannot be modified while the VM is not running.

Therefore, VM-level telemetry collection was not claimed as completed.

The VM can be started and the Azure Monitor Agent deployed later if host-level monitoring is required.

## Log Query Validation

The Azure CLI Log Analytics query extension could not be installed successfully because the extension installation encountered a network connection reset.

The KQL queries were therefore prepared for execution through the Azure Portal's Log Analytics Logs interface rather than claiming successful CLI query execution.

## Monitoring Architecture

The monitoring flow implemented in the project is:

Azure Resources
→ Azure Monitor Diagnostic Settings
→ Log Analytics Workspace
→ KQL Analysis

The monitored sources include:

- Azure Subscription Activity Log
- Azure Key Vault
- Azure App Service

## Result

Centralized Azure monitoring and diagnostic logging were implemented using Azure Monitor and Log Analytics.

The configuration provides visibility into administrative activity, security events, Key Vault operations, App Service activity, and authentication-related events while clearly documenting the current limitation for VM-level telemetry.
"@ | Set-Content docs\Monitoring.md