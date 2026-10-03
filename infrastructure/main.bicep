targetScope = 'resourceGroup'

@description('SSH public key used for the Linux VM.')
param sshPublicKey string

@description('Administrator username for the Linux VM.')
param adminUsername string = 'azureadmin'

@description('IP address allowed to SSH to the VM.')
param adminIpAddress string = '122.183.37.185'

@description('IP address allowed to access the App Service.')
param appServiceAllowedIp string = '157.51.109.60/32'

@description('Common project tags.')
param projectTag string = 'SecurityAcrossCloudStack'

var location = 'malaysiawest'

var vnetName = 'vnet-cloud-stack'
var nsgName = 'nsg-web-security'
var subnetName = 'web-subnet'
var publicIpName = 'vm-web-01-ip'
var nicName = 'vm-web-01267'
var vmName = 'vm-web-01'

var appServicePlanName = 'ASP-rgsecuritycloudstack-ab57'
var appServiceName = 'security-cloud-stack-app-01'
var keyVaultName = 'kvseccloud01'

var tags = {
  Project: projectTag
}


// ============================================================
// NETWORK SECURITY GROUP
// ============================================================

resource nsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: nsgName
  location: location
  tags: tags

  properties: {
    securityRules: [
      {
        name: 'Allow-HTTP-Web'
        properties: {
          priority: 100
          access: 'Allow'
          direction: 'Inbound'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '80'
        }
      }
      {
        name: 'Allow-SSH-MyIp'
        properties: {
          priority: 110
          access: 'Allow'
          direction: 'Inbound'
          protocol: 'Tcp'
          sourceAddressPrefix: adminIpAddress
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '22'
        }
      }
    ]
  }
}


// ============================================================
// VIRTUAL NETWORK
// ============================================================

resource vnet 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: vnetName
  location: location
  tags: tags

  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.0.0.0/16'
      ]
    }

    subnets: [
      {
        name: 'management-subnet'
        properties: {
          addressPrefixes: [
            '10.0.2.0/24'
          ]
          defaultOutboundAccess: false
        }
      }
      {
        name: subnetName
        properties: {
          addressPrefixes: [
            '10.0.1.0/24'
          ]
          defaultOutboundAccess: false

          networkSecurityGroup: {
            id: nsg.id
          }
        }
      }
    ]
  }
}


// ============================================================
// PUBLIC IP
// ============================================================

resource publicIp 'Microsoft.Network/publicIPAddresses@2024-05-01' = {
  name: publicIpName
  location: location
  tags: tags

  sku: {
    name: 'Standard'
    tier: 'Regional'
  }

  zones: [
    '2'
  ]

  properties: {
    publicIPAllocationMethod: 'Static'
  }
}


// ============================================================
// NETWORK INTERFACE
// ============================================================

resource nic 'Microsoft.Network/networkInterfaces@2024-05-01' = {
  name: nicName
  location: location
  tags: tags

  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'

        properties: {
          privateIPAllocationMethod: 'Dynamic'

          publicIPAddress: {
            id: publicIp.id
          }

          subnet: {
            id: resourceId(
              'Microsoft.Network/virtualNetworks/subnets',
              vnetName,
              subnetName
            )
          }
        }
      }
    ]
  }
}


// ============================================================
// VIRTUAL MACHINE
// ============================================================

resource vm 'Microsoft.Compute/virtualMachines@2024-07-01' = {
  name: vmName
  location: location
  tags: tags

  zones: [
    '2'
  ]

  properties: {
    hardwareProfile: {
      vmSize: 'Standard_B2ats_v2'
    }

    storageProfile: {
      imageReference: {
        publisher: 'canonical'
        offer: 'ubuntu-24_04-lts'
        sku: 'server'
        version: 'latest'
      }

      osDisk: {
        createOption: 'FromImage'
        managedDisk: {
          storageAccountType: 'Standard_LRS'
        }
      }
    }

    osProfile: {
      computerName: vmName
      adminUsername: adminUsername

      linuxConfiguration: {
        disablePasswordAuthentication: true

        ssh: {
          publicKeys: [
            {
              path: '/home/azureadmin/.ssh/authorized_keys'
              keyData: sshPublicKey
            }
          ]
        }
      }
    }

    networkProfile: {
      networkInterfaces: [
        {
          id: nic.id
          properties: {
            primary: true
          }
        }
      ]
    }

    securityProfile: {
      securityType: 'TrustedLaunch'

      uefiSettings: {
        secureBootEnabled: true
        vTpmEnabled: true
      }
    }

    diagnosticsProfile: {
      bootDiagnostics: {
        enabled: true
      }
    }
  }
}


// ============================================================
// APP SERVICE PLAN
// ============================================================

resource appServicePlan 'Microsoft.Web/serverfarms@2024-04-01' = {
  name: appServicePlanName
  location: location
  tags: tags

  sku: {
    name: 'F1'
    tier: 'Free'
  }

  properties: {
    reserved: true
  }
}


// ============================================================
// APP SERVICE
// ============================================================

resource appService 'Microsoft.Web/sites@2024-04-01' = {
  name: appServiceName
  location: location
  tags: tags

  kind: 'app,linux'

  identity: {
    type: 'SystemAssigned'
  }

  properties: {
    serverFarmId: appServicePlan.id

    httpsOnly: true

    publicNetworkAccess: 'Enabled'

    siteConfig: {
      linuxFxVersion: 'PYTHON|3.12'

      ftpsState: 'FtpsOnly'

      minTlsVersion: '1.2'

      scmMinTlsVersion: '1.2'

      remoteDebuggingEnabled: false

      ipSecurityRestrictions: [
        {
          name: 'Allow-My-IP'
          priority: 100
          action: 'Allow'
          ipAddress: appServiceAllowedIp
        }
        {
          name: 'Deny all'
          priority: 2147483647
          action: 'Deny'
          ipAddress: 'Any'
          description: 'Deny all access'
        }
      ]

      ipSecurityRestrictionsDefaultAction: 'Deny'

      scmIpSecurityRestrictions: [
        {
          name: 'Allow-My-IP-SCM'
          priority: 100
          action: 'Allow'
          ipAddress: appServiceAllowedIp
        }
        {
          name: 'Deny all'
          priority: 2147483647
          action: 'Deny'
          ipAddress: 'Any'
          description: 'Deny all access'
        }
      ]

      scmIpSecurityRestrictionsDefaultAction: 'Deny'

      scmIpSecurityRestrictionsUseMain: false
    }
  }
}


// ============================================================
// KEY VAULT
// ============================================================

resource keyVault 'Microsoft.KeyVault/vaults@2024-04-01-preview' = {
  name: keyVaultName
  location: location
  tags: tags

  properties: {
    tenantId: subscription().tenantId

    sku: {
      family: 'A'
      name: 'standard'
    }

    enableRbacAuthorization: true

    enableSoftDelete: true

    softDeleteRetentionInDays: 90

    publicNetworkAccess: 'Enabled'

    networkAcls: {
      bypass: 'None'
      defaultAction: 'Allow'
    }

    accessPolicies: []
  }
}


// ============================================================
// RESOURCE GROUP DELETE PROTECTION
// ============================================================

resource resourceGroupLock 'Microsoft.Authorization/locks@2020-05-01' = {
  name: 'SecurityLab-ResourceGroup-Lock'

  properties: {
    level: 'CanNotDelete'
  }
}
// ============================================================
// APP SERVICE ENTRA ID AUTHENTICATION
// ============================================================

resource appServiceAuth 'Microsoft.Web/sites/config@2024-04-01' = {
  name: 'authsettingsV2'
  parent: appService

  properties: {
    globalValidation: {
      redirectToProvider: 'aad'
      unauthenticatedClientAction: 'RedirectToLoginPage'
    }

    login: {
      preserveUrlFragmentsForLogins: false

      routes: {
        logoutEndpoint: '/.auth/logout'
      }
    }

    platform: {
      enabled: true
      runtimeVersion: '~1'
    }
  }
}