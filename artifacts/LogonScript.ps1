param (
    [string]$arcFederatedToken,
    [string]$msiUrl
)

$SubscriptionId = $env:arcSubscriptionId
$TenantId = $env:arcTenantId
$Location = $env:arcLocation
$ResourceGroupName = $env:arcResourceGroup
$ClusterName = $Env:clusterName
$CustomLocationOid = "51dfe1e8-70c6-4de5-a08e-e18aff23d815"
# TODO: shold we set Tag as constant?
$Tag = "1.8.202.0"
$UseK8s=$false
$CpuCoreCount = if ($env:cpuCoreCount) { $env:cpuCoreCount } else { 8 }
$VMMemory = if ($env:vmMemory) { $env:vmMemory } else { 16384 }
$EnableArcGateway = $env:enableArcGateway
$DisableArcAgentAutoUpgrade = if ($env:disableArcAgentAutoUpgrade) { $env:disableArcAgentAutoUpgrade } else { "true" }

#Requires -RunAsAdministrator

Start-Transcript -Path C:\Temp\LogonScript.log

Write-Host "Starting the script execution..."

# The federated token is short lived so convert it immediately to tokens with longer lifetime.
# Convert federated token to ARM access token
az login --service-principal --username $Env:arcAppId --federated-token "$arcFederatedToken" --tenant $Env:arcTenantId

# Acquire a key vault scoped access token before the federated token expires
az account get-access-token --scope https://vault.azure.net/.default --output none

# download public script and config json tempaltes
$scriptUrl = "https://raw.githubusercontent.com/jagadishmurugan/AKS-Edge/refs/heads/users/jagamu/accept-config-file-input/tools/scripts/AksEdgeQuickStart/AksEdgeQuickStartForAio.ps1"
$scriptPath = "AksEdgeQuickStartForAio.ps1"

Invoke-WebRequest -Uri $scriptUrl -OutFile $scriptPath

# update json config
# Here string for the json content
$aideuserConfig = @"
{
    "SchemaVersion": "1.1",
    "Version": "1.0",
    "AksEdgeProduct": "$productName",
    "AksEdgeProductUrl": "$productUrl",
    "Azure": {
        "SubscriptionName": "",
        "SubscriptionId": "$SubscriptionId",
        "TenantId": "$TenantId",
        "ResourceGroupName": "$ResourceGroupName",
        "ServicePrincipalName": "aksedge-sp",
        "Location": "$Location",
        "CustomLocationOID":"$CustomLocationOid",
        "EnableWorkloadIdentity": true,
        "EnableKeyManagement": true,
        "GatewayResourceId": "",
        "Auth":{
            "ServicePrincipalId":"",
            "Password":""
        }
    },
    "AksEdgeConfigFile": "aksedge-config.json"
}
"@
$aksedgeConfig = @"
{
    "SchemaVersion": "1.14",
    "Version": "1.0",
    "DeploymentType": "SingleMachineCluster",
    "Init": {
        "ServiceIPRangeSize": 10
    },
    "Network": {
        "NetworkPlugin": "$networkplugin",
        "InternetDisabled": false,
        "Proxy": {
            "Http": null,
            "Https": null,
            "No": null
        }
    },
    "User": {
        "AcceptEula": true,
        "AcceptOptionalTelemetry": true
    },
    "Machines": [
        {
            "LinuxNode": {
                "CpuCount": "$CpuCoreCount",
                "MemoryInMB": $VMMemory,
                "DataSizeInGB": 40,
                "LogSizeInGB": 4
            }
        }
    ]
}
"@

# Run the command and wait for it to complete
try {
    $output = Invoke-Expression ".\AksEdgeQuickStartForAio.ps1 -aideUserConfigfile $aideuserConfig -aksedgeConfigFile $aksedgeConfig -Tag 'aio-accept-config-file-input-02'"
    Write-Host "Command executed successfully!"
    Write-Output $output
} catch {
    Write-Host "An error occurred:" -ForegroundColor Red
    Write-Host $_.Exception.Message
}
