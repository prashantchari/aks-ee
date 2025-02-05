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
$scriptUrl = "https://raw.githubusercontent.com/wuqiten/AKS-Edge/refs/heads/main/tools/scripts/AksEdgeQuickStart/AksEdgeQuickStartForAio.ps1"
$scriptPath = "AksEdgeQuickStartForAio.ps1"

Invoke-WebRequest -Uri $scriptUrl -OutFile $scriptPath


Invoke-WebRequest -Uri https://secure.globalsign.net/cacert/Root-R1.crt -OutFile c:\globalsignR1.crt
Import-Certificate -FilePath c:\globalsignR1.crt -CertStoreLocation Cert:\LocalMachine\Root

# Run the command and wait for it to complete
try {
    $output = & .\AksEdgeQuickStartForAio.ps1 `
    -SubscriptionId $SubscriptionId `
    -TenantId $TenantId `
    -Location $Location `
    -ResourceGroupName $ResourceGroupName `
    -ClusterName $ClusterName `
    -CustomLocationOid $CustomLocationOid `
    -UseK8s $UseK8s `
    -Tag $Tag
    Write-Host "Command executed successfully!"
    Write-Output $output
} catch {
    Write-Host "An error occurred:" -ForegroundColor Red
    Write-Host $_.Exception.Message
}

Write-Host "Creating admin credentials"
az account set --subscription $env:arcSubscriptionId *>&1

# Create admin service account and write token to key vault
# The secret name must be a 1-127 character string, starting with a letter and containing only 0-9, a-z, A-Z, and -.
kubectl apply -f https://raw.githubusercontent.com/prashantchari/public/main/arc-admin.yaml | Write-Host

# wait for a token to be created
Write-Host "Writing admin token to key vault secret"
$uniqueSecretName = "$Env:clusterName-$Env:arcResourceGroup-$env:arcSubscriptionId"
while ($true) {
    $token = kubectl get secret arc-admin-secret -n kube-system -o jsonpath='{.data.token}' --ignore-not-found | %{[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($_))}
    if ($token) {
        Write-Host "Writing token to secret named: $uniqueSecretName in key vault $Env:proxyCredentialsKeyVaultName"
        az keyvault secret set --vault-name $Env:proxyCredentialsKeyVaultName --name $uniqueSecretName --value $token *>&1
        break
    } else {
        Write-Host "Waiting for token to be created..."
        Start-Sleep -Seconds 5
    }
}


