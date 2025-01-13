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
$Tag = "1.8.202.0"
$UseK8s = $false
$CpuCoreCount = if ($env:cpuCoreCount) { $env:cpuCoreCount } else { 8 }
$VMMemory = if ($env:vmMemory) { $env:vmMemory } else { 16384 }
$EnableArcGateway = $env:enableArcGateway
$DisableArcAgentAutoUpgrade = if ($env:disableArcAgentAutoUpgrade) { $env:disableArcAgentAutoUpgrade } else { "true" }

# https://github.com/Azure/azure-cli-extensions/issues/6637
Invoke-WebRequest -Uri https://secure.globalsign.net/cacert/Root-R1.crt -OutFile c:\globalsignR1.crt
Import-Certificate -FilePath c:\globalsignR1.crt -CertStoreLocation Cert:\LocalMachine\Root


# Inject temporary fix https://portal.microsofticm.com/imp/v5/incidents/details/564169938/summary
$sourceFile = "C:\Temp\akseescript.ps1"  # The target .ps1 file

# Read the target file content
$fileContent = Get-Content -Path $sourceFile

# Define the new code to inject
$newCode = @'
# Temporary fix https://portal.microsofticm.com/imp/v5/incidents/details/564169938/summary
$kubectlPath = "C:\Program Files\AksEdge\kubectl\kubectl.exe"

if (Test-Path $kubectlPath) {
    Write-Host "kubectl.exe found in $kubectlPath"
    robocopy "C:\Program Files\AksEdge\kubectl" "$env:userprofile\.azure\kubectl-client" kubectl.exe
} else {
    Write-Host "Error: kubectl.exe not found in $kubectlPath" -ForegroundColor Red
    exit -1
}
'@

# Find the line to inject after
$targetLine = $fileContent | Select-String -Pattern '^Write-Host "Arc enable the kubernetes cluster' -SimpleMatch
if ($null -eq $targetLine) {
    Write-Host "Target line not found. Injection aborted." -ForegroundColor Red
    exit
}

# Get the index of the target line
$targetIndex = $targetLine.LineNumber - 1  # LineNumber is 1-based, array is 0-based

# Split the content and inject the new code
$before = $fileContent[0..$targetIndex]
$after = $fileContent[$targetIndex + 1..($fileContent.Length - 1)]

# Combine everything
$updatedContent = $before + $newCode + $after

# Save the updated content back to the file
Set-Content -Path $sourceFile -Value $updatedContent -Force

Write-Host "Code successfully injected into $sourceFile." -ForegroundColor Green



az login --service-principal --username $Env:arcAppId --federated-token "$arcFederatedToken" --tenant $Env:arcTenantId

& "C:\Temp\akseescript.ps1" `
    -SubscriptionId $SubscriptionId `
    -TenantId $TenantId `
    -Location $Location `
    -ResourceGroupName $ResourceGroupName `
    -ClusterName $ClusterName `
    -CustomLocationOid $CustomLocationOid `
    -UseK8s:$UseK8s `
    -Tag $Tag