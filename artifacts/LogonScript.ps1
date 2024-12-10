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