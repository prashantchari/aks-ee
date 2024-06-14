param (
    [string]$arcFederatedToken
)

Start-Transcript -Path C:\Temp\LogonScript.log

# The federated token is short lived so convert it immediately to tokens with longer lifetime.
# Convert federated token to ARM access token
az login --service-principal --username $Env:arcAppId --federated-token "$arcFederatedToken" --tenant $Env:arcTenantId

# Acquire a key vault scoped access token before the federated token expires
az account get-access-token --scope https://vault.azure.net/.default --output none

## Deploy AKS EE

# Parameters
$AksEdgeRemoteDeployVersion = "1.0.230221.1200"
$schemaVersion = "1.1"
$versionAksEdgeConfig = "1.0"
$aksEdgeDeployModules = "main"
$aksEEReleasesUrl = "https://api.github.com/repos/Azure/AKS-Edge/releases"

# Requires -RunAsAdministrator

New-Variable -Name AksEdgeRemoteDeployVersion -Value $AksEdgeRemoteDeployVersion -Option Constant -ErrorAction SilentlyContinue

if (! [Environment]::Is64BitProcess) {
    Write-Host "Error: Run this in 64bit Powershell session" -ForegroundColor Red
    exit -1
}

if ($env:kubernetesDistribution -eq "k8s") {
    $productName = "AKS Edge Essentials - K8s"
    $networkplugin = "calico"
} else {
    $productName = "AKS Edge Essentials - K3s"
    $networkplugin = "flannel"
}

$latestReleaseTag = "1.6.384.0" # (Invoke-WebRequest $aksEEReleasesUrl -UseBasicParsing | ConvertFrom-Json)[0].tag_name
Write-Host "Fetching the AKS Edge Essentials release: $latestReleaseTag"

$AKSEEReleaseDownloadUrl = "https://github.com/Azure/AKS-Edge/archive/refs/tags/$latestReleaseTag.zip"
$output = Join-Path "C:\temp" "$latestReleaseTag.zip"
Invoke-WebRequest $AKSEEReleaseDownloadUrl -OutFile $output -UseBasicParsing
Expand-Archive $output -DestinationPath "C:\temp" -Force
$AKSEEReleaseConfigFilePath = "C:\temp\AKS-Edge-$latestReleaseTag\tools\aksedge-config.json"
$jsonContent = Get-Content -Raw -Path $AKSEEReleaseConfigFilePath | ConvertFrom-Json
$schemaVersionAksEdgeConfig = $jsonContent.SchemaVersion
# Clean up the downloaded release files
Remove-Item -Path $output -Force
Remove-Item -Path "C:\temp\AKS-Edge-$latestReleaseTag" -Force -Recurse


# Here string for the json content
$aideuserConfig = @"
{
    "SchemaVersion": "$AksEdgeRemoteDeployVersion",
    "Version": "$schemaVersion",
    "AksEdgeProduct": "$productName",
    "AksEdgeProductUrl": "https://download.microsoft.com/download/3/d/7/3d7b3eea-51c2-4a2c-8405-28e40191e715/AksEdge-K3s-1.26.10-1.6.384.0.msi",
    "Azure": {
        "SubscriptionId": "$env:arcSubscriptionId",
        "TenantId": "$env:arcTenantId",
        "ResourceGroupName": "$env:arcResourceGroup",
        "Location": "$env:arcLocation"
    },
    "AksEdgeConfigFile": "aksedge-config.json"
}
"@

$aksedgeConfig = @"
{
    "SchemaVersion": "1.9",
    "Version": "1.0",
    "DeploymentType": "SingleMachineCluster",
    "Init": {
        "ServiceIPRangeSize": 10
    },
    "Network": {
        "NetworkPlugin": "$networkplugin",
        "InternetDisabled": false
    },
    "User": {
        "AcceptEula": true,
        "AcceptOptionalTelemetry": true
    },
    "Machines": [
        {
            "LinuxNode": {
                "CpuCount": 8,
                "MemoryInMB": 16384,
                "DataSizeInGB": 40,
                "LogSizeInGB": 4
            }
        }
    ]
}
"@

Set-ExecutionPolicy Bypass -Scope Process -Force
# Download the AksEdgeDeploy modules from Azure/AksEdge
$url = "https://github.com/Azure/AKS-Edge/archive/$aksEdgeDeployModules.zip"
$zipFile = "$aksEdgeDeployModules.zip"
$installDir = "C:\AksEdgeScript"
$workDir = "$installDir\AKS-Edge-main"

if (-not (Test-Path -Path $installDir)) {
    Write-Host "Creating $installDir..."
    New-Item -Path "$installDir" -ItemType Directory | Out-Null
}

Push-Location $installDir

Write-Host "`n"
Write-Host "About to silently install AKS Edge Essentials, this will take a few minutes." -ForegroundColor Green
Write-Host "`n"

try {
    function download2() { $ProgressPreference = "SilentlyContinue"; Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $installDir\$zipFile }
    download2
}
catch {
    Write-Host "Error: Downloading Aide Powershell Modules failed" -ForegroundColor Red
    Stop-Transcript | Out-Null
    Pop-Location
    exit -1
}

if (!(Test-Path -Path "$workDir")) {
    Expand-Archive -Path $installDir\$zipFile -DestinationPath "$installDir" -Force
}

$aidejson = (Get-ChildItem -Path "$workDir" -Filter aide-userconfig.json -Recurse).FullName
Set-Content -Path $aidejson -Value $aideuserConfig -Force
$aksedgejson = (Get-ChildItem -Path "$workDir" -Filter aksedge-config.json -Recurse).FullName
Set-Content -Path $aksedgejson -Value $aksedgeConfig -Force

$aksedgeShell = (Get-ChildItem -Path "$workDir" -Filter AksEdgeShell.ps1 -Recurse).FullName
. $aksedgeShell

# Download, install and deploy AKS EE 
Write-Host "Step 2: Download, install and deploy AKS Edge Essentials"
# invoke the workflow, the json file already stored above.
$retval = Start-AideWorkflow -jsonFile $aidejson
# report error via Write-Error for Intune to show proper status
if ($retval) {
    Write-Host "Deployment Successful. "
} else {
    Write-Error -Message "Deployment failed" -Category OperationStopped
    Stop-Transcript | Out-Null
    Pop-Location
    exit -1
}

if ($env:windowsNode -eq $true) {
    # Get a list of all nodes in the cluster
    $nodes = kubectl get nodes -o json | ConvertFrom-Json

    # Loop through each node and check the OSImage field
    foreach ($node in $nodes.items) {
        $os = $node.status.nodeInfo.osImage
        if ($os -like '*windows*') {
            # If the OSImage field contains "windows", assign the "worker" role
            kubectl label nodes $node.metadata.name node-role.kubernetes.io/worker=worker
        }
    }
}

Write-Host "`n"
Write-Host "Checking kubernetes nodes"
Write-Host "`n"
kubectl get nodes -o wide | Write-Host
Write-Host "`n"

Write-Host "Prep for AIO workload deployment" -ForegroundColor Cyan

Write-Host "Deploy local path provisioner"
try {
    $localPathProvisionerYaml= (Get-ChildItem -Path "$workdir" -Filter local-path-storage.yaml -Recurse).FullName
    kubectl apply -f $localPathProvisionerYaml | Write-Host
    Write-Host "Successfully deployment the local path provisioner from $localPathProvisionerYaml"
}
catch {
    Write-Host "Error: local path provisioner deployment failed" -ForegroundColor Red
    Stop-Transcript | Out-Null
    Pop-Location
    exit -1 
}

Write-Host "Configuring firewall specific to AIO"
try {
    $fireWallRuleExists = Get-NetFirewallRule -DisplayName "AIO MQTT Broker"  -ErrorAction SilentlyContinue
    if ( $null -eq $fireWallRuleExists ) {
        Write-Host "Add firewall rule for AIO MQTT Broker"
        New-NetFirewallRule -DisplayName "AIO MQTT Broker" -Direction Inbound -Action Allow | Out-Null
    }
    else {
        Write-Host "firewall rule for AIO MQTT Broker exists, skip configuring firewall rule..."
    }   
}
catch {
    Write-Host "Error: Firewall rule addition for AIO MQTT broker failed" -ForegroundColor Red
    Stop-Transcript | Out-Null
    Pop-Location
    exit -1 
}

Write-Host "Configuring port proxy for AIO"
try {
    $deploymentInfo = Get-AksEdgeDeploymentInfo
    # Get the service ip address start to determine the connect address
    $connectAddress = $deploymentInfo.LinuxNodeConfig.ServiceIpRange.split("-")[0]
    $portProxyRulExists = netsh interface portproxy show v4tov4 | findstr /C:"1883" | findstr /C:"$connectAddress"
    if ( $null -eq $portProxyRulExists ) {
        Write-Host "Configure port proxy for AIO"
        netsh interface portproxy add v4tov4 listenport=1883 listenaddress=0.0.0.0 connectport=1883 connectaddress=$connectAddress | Out-Null
    }
    else {
        Write-Host "Port proxy rule for AIO exists, skip configuring port proxy..."
    } 
}
catch {
    Write-Host "Error: port proxy update for AIO failed" -ForegroundColor Red
    Stop-Transcript | Out-Null
    Pop-Location
    exit -1 
}

Write-Host "Update the iptables rules"
try {
    $iptableRulesExist = Invoke-AksEdgeNodeCommand -NodeType "Linux" -command "sudo iptables-save | grep -- '-m tcp --dport 9110 -j ACCEPT'" -ignoreError
    if ( $null -eq $iptableRulesExist ) {
        Invoke-AksEdgeNodeCommand -NodeType "Linux" -command "sudo iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 9110 -j ACCEPT"
        Write-Host "Updated runtime iptable rules for node exporter"
        Invoke-AksEdgeNodeCommand -NodeType "Linux" -command "sudo sed -i '/-A OUTPUT -j ACCEPT/i-A INPUT -p tcp -m tcp --dport 9110 -j ACCEPT' /etc/systemd/scripts/ip4save"
        Write-Host "Persisted iptable rules for node exporter"
    }
    else {
        Write-Host "iptable rule exists, skip configuring iptable rules..."
    } 
}
catch {
    Write-Host "Error: iptable rule update failed" -ForegroundColor Red
    Stop-Transcript | Out-Null
    Pop-Location
    exit -1 
}

# az version
az -v

# Set default subscription to run commands against
# "subscriptionId" value comes from clientVM.json ARM template, based on which 
# subscription user deployed ARM template to. This is needed in case Service 
# Principal has access to multiple subscriptions, which can break the automation logic
az account set --subscription $env:arcSubscriptionId *>&1

Write-Host "Creating admin credentials"
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

# Installing Azure CLI extensions
# Making extension install dynamic
az config set extension.use_dynamic_install=yes_without_prompt
Write-Host "`n"
Write-Host "Installing Azure CLI extensions"
az extension add --name connectedk8s
az extension add --name k8s-extension
Write-Host "`n"

# Registering Azure Arc providers
Write-Host "Registering Azure Arc providers, hold tight..."
Write-Host "`n"
az provider register --namespace Microsoft.Kubernetes --wait
az provider register --namespace Microsoft.KubernetesConfiguration --wait
az provider register --namespace Microsoft.ExtendedLocation --wait

# Onboarding the cluster to Azure Arc
Write-Host "Onboarding the AKS Edge Essentials cluster to Azure Arc..."
Write-Host "`n"

# https://github.com/Azure/azure-cli-extensions/issues/6637
Invoke-WebRequest -Uri https://secure.globalsign.net/cacert/Root-R1.crt -OutFile c:\globalsignR1.crt
Import-Certificate -FilePath c:\globalsignR1.crt -CertStoreLocation Cert:\LocalMachine\Root

$timeout = 900
$startTime = Get-Date
$endTime = $startTime.AddSeconds($timeout)
$arcEnabled = ' '


while ((Get-Date) -lt $endTime -and $arcEnabled -ne 'Succeeded') {

    if ($env:kubernetesDistribution -eq "k8s") {
        az connectedk8s connect --name $Env:clusterName `
        --resource-group $Env:arcResourceGroup `
        --location $env:arcLocation `
        --custom-locations-oid 51dfe1e8-70c6-4de5-a08e-e18aff23d815 `
        --onboarding-timeout 1200 `
        --distribution aks_edge_k8s | Write-Host
    } else {
        az connectedk8s connect --name $Env:clusterName `
        --resource-group $Env:arcResourceGroup `
        --location $env:arcLocation `
        --custom-locations-oid 51dfe1e8-70c6-4de5-a08e-e18aff23d815 `
        --onboarding-timeout 1200 `
        --distribution aks_edge_k3s | Write-Host
    }

    $arcEnabled = az connectedk8s show --name $Env:clusterName --resource-group $Env:arcResourceGroup --query "provisioningState" --only-show-errors -o tsv 2> null
    if ($arcEnabled -ne 'Succeeded') {
        Write-Host "Writing arc enablement troubleshoot logs"
        az connectedk8s troubleshoot  --name $Env:clusterName --resource-group $Env:arcResourceGroup
    }
    Start-Sleep -Seconds 30
}

if ($arcEnabled -eq 'Succeeded') {
    Write-Host "Cluster is Arc-enabled"
}
else {
    Write-Host "Timeout reached, cluster is not Arc-enabled"
    exit 1
}

# enable features
az connectedk8s enable-features --name $Env:clusterName --resource-group $Env:arcResourceGroup --features cluster-connect custom-locations --custom-locations-oid 51dfe1e8-70c6-4de5-a08e-e18aff23d815 | Write-Host

Stop-Transcript
exit 0