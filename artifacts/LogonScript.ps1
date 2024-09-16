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

$EnableArcGateway = $env:enableArcGateway

#Requires -RunAsAdministrator

function Verify-ConnectedStatus
{
param(
    [Parameter(Mandatory=$true)]
    [object] $arcArgs,
    [Parameter(Mandatory=$true)]
    [string] $clusterName
)

    $k8sConnectArgs = @("-g", $arcArgs.ResourceGroupName)
    $k8sConnectArgs += @("-n", $clusterName)
    $k8sConnectArgs += @("--subscription", $arcArgs.SubscriptionId)

    # 15 min timeout to check for Connected status - as recommended by Arc team
    $retries = 90
    $sleepDurationInSeconds = 10
    for (; $retries -gt 0; $retries--)
    {
        $connectedCluster = az connectedk8s show $k8sConnectArgs | ConvertFrom-Json
        if ($connectedCluster.ConnectivityStatus -eq "Connected")
        {
            Write-Host "Cluster reached connected status"
            break
        }

        Write-Host "Arc connection status is $($connectedCluster.ConnectivityStatus). Waiting for status to be connected..."
        Start-Sleep -Seconds $sleepDurationInSeconds
    }

    if ($retries -eq 0)
    {
        throw "Arc Connection timed out!"
    }
}

function New-ConnectedCluster
{
param(
    [Parameter(Mandatory=$true)]
    [object] $arcArgs,
    [Parameter(Mandatory=$true)]
    [string] $clusterName,
    [Switch] $useK8s=$false,
    # Optional parameter
    [string] $arcgwResourceId = $null
)

    Write-Host "New-ConnectedCluster"

    $tags = @("SKU=AKSEdgeEssentials")
    $aksEdgeVersion = (Get-Module -Name AksEdge).Version.ToString()
    if ($aksEdgeVersion) {
        $tags += @("AKSEE Version=$aksEdgeVersion")
    }
    $infra = Get-AideInfra
    if ($infra) { 
        $tags += @("Host Infra=$infra")
    }
    $clusterid = $(kubectl get configmap -n aksedge aksedge -o jsonpath="{.data.clustername}")
    if ($clusterid) { 
        $tags += @("ClusterId=$clusterid")
    }

    $k8sConnectArgs = @("-g", $arcArgs.ResourceGroupName)
    $k8sConnectArgs += @("-n", $clusterName)
    $k8sConnectArgs += @("-l", $arcArgs.Location)
    $k8sConnectArgs += @("--subscription", $arcArgs.SubscriptionId)
    $k8sConnectArgs += @("--tags", $tags)

    if ($arcgwResourceId) {
        $k8sConnectArgs += @("--gateway-resource-id", $arcgwResourceId)
        $k8sConnectArgs += @("-l", "eastus2euap", "--disable-auto-upgrade")
    }

    Write-Host "Connect cmd args - $k8sConnectArgs"

    $errOut = $($retVal = & {az connectedk8s connect $k8sConnectArgs}) 2>&1
    if ($LASTEXITCODE -ne 0)
    {
        throw "Arc Connection failed with error : $errOut"
    }

    Verify-ConnectedStatus -arcArgs $arcArgs -clusterName $ClusterName
}

function New-ArcGateway {
    param (
        [Parameter(Mandatory=$true)]
        [object] $arcArgs,

        [string] $gatewayName = "arcgw",
        [string] $location = "eastus2euap" 
    )

    Write-Host "Registering the GatewayPreview feature..."
    # Register the feature for Azure Arc
    $errOut = $($retVal = & {az feature registration create --namespace Microsoft.HybridCompute --name GatewayPreview --subscription $arcArgs.SubscriptionId}) 2>&1
    if ($LASTEXITCODE -ne 0)
    {
        throw "Failed to register the GatewayPreview feature : $errOut"
    }

    Write-Host "Installing Azure Arc extensions..."
    # Install the Arc agent and Arc gateway CLI extensions
    # TODO: Remove the whl files once arc agent and arc gw CLI extension are available in public preview
    $errOut = $($retVal = & {az extension add --allow-preview $true --upgrade --yes --source https://arcgwprodsa.blob.core.windows.net/public/connectedmachine-0.7.0-py3-none-any.whl}) 2>&1
    if ($LASTEXITCODE -ne 0)
    {
        throw "Failed to install the Arc extension connectedmachine with error : $errOut"
    }
    $errOut = $($retVal = & {az extension add --allow-preview $true --upgrade --yes --source https://github.com/AzureArcForKubernetes/azure-cli-extensions/raw/connectedk8s/public/cli-extensions/connectedk8s-1.10.0-py2.py3-none-any.whl}) 2>&1
    if ($LASTEXITCODE -ne 0)
    {
        throw "Failed to install the Arc extension connectedk8s with error : $errOut"
    }

    Write-Host "Creating the Azure Arc Gateway..."
    # Create an Azure Arc Gateway
    # TODO: Use --location ARC_REGION once arc gateway resource is available in non-canary regions
    $errOut = $($retVal = & {az connectedmachine gateway create --name $gatewayName --resource-group $arcArgs.ResourceGroupName --location $location --gateway-type public --allowed-features '*' --subscription $arcArgs.SubscriptionId}) 2>&1
    if ($LASTEXITCODE -ne 0)
    {
        throw "Failed to create the Arc Gateway with error : $errOut"
    }

    Write-Host "Retrieving Arc Gateway Resource ID..."
    # Get the Arc Gateway Resource ID
    $errOut = $($arcGwResourceId = & {az connectedmachine gateway show --name $gatewayName --resource-group $arcArgs.ResourceGroupName --query id -o tsv --subscription $arcArgs.SubscriptionId}) 2>&1
    if ($LASTEXITCODE -ne 0)
    {
        throw "Failed to retrieve the Arc Gateway Resource ID with error : $errOut"
    }
    # Print the Arc Gateway Resource ID
    Write-Host "Arc Gateway Resource ID: $arcGwResourceId"

    # Return the Arc Gateway Resource ID in case the function needs to be used programmatically
    return $arcGwResourceId
}
Start-Transcript -Path C:\Temp\LogonScript.log

# The federated token is short lived so convert it immediately to tokens with longer lifetime.
# Convert federated token to ARM access token
az login --service-principal --username $Env:arcAppId --federated-token "$arcFederatedToken" --tenant $Env:arcTenantId

# Acquire a key vault scoped access token before the federated token expires
az account get-access-token --scope https://vault.azure.net/.default --output none

# Download MSI when msiUrl is specified
if ($msiUrl){
    Write-Host "MSI URL: $msiUrl"
    $msiFileName = Split-Path $msiUrl -Leaf
    $msiLocalDir = "C:\Users\Public\Downloads"
    $msiLocalPath = Join-Path -Path $msiLocalDir -ChildPath $msiFileName
    azcopy copy $msiUrl $msiLocalPath
    Write-Host "MSI Local File Path: $msiLocalPath"
}

# MSI avaliable locally ?
if ( $msiUrl ){
    $productUrl = $msiLocalPath.replace('\','\\')
}  else {
    $productUrl = "https://download.microsoft.com/download/9/0/8/9089c6e0-bc8e-4318-b1e0-a045c29fc14d/AksEdge-K3s-1.29.6-1.8.202.0.msi"
}
Write-Host "Product Url: $productUrl"
# ================================================================================================


New-Variable -Name gAksEdgeQuickStartForAioVersion -Value "1.0.240815.1500" -Option Constant -ErrorAction SilentlyContinue

# Specify only AIO supported regions
New-Variable -Option Constant -ErrorAction SilentlyContinue -Name arcLocations -Value @(
    "eastus", "eastus2", "northeurope", "westeurope", "westus", "westus2", "westus3"
)

if (! [Environment]::Is64BitProcess) {
    Write-Host "Error: Run this in 64bit Powershell session" -ForegroundColor Red
    exit -1
}
#Validate inputs
if ($arcLocations -inotcontains $Location) {
    Write-Host "Error: Location $Location is not supported for Azure Arc" -ForegroundColor Red
    Write-Host "Supported Locations : $arcLocations"
    exit -1
}

# Validate az cli version.
try {
    $azVersion = (az version)[1].Split(":")[1].Split('"')[1]
    if ($azVersion -lt "2.38.0"){
        Write-Host "Installed Azure CLI version $azVersion is older than 2.38.0. Please upgrade Azure CLI and retry." -ForegroundColor Red
        exit -1
    }
}
catch {
    Write-Host "Please install Azure CLI version 2.38.0 or newer and retry." -ForegroundColor Red
    exit -1
}

# Ensure logged into Azure
$azureLogin = az account show
if ( $null -eq $azureLogin){
    Write-Host "Please login to azure via `az login` and retry." -ForegroundColor Red
    exit -1
}

# Ensure `connectedk8s` az cli extension is installed and up to date.
az extension add --upgrade --name connectedk8s -y --allow-preview false

$installDir = $((Get-Location).Path)
$productName = "AKS Edge Essentials - K3s"
$networkplugin = "flannel"
if ($UseK8s) {
    $productName ="AKS Edge Essentials - K8s"
    $networkplugin = "calico"
}

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
    "SchemaVersion": "1.13",
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

###
# Main
###
if (-not (Test-Path -Path $installDir)) {
    Write-Host "Creating $installDir..."
    New-Item -Path "$installDir" -ItemType Directory | Out-Null
}

$starttime = Get-Date
$starttimeString = $($starttime.ToString("yyMMdd-HHmm"))
$transcriptFile = "$installDir\aksedgedlog-$starttimeString.txt"

Start-Transcript -Path $transcriptFile

Set-ExecutionPolicy Bypass -Scope Process -Force
# Download the AksEdgeDeploy modules from Azure/AksEdge
$fork ="Azure"
$branch="main"
$url = "https://github.com/$fork/AKS-Edge/archive/$branch.zip"
$zipFile = "AKS-Edge-$branch.zip"
$workdir = "$installDir\AKS-Edge-$branch"
if (-Not [string]::IsNullOrEmpty($Tag)) {
    $url = "https://github.com/$fork/AKS-Edge/archive/refs/tags/$Tag.zip"
    $zipFile = "$Tag.zip"
    $workdir = "$installDir\AKS-Edge-$tag"
}
Write-Host "Step 1 : Azure/AKS-Edge repo setup" -ForegroundColor Cyan

if (!(Test-Path -Path "$installDir\$zipFile")) {
    try {
        Invoke-WebRequest -Uri $url -OutFile $installDir\$zipFile
    } catch {
        Write-Host "Error: Downloading Aide Powershell Modules failed" -ForegroundColor Red
        Stop-Transcript | Out-Null
        Pop-Location
        exit -1
    }
}
if (!(Test-Path -Path "$workdir")) {
    Expand-Archive -Path $installDir\$zipFile -DestinationPath "$installDir" -Force
}

$aidejson = (Get-ChildItem -Path "$workdir" -Filter aide-userconfig.json -Recurse).FullName
Set-Content -Path $aidejson -Value $aideuserConfig -Force
$aideuserConfigJson = $aideuserConfig | ConvertFrom-Json

$aksedgejson = (Get-ChildItem -Path "$workdir" -Filter aksedge-config.json -Recurse).FullName
Set-Content -Path $aksedgejson -Value $aksedgeConfig -Force

$aksedgeShell = (Get-ChildItem -Path "$workdir" -Filter AksEdgeShell.ps1 -Recurse).FullName
. $aksedgeShell

# Download, install and deploy AKS EE 
Write-Host "Step 2: Download, install and deploy AKS Edge Essentials" -ForegroundColor Cyan
# invoke the workflow, the json file already updated above.
$retval = Start-AideWorkflow -jsonFile $aidejson 2> $null
if ($retval) {
    Write-Host "Deployment Successful. "
} else {
    Write-Error -Message "Deployment failed" -Category OperationStopped
    Stop-Transcript | Out-Null
    Pop-Location
    exit -1
}

Write-Host "Step 3: Connect the cluster to Azure" -ForegroundColor Cyan
# Set the azure subscription
$errOut = $($retVal = & {az account set -s $SubscriptionId}) 2>&1
if ($LASTEXITCODE -ne 0)
{
    throw "Error setting Subscription ($SubscriptionId): $errOut"
}

# Register the required resource providers 
$resourceProviders = 
@(
    "Microsoft.ExtendedLocation",
    "Microsoft.Kubernetes",
    "Microsoft.KubernetesConfiguration"
)
foreach($rp in $resourceProviders)
{
    $errOut = $($obj = & {az provider show -n $rp | ConvertFrom-Json}) 2>&1
    if ($LASTEXITCODE -ne 0)
    {
        throw "Error querying provider $rp : $errOut"
    }

    if ($obj.registrationState -eq "Registered")
    {
        continue
    }

    $errOut = $($retVal = & {az provider register -n $rp}) 2>&1
    if ($LASTEXITCODE -ne 0)
    {
        throw "Error registering provider $rp : $errOut"
    }
}
Write-Host "...............Get Env Variables........................" -ForegroundColor Cyan
Get-ChildItem Env:
Write-Host "........................................................" -ForegroundColor Cyan

# Arc-enable the Kubernetes cluster
Write-Host "Arc enable the kubernetes cluster $ClusterName" -ForegroundColor Cyan
# https://github.com/Azure/azure-cli-extensions/issues/6637
Invoke-WebRequest -Uri https://secure.globalsign.net/cacert/Root-R1.crt -OutFile c:\globalsignR1.crt
Import-Certificate -FilePath c:\globalsignR1.crt -CertStoreLocation Cert:\LocalMachine\Root

# Check if $EnableArcGateway is enabled (i.e., $true)
if ($EnableArcGateway -eq "true") {
    Write-Host "Arc Gateway is enabled, creating the Arc Gateway resource."
    $arcgwResourceId = New-ArcGateway -arcArgs $aideuserConfigJson.Azure
    New-ConnectedCluster -clusterName $ClusterName -arcArgs $aideuserConfigJson.Azure -useK8s:$UseK8s -arcgwResourceId $arcgwResourceId
} else {
    New-ConnectedCluster -clusterName $ClusterName -arcArgs $aideuserConfigJson.Azure -useK8s:$UseK8s
}


# Enable custom location support on your cluster using az connectedk8s enable-features command
Write-Host "Associate Custom location with $ClusterName cluster"
$objectId = $aideuserConfigJson.Azure.CustomLocationOID
if ([string]::IsNullOrEmpty($objectId))
{
    $customLocationsAppId = "bc313c14-388c-4e7d-a58e-70017303ee3b"
    $errOut = $($objectId = & {az ad sp show --id $customLocationsAppId --query id -o tsv}) 2>&1
    if ($null -eq $objectId)
    {
        throw "Error querying ObjectId for CustomLocationsAppId : $errOut"
    }
}
$errOut = $($retVal = & {az connectedk8s enable-features -n $ClusterName -g $ResourceGroupName --custom-locations-oid $objectId --features cluster-connect custom-locations}) 2>&1
if ($LASTEXITCODE -ne 0)
{
    throw "Error enabling feature CustomLocations : $errOut"
}

Write-Host "Step 4: Prep for AIO workload deployment" -ForegroundColor Cyan
Write-Host "Deploy local path provisioner"
try {
    $localPathProvisionerYaml= (Get-ChildItem -Path "$workdir" -Filter local-path-storage.yaml -Recurse).FullName
    & kubectl apply -f $localPathProvisionerYaml
    Write-Host "Successfully deployment the local path provisioner"
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

    # Add additional firewall rules
    $dports = @(10124, 8420, 2379, 50051)
    foreach($port in $dports)
    {
        $iptableRulesExist = Invoke-AksEdgeNodeCommand -NodeType "Linux" -command "sudo iptables-save | grep -- '-m tcp --dport $port -j ACCEPT'" -ignoreError
        if ( $null -eq $iptableRulesExist ) {
            Invoke-AksEdgeNodeCommand -NodeType "Linux" -command "sudo iptables -A INPUT -p tcp --dport $port -j ACCEPT"
            Write-Host "Updated runtime iptable rules for port $port"
        }
        else {
            Write-Host "iptable rule exists, skip configuring iptable rule for port $port..."
        }
    }
}
catch {
    Write-Host "Error: iptable rule update failed" -ForegroundColor Red
    Stop-Transcript | Out-Null
    Pop-Location
    exit -1 
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

$endtime = Get-Date
$duration = ($endtime - $starttime)
Write-Host "Duration: $($duration.Hours) hrs $($duration.Minutes) mins $($duration.Seconds) seconds"
Stop-Transcript | Out-Null
Pop-Location
exit 0