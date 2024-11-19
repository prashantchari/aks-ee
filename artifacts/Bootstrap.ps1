param (
    [string]$adminUsername,
    [string]$arcAppId,
    [string]$arcFederatedToken,
    [string]$arcTenantId,
    [string]$arcSubscriptionId,
    [string]$arcLocation,
    [string]$templateBaseUrl,
    [string]$clusterName,
    [string]$arcResourceGroup,
    [string]$windowsNode,
    [string]$kubernetesDistribution,
    [string]$uamiClientId,
    [string]$proxyCredentialsKeyVaultName,
    [string]$helmRegistry,
    [string]$enableArcGateway,
    [string]$disableArcAgentAutoUpgrade,
    [string]$cpuCoreCount,
    [string]$vmMemory
)

[System.Environment]::SetEnvironmentVariable('adminUsername', $adminUsername,[System.EnvironmentVariableTarget]::Machine)
[System.Environment]::SetEnvironmentVariable('arcAppId', $arcAppId,[System.EnvironmentVariableTarget]::Machine)
[System.Environment]::SetEnvironmentVariable('arcFederatedToken', $arcFederatedToken,[System.EnvironmentVariableTarget]::Machine)
[System.Environment]::SetEnvironmentVariable('arcTenantId', $arcTenantId,[System.EnvironmentVariableTarget]::Machine)
[System.Environment]::SetEnvironmentVariable('clusterName', $clusterName,[System.EnvironmentVariableTarget]::Machine)
[System.Environment]::SetEnvironmentVariable('arcResourceGroup', $arcResourceGroup,[System.EnvironmentVariableTarget]::Machine)
[System.Environment]::SetEnvironmentVariable('arcLocation', $arcLocation,[System.EnvironmentVariableTarget]::Machine)
[System.Environment]::SetEnvironmentVariable('arcSubscriptionId', $arcSubscriptionId,[System.EnvironmentVariableTarget]::Machine)
[System.Environment]::SetEnvironmentVariable('templateBaseUrl', $templateBaseUrl,[System.EnvironmentVariableTarget]::Machine)
[System.Environment]::SetEnvironmentVariable('kubernetesDistribution', $kubernetesDistribution,[System.EnvironmentVariableTarget]::Machine)
[System.Environment]::SetEnvironmentVariable('windowsNode', $windowsNode,[System.EnvironmentVariableTarget]::Machine)
[System.Environment]::SetEnvironmentVariable('proxyCredentialsKeyVaultName', $proxyCredentialsKeyVaultName,[System.EnvironmentVariableTarget]::Machine)
[System.Environment]::SetEnvironmentVariable('enableArcGateway', $enableArcGateway,[System.EnvironmentVariableTarget]::Machine)
[System.Environment]::SetEnvironmentVariable('disableArcAgentAutoUpgrade', $disableArcAgentAutoUpgrade,[System.EnvironmentVariableTarget]::Machine)
[System.Environment]::SetEnvironmentVariable('cpuCoreCount', $cpuCoreCount,[System.EnvironmentVariableTarget]::Machine)
[System.Environment]::SetEnvironmentVariable('vmMemory', $vmMemory,[System.EnvironmentVariableTarget]::Machine)

if ($helmRegistry){
    [System.Environment]::SetEnvironmentVariable('HELMREGISTRY', $helmRegistry,[System.EnvironmentVariableTarget]::Machine)
}

if ($uamiClientId){
    [System.Environment]::SetEnvironmentVariable('AZCOPY_AUTO_LOGIN_TYPE', "MSI",[System.EnvironmentVariableTarget]::Machine)
    [System.Environment]::SetEnvironmentVariable('AZCOPY_MSI_CLIENT_ID', $uamiClientId,[System.EnvironmentVariableTarget]::Machine)
}

# Create path
Write-Output "Create deployment path"
$tempDir = "C:\Temp"
New-Item -Path $tempDir -ItemType directory -Force

Start-Transcript "C:\Temp\Bootstrap.log"

$ErrorActionPreference = "SilentlyContinue"

# Downloading GitHub artifacts
Invoke-WebRequest ($templateBaseUrl + "artifacts/LogonScript.ps1") -OutFile "C:\Temp\LogonScript.ps1"
Invoke-WebRequest "https://raw.githubusercontent.com/Azure/arc_jumpstart_docs/main/img/wallpaper/jumpstart_wallpaper_dark.png" -OutFile "C:\Temp\wallpaper.png"

# Installing tools
workflow ClientTools_01
        {
            $chocolateyAppList = 'azure-cli,azcopy10,az.powershell,kubernetes-cli,kubernetes-helm'
            #Run commands in parallel.
            Parallel 
                {
                    InlineScript {
                        param (
                            [string]$chocolateyAppList
                        )
                        if ([string]::IsNullOrWhiteSpace($using:chocolateyAppList) -eq $false)
                        {
                            try{
                                choco config get cacheLocation
                            }catch{
                                Write-Output "Chocolatey not detected, trying to install now"
                                Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
                            }
                        }
                        if ([string]::IsNullOrWhiteSpace($using:chocolateyAppList) -eq $false){   
                            Write-Host "Chocolatey Apps Specified"  
                            
                            $appsToInstall = $using:chocolateyAppList -split "," | ForEach-Object { "$($_.Trim())" }
                        
                            foreach ($app in $appsToInstall)
                            {
                                Write-Host "Installing $app"
                                & choco install $app /y -Force| Write-Output
                            }
                        }                        
                    }
                }
        }

ClientTools_01 | Format-Table

# Enable VirtualMachinePlatform feature, the vm reboot will be done in DSC extension
Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart

# Disable Microsoft Edge sidebar
$RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
$Name         = 'HubsSidebarEnabled'
$Value        = '00000000'
# Create the key if it does not exist
If (-NOT (Test-Path $RegistryPath)) {
  New-Item -Path $RegistryPath -Force | Out-Null
}
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force

# Disable Microsoft Edge first-run Welcome screen
$RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
$Name         = 'HideFirstRunExperience'
$Value        = '00000001'
# Create the key if it does not exist
If (-NOT (Test-Path $RegistryPath)) {
  New-Item -Path $RegistryPath -Force | Out-Null
}
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force

# # Creating scheduled task for LogonScript.ps1
# Invoke-Command -FilePath C:\Temp\LogonScript.ps1
# $Trigger = New-ScheduledTaskTrigger -AtStartUp
# $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument 'C:\Temp\LogonScript.ps1'
# Register-ScheduledTask -TaskName "LogonScript" -Trigger $Trigger -User $adminUsername -Action $Action -RunLevel "Highest" -Force

# Disabling Windows Server Manager Scheduled Task
Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask


# Clean up Bootstrap.log
Stop-Transcript
$logSuppress = Get-Content C:\Temp\Bootstrap.log | Where { $_ -notmatch "Host Application: powershell.exe" } 
$logSuppress | Set-Content C:\Temp\Bootstrap.log -Force