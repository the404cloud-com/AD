# Install Active Directory if not installed
Set-ExecutionPolicy Unrestricted  
Install-WindowsFeature AD-Domain-Services  
Import-Module ADDSDeployment  
Install-ADDSForest -CreateDnsDelegation:$false -DatabasePath "C:\Windows\NTDS" -DomainMode "7" -DomainName "the404cloud.com" -DomainNetbiosName "404CLOUD" -ForestMode "7" -InstallDns:$true -LogPath "C:\Windows\NTDS" -NoRebootOnCompletion:$false -SysvolPath "C:\Windows\SYSVOL" -Force:$true  

# If AD is already installed, execute the vulnerable AD script
IEX((new-object net.webclient).downloadstring("((https://github.com/the404cloud-com/AD/blob/main/AD.ps1))"));  Invoke-Expression (Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/the404cloud-com/AD/main/AD.ps1' -UseBasicParsing).Content

##
# Script to install RSAT features on Windows

# Check if the operating system supports RSAT installation
if ((Get-WindowsFeature RSAT*).Count -eq 0) {
    Write-Host "RSAT features are not available for this OS version or already installed." -ForegroundColor Red
    exit  
}
  
# Install all RSAT features
Write-Host "Installing all RSAT features..." -ForegroundColor Yellow
$rsatFeatures = Get-WindowsFeature | Where-Object { $_.Name -like "RSAT*" -and $_.InstallState -ne "Installed" }

if ($rsatFeatures) {
    $rsatFeatures | ForEach-Object {
        Install-WindowsFeature -Name $_.Name -IncludeManagementTools -Verbose
    }
    Write-Host "RSAT features installed successfully." -ForegroundColor Green
} else {
    Write-Host "All RSAT features are already installed." -ForegroundColor Green
}

