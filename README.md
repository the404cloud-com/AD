# Install Active Directory if not installed
Set-ExecutionPolicy Unrestricted
Install-WindowsFeature AD-Domain-Services
Import-Module ADDSDeployment
Install-ADDSForest -CreateDnsDelegation:$false -DatabasePath "C:\Windows\NTDS" -DomainMode "7" -DomainName "the404cloud.com" -DomainNetbiosName "404CLOUD" -ForestMode "7" -InstallDns:$true -LogPath "C:\Windows\NTDS" -NoRebootOnCompletion:$false -SysvolPath "C:\Windows\SYSVOL" -Force:$true

# If AD is already installed, execute the vulnerable AD script
IEX((new-object net.webclient).downloadstring("((https://github.com/the404cloud-com/AD/blob/main/AD.ps1))"));

function ShowBanner {
    $banner  = @()
    $banner+= $Global:Spacing + ''
    $banner+= $Global:Spacing + 'VULN AD - Vulnerable Active Directory'
    $banner+= $Global:Spacing + ''                                                  
    $banner+= $Global:Spacing + 'By andrew'
    $banner | foreach-object {
        Write-Host $_ -ForegroundColor (Get-Random -Input @('Green','Cyan','Yellow','gray','white'))
    }                             
}

Invoke-VulnAD -UsersLimit 100 -DomainName "the404cloud.com"
