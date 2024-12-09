#Base Lists 
$Global:HumansNames = @('Aaren', 'Aarika', 'Abagael', ...); # Truncated for brevity
$Global:BadPasswords = @('123123', 'baseball', ...); # Truncated for brevity
$Global:HighGroups = @('Office Admin','IT Admins','Executives');
$Global:MidGroups = @('Senior management','Project management');
$Global:NormalGroups = @('marketing','sales','accounting');
$Global:BadACL = @('GenericAll','GenericWrite','WriteOwner','WriteDACL','Self','WriteProperty');
$Global:ServicesAccountsAndSPNs = @('mssql_svc,mssqlserver','http_svc,httpserver','exchange_svc,exserver');
$Global:CreatedUsers = @();
$Global:AllObjects = @();
$Global:Domain = "";

#Strings 
$Global:Spacing = "t"
$Global:PlusLine = "t[+]"
$Global:ErrorLine = "t[-]"
$Global:InfoLine = "t[*]"

function Write-Good { param( $String ) Write-Host $Global:PlusLine  $String -ForegroundColor 'Green'}
function Write-Bad  { param( $String ) Write-Host $Global:ErrorLine $String -ForegroundColor 'red'  }
function Write-Info { param( $String ) Write-Host $Global:InfoLine $String -ForegroundColor 'gray' }

function ShowBanner {
    $banner  = @()
    $banner+= $Global:Spacing + ''
    $banner+= $Global:Spacing + 'VULN AD - Vulnerable Active Directory'
    $banner+= $Global:Spacing + ''                                                  
    $banner+= $Global:Spacing + 'By Andrew'
    $banner | foreach-object {
        Write-Host $_ -ForegroundColor (Get-Random -Input @('Green','Cyan','Yellow','gray','white'))
    }                             
}

# All other functions remain the same
# ...
function Invoke-VulnAD {
    Param(
        [int]$UsersLimit = 100,
        [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Position=1)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DomainName
    )
    ShowBanner
    $Global:Domain = $DomainName
    Set-ADDefaultDomainPasswordPolicy -Identity $Global:Domain -LockoutDuration 00:01:00 -LockoutObservationWindow 00:01:00 -ComplexityEnabled $false -ReversibleEncryptionEnabled $False -MinPasswordLength 4
    VulnAD-AddADUser -limit $UsersLimit
    Write-Good "Users Created"
    VulnAD-AddADGroup -GroupList $Global:HighGroups
    Write-Good "$Global:HighGroups Groups Created"
    VulnAD-AddADGroup -GroupList $Global:MidGroups
    Write-Good "$Global:MidGroups Groups Created"
    VulnAD-AddADGroup -GroupList $Global:NormalGroups
    Write-Good "$Global:NormalGroups Groups Created"
    VulnAD-BadAcls
    Write-Good "BadACL Done"
    VulnAD-Kerberoasting
    Write-Good "Kerberoasting Done"
    VulnAD-ASREPRoasting
    Write-Good "AS-REPRoasting Done"
    VulnAD-DnsAdmins
    Write-Good "DnsAdmins Done"
    VulnAD-PwdInObjectDescription
    Write-Good "Password In Object Description Done"
    VulnAD-DefaultPassword
    Write-Good "Default Password Done"
    VulnAD-PasswordSpraying
    Write-Good "Password Spraying Done"
    VulnAD-DCSync
    Write-Good "DCSync Done"
    VulnAD-DisableSMBSigning
    Write-Good "SMB Signing Disabled"
}
