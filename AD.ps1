# This script configures a vulnerable Active Directory environment for testing purposes.
# WARNING: Use only in a controlled lab environment. DO NOT RUN IN PRODUCTION.

# Basic configuration
$DomainName = "vulnerable.local"
$DefaultPassword = "WeakP@ssw0rd"  # Default weak password

# Function to create vulnerable Access Control Lists (ACLs) and Access Control Entries (ACEs)
function Configure-WeakACLs {
    Write-Host "Configuring weak ACLs..."
    $WeakUser = Get-ADUser -Filter {Name -eq "VulnerableUser1"}
    $AdminGroup = Get-ADGroup -Identity "Domain Admins"
    
    $Acl = Get-ACL -Path "AD:$($AdminGroup.DistinguishedName)"
    $AccessRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule `
        ($WeakUser.DistinguishedName, "GenericAll", "Allow")
    $Acl.AddAccessRule($AccessRule)
    Set-ACL -Path "AD:$($AdminGroup.DistinguishedName)" -AclObject $Acl
    Write-Host "Weak ACL configured for Domain Admins group."
}

# Function to create Kerberoastable accounts
function Create-KerberoastableAccounts {
    Write-Host "Creating Kerberoastable accounts..."
    New-ADUser -Name "KerberoastableUser" `
               -UserPrincipalName "kerberoastable@$DomainName" `
               -ServicePrincipalName "HTTP/kerberoastable" `
               -AccountPassword (ConvertTo-SecureString "Service123!" -AsPlainText -Force) `
               -Enabled $true
    Write-Host "Kerberoastable account created."
}

# Function to create AS-REP roastable accounts
function Create-ASREPAccounts {
    Write-Host "Creating AS-REP roastable accounts..."
    New-ADUser -Name "ASREPUser" `
               -UserPrincipalName "asrepuser@$DomainName" `
               -CannotChangePassword $true `
               -DoesNotRequirePreAuth $true `
               -AccountPassword (ConvertTo-SecureString "NoPreAuth!" -AsPlainText -Force) `
               -Enabled $true
    Write-Host "AS-REP roastable account created."
}

# Function to abuse DnsAdmins group
function Configure-DnsAdmins {
    Write-Host "Adding vulnerabilities to DNSAdmins group..."
    Add-ADGroupMember -Identity "DnsAdmins" -Members "VulnerableUser1"
    Write-Host "DnsAdmins group configured with vulnerabilities."
}

# Function to embed passwords in object descriptions
function Embed-PasswordsInDescriptions {
    Write-Host "Embedding passwords in object descriptions..."
    Set-ADUser -Identity "VulnerableUser1" -Description "Password=WeakP@ssw0rd"
    Write-Host "Password embedded in VulnerableUser1's description."
}

# Function to disable SMB signing
function Disable-SmbSigning {
    Write-Host "Disabling SMB signing..."
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 0
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableSecuritySignature" -Value 0
    Write-Host "SMB signing disabled."
}

# Function to create users with weak default passwords
function Create-VulnerableUsers {
    Write-Host "Creating users with weak passwords..."
    $NumberOfUsers = 50  # Modify as needed
    for ($i = 1; $i -le $NumberOfUsers; $i++) {
        $Username = "VulnerableUser$i"
        $SecurePassword = ConvertTo-SecureString $DefaultPassword -AsPlainText -Force
        New-ADUser -Name $Username `
                   -SamAccountName $Username `
                   -UserPrincipalName "$Username@$DomainName" `
                   -AccountPassword $SecurePassword `
                   -Enabled $true `
                   -PasswordNeverExpires $true
        Write-Host "Created user: $Username"
    }
}

# Function to configure DCSync permissions for a user
function Configure-DCSyncAttack {
    Write-Host "Configuring DCSync attack vulnerability..."
    $WeakUser = Get-ADUser -Filter {Name -eq "VulnerableUser1"}
    Add-ADPermission -Identity "Domain Admins" `
                      -User $WeakUser.DistinguishedName `
                      -AccessRights "Replicating Directory Changes All"
    Write-Host "DCSync vulnerability configured for VulnerableUser1."
}

# Function to simulate Silver Ticket and Golden Ticket attacks
function Configure-TicketAttacks {
    Write-Host "Creating accounts for Silver and Golden Ticket simulations..."
    New-ADUser -Name "GoldenTicketUser" `
               -UserPrincipalName "goldenticket@$DomainName" `
               -AccountPassword (ConvertTo-SecureString "Golden123!" -AsPlainText -Force) `
               -Enabled $true
    New-ADUser -Name "SilverTicketUser" `
               -UserPrincipalName "silverticket@$DomainName" `
               -AccountPassword (ConvertTo-SecureString "Silver123!" -AsPlainText -Force) `
               -Enabled $true
    Write-Host "Accounts created for ticket attacks."
}

# Main function to execute all the configurations
function Main {
    Create-VulnerableUsers
    Configure-WeakACLs
    Create-KerberoastableAccounts
    Create-ASREPAccounts
    Configure-DnsAdmins
    Embed-PasswordsInDescriptions
    Disable-SmbSigning
    Configure-DCSyncAttack
    Configure-TicketAttacks
    Write-Host "Vulnerable Active Directory environment setup complete!"
}

# Execute the main function
Main
