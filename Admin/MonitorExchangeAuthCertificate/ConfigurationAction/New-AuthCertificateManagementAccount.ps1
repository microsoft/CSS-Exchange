# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\Shared\Invoke-CatchActionError.ps1

function New-AuthCertificateManagementAccount {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [SecureString]$Password,
        [string]$DomainToUse = $env:USERDNSDOMAIN,
        [string]$DomainController = $env:USERDNSDOMAIN,
        [ScriptBlock]$CatchActionFunction
    )

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    $systemMailboxGuid = "b963af59-3975-4f92-9d58-ad0b1fe3a1a3"
    $samAccountName = "SM_ad0b1fe3a1a3"
    $userPrincipalName = "SystemMailbox{$($systemMailboxGuid)}@$($DomainToUse)"

    Write-Verbose ("Domain passed to the function is: $($DomainToUse)")
    Write-Verbose ("Domain or Domain Controller to be used with 'New-ADUser' call is: $($DomainController)")
    try {
        $adAccount = Get-ADUser -Identity $samAccountName -Server $DomainController -ErrorAction Stop
    } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Write-Verbose ("AD user account wasn't found using Domain Controller: $($DomainController)")
        Invoke-CatchActionError $CatchActionFunction
    } catch {
        Write-Verbose ("We hit an unhandled exception and cannot continue - Exception: $($Error[0].Exception.Message)")
        Invoke-CatchActionError $CatchActionFunction
        return $false
    }

    if ($null -eq $adAccount) {
        try {
            $newADUserParams = @{
                Name                 = "SystemMailbox{$($systemMailboxGuid)}"
                DisplayName          = "Microsoft Exchange Auth Certificate Manager"
                SamAccountName       = $samAccountName
                UserPrincipalName    = $userPrincipalName
                AccountPassword      = $Password
                Enabled              = $true
                PasswordNeverExpires = $true
                Server               = $DomainController
                ErrorAction          = "Stop"
            }

            if ($PSCmdlet.ShouldProcess($samAccountName, "New-ADUser")) {
                New-ADUser @newADUserParams | Out-Null
            }
            Write-Verbose ("User: 'Microsoft Exchange Auth Certificate Manager' was successfully created")
            return $true
        } catch [System.UnauthorizedAccessException] {
            Write-Verbose ("You don't have the permissions to create a new AD user account")
            Invoke-CatchActionError $CatchActionFunction
        } catch {
            Write-Verbose ("Something went wrong while creating the 'Microsoft Exchange Auth Certificate Manager' account - Exception: $($Error[0].Exception.Message)")
            Invoke-CatchActionError $CatchActionFunction
        }
    } else {
        Write-Verbose ("The AD account: $($userPrincipalName) already exists")
        Write-Verbose ("Trying to reset the password for the account")
        try {
            if ($PSCmdlet.ShouldProcess($adAccount, "Set-ADAccountPassword")) {
                Set-ADAccountPassword -Identity $adAccount -NewPassword $Password -Reset -Server $DomainController -Confirm:$false -ErrorAction Stop
            }
            if ($PSCmdlet.ShouldProcess($adAccount, "Set-ADUser")) {
                Set-ADUser -Identity $adAccount -ChangePasswordAtLogon $false -Server $DomainController -Confirm:$false -ErrorAction Stop
            }
            return $true
        } catch [System.UnauthorizedAccessException] {
            Write-Verbose ("You don't have the permissions to reset the password of an AD account")
            Invoke-CatchActionError $CatchActionFunction
        } catch {
            Write-Verbose ("Unable to reset the password for the already existing AD user account - Exception: $($Error[0].Exception.Message)")
            Invoke-CatchActionError $CatchActionFunction
        }
    }

    return $false
}
