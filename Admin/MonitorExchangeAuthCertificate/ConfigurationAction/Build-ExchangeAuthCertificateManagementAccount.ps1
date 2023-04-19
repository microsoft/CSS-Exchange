# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Add-ADUserToLocalGroup.ps1
. $PSScriptRoot\New-AuthCertificateManagementAccount.ps1
. $PSScriptRoot\..\..\..\Shared\Invoke-CatchActionError.ps1

function Build-ExchangeAuthCertificateManagementAccount {
    [CmdletBinding(DefaultParameterSetName = "CreateNewAccount", SupportsShouldProcess)]
    [OutputType([System.Object])]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ParameterSetName = "UseExistingAccount")]
        [bool]$UseExistingAccount = $false,
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ParameterSetName = "UseExistingAccount")]
        [PSCredential]$AccountCredentialObject,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = "CreateNewAccount")]
        [SecureString]$PasswordToSet,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = "CreateNewAccount")]
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = "UseExistingAccount")]
        [string]$DomainController,
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ParameterSetName = "CreateNewAccount")]
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ParameterSetName = "UseExistingAccount")]
        [ScriptBlock]$CatchActionFunction
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        $systemMailboxIdentity = "SM_ad0b1fe3a1a3"
        $domainToUse = (Get-Mailbox -Arbitration -ErrorAction SilentlyContinue | Where-Object {
            ($null -ne $_.UserPrincipalName)
            } | Select-Object -First 1).UserPrincipalName.Split("@")[-1]

        if (($UseExistingAccount) -and
            ($null -ne $AccountCredentialObject)) {
            Write-Verbose ("Account information passed - we will use account: $($AccountCredentialObject.UserName)")

            if ($AccountCredentialObject.UserName.IndexOf("\") -ne -1) {
                Write-Verbose ("Username passed in <Domain>\<SamAccountName> format")
                $systemMailboxIdentity = ($AccountCredentialObject.UserName).Split("\")[-1]
            } else {
                Write-Verbose ("Username passed in UPN or plain format")
                $systemMailboxIdentity = $AccountCredentialObject.UserName
            }

            $PasswordToSet = $AccountCredentialObject.Password
        }

        function NewAuthCertificateManagementRole {
            [CmdletBinding()]
            [OutputType([bool])]
            param(
                [string]$DomainController
            )

            Write-Verbose "Calling: $($MyInvocation.MyCommand)"

            try {
                Write-Verbose ("Trying to create 'Auth Certificate Management' role group by using Domain Controller: $($DomainController)")
                if ($PSCmdlet.ShouldProcess("View-Only Configuration, View-Only Recipients, Exchange Server Certificates, Organization Client Access", "New-RoleGroup")) {
                    $roleGroupParams = @{
                        Name             = "Auth Certificate Management"
                        Roles            = "View-Only Configuration", "View-Only Recipients" , "Exchange Server Certificates", "Organization Client Access"
                        Description      = "Members of this management group can create and manage Auth Certificates"
                        DomainController = $DomainController
                        ErrorAction      = "Stop"
                        WhatIf           = $WhatIfPreference
                    }
                    New-RoleGroup @roleGroupParams | Out-Null

                    Write-Verbose ("Validate that the role group was created successful")
                    $roleGroup = Get-RoleGroup -Identity "Auth Certificate Management" -DomainController $DomainController -ErrorAction SilentlyContinue

                    if ($null -ne $roleGroup) {
                        Write-Verbose ("Role group 'Auth Certificate Management' found by using Domain Controller: $($DomainController)")
                        return $true
                    } else {
                        throw ("Role group 'Auth Certificate Management' not found by using Domain Controller: $($DomainController)")
                    }
                } else {
                    return $true
                }
            } catch {
                Write-Verbose ("Unable to create 'Auth Certificate Management' role group - Exception: $($Error[0].Exception.Message)")
                Invoke-CatchActionError $CatchActionFunction
            }

            return $false
        }
    }
    process {
        if ($null -eq $domainToUse) {
            Write-Verbose ("Unable to figure out the domain used by the arbitration mailbox - we can't continue without this information")
            return
        }

        $authCertificateRoleGroup = Get-RoleGroup -Identity "Auth Certificate Management" -ErrorAction SilentlyContinue

        if ($null -eq $authCertificateRoleGroup) {
            Write-Verbose ("Role group for Auth Certificate management doesn't exist. Group 'Auth Certificate Management' will be created now")
            $newRoleGroupStatus = NewAuthCertificateManagementRole -DomainController $DomainController
        }

        if (($null -ne $authCertificateRoleGroup) -or
            ($newRoleGroupStatus)) {
            Write-Verbose ("Role group exists or was created successfully - searching for Auth Certificate management account")
            if ($UseExistingAccount -eq $false) {
                Write-Verbose ("System mailbox doesn't exist and will be created now")
                $newAuthCertificateManagementAccountParams = @{
                    Password         = $PasswordToSet
                    DomainToUse      = $domainToUse
                    DomainController = $DomainController
                    WhatIf           = $WhatIfPreference
                }

                if ($null -ne $CatchActionFunction) {
                    $newAuthCertificateManagementAccountParams.Add("CatchActionFunction", ${Function:Invoke-CatchActions})
                }

                $adUserExistsOrCreated = New-AuthCertificateManagementAccount @newAuthCertificateManagementAccountParams
                Write-Verbose ("Waiting 10 seconds for replication - please be patient")
                Start-Sleep -Seconds 10
            } else {
                Write-Verbose ("Trying to find the user which was passed to the function")
                $adUserExistsOrCreated = ((Get-User -Identity $systemMailboxIdentity -DomainController $DomainController -ErrorAction SilentlyContinue).Count -eq 1)
                Write-Verbose ("Does the account exists? $($adUserExistsOrCreated)")
            }
        } else {
            Write-Verbose ("Something went wrong while preparing the Auth Certificate management role group")
            return
        }

        if ($adUserExistsOrCreated) {
            Write-Verbose ("Auth Certificate management AD account is now ready to use - going to email enable it now")
            $systemMailboxRecipientInfo = Get-Recipient -Identity $systemMailboxIdentity -ErrorAction SilentlyContinue

            if ($null -eq $systemMailboxRecipientInfo) {
                Write-Verbose ("Recipient has not yet been email enabled")
                try {
                    if ($PSCmdlet.ShouldProcess($systemMailboxIdentity, "Enable-Mailbox")) {
                        Enable-Mailbox -Identity $systemMailboxIdentity -DomainController $DomainController -ErrorAction Stop | Out-Null
                        Write-Verbose ("Wait another 5 seconds and give Exchange time to process")
                        Start-Sleep -Seconds 5
                    }
                } catch {
                    Write-Verbose ("Something went wrong while email activating the Auth Certificate management account")
                    Invoke-CatchActionError $CatchActionFunction
                    return
                }
            }
        } else {
            Write-Verbose ("Something went wrong while preparing the Auth Certificate management account")
            return
        }

        $systemMailboxMailboxInfo = Get-Mailbox -Identity $systemMailboxIdentity -DomainController $DomainController -ErrorAction SilentlyContinue

        if (($WhatIfPreference) -and
            ($null -eq $systemMailboxMailboxInfo)) {
            $systemMailboxMailboxInfo = @{
                HiddenFromAddressListsEnabled = $false
            }
        }

        if ($null -ne $systemMailboxMailboxInfo) {
            Write-Verbose ("Auth Certificate management mailbox found")
            if ($systemMailboxMailboxInfo.HiddenFromAddressListsEnabled -eq $false) {
                Write-Verbose ("Auth Certificate management mailbox is not hidden from AddressList - going to hide the mailbox now")
                try {
                    if ($PSCmdlet.ShouldProcess($systemMailboxIdentity, "Set-Mailbox")) {
                        Set-Mailbox -Identity $systemMailboxIdentity -HiddenFromAddressListsEnabled $true -ErrorAction Stop | Out-Null
                    }
                } catch {
                    Write-Verbose ("Unable to hide Auth Certificate management account from AddressList")
                    Invoke-CatchActionError $CatchActionFunction
                    return
                }
            }
        } else {
            Write-Verbose ("Unable to email enable the Auth Certificate management account")
            return
        }

        $roleGroupMembership = Get-RoleGroupMember "Auth Certificate Management" -ErrorAction SilentlyContinue
        $systemMailboxUserInfo = Get-User -Identity $systemMailboxIdentity -DomainController $DomainController -ErrorAction SilentlyContinue

        if (($WhatIfPreference) -and
            ($null -eq $systemMailboxUserInfo)) {
            $systemMailboxUserInfo = @{
                SamAccountName    = $systemMailboxIdentity
                UserPrincipalName = $systemMailboxIdentity
            }
        }

        if (($null -eq $roleGroupMembership) -or
            (-not($roleGroupMembership.DistinguishedName.ToLower().Contains($systemMailboxUserInfo.DistinguishedName.ToLower())))) {
            Write-Verbose ("Add Auth Certificate management account to 'Auth Certificate Management' role group")
            try {
                if ($PSCmdlet.ShouldProcess($systemMailboxIdentity, "Add-RoleGroupMember")) {
                    Add-RoleGroupMember "Auth Certificate Management" -Member $systemMailboxIdentity -ErrorAction Stop | Out-Null
                    Write-Verbose ("Auth Certificate management account added to 'Auth Certificate Management' role group")
                }
            } catch {
                Write-Verbose ("Unable to add Auth Certificate management account to role group")
                Invoke-CatchActionError $CatchActionFunction
                return
            }
        } else {
            Write-Verbose ("Account: $($systemMailboxIdentity) is already a member of the 'Auth Certificate Management' role group")
        }

        if ($null -ne $systemMailboxUserInfo) {
            Write-Verbose ("Account: $($systemMailboxIdentity) must be added to the local administrators group")
            if (Add-ADUserToLocalGroup -MemberUPN $systemMailboxUserInfo.UserPrincipalName -Group "S-1-5-32-544" -WhatIf:$WhatIfPreference) {
                Write-Verbose ("Account successfully added to local administrators group")
            } else {
                Write-Verbose ("Error while adding the user to the local administrators group - Exception: $($Error[0].Exception.Message)")
                return
            }
        } else {
            Write-Verbose ("Something went wrong as we can no longer find the Auth Certificate management account")
            return
        }
    }
    end {
        return [PSCustomObject]@{
            UserPrincipalName = $systemMailboxUserInfo.UserPrincipalName
            SamAccountName    = $systemMailboxUserInfo.SamAccountName
            Password          = $PasswordToSet
        }
    }
}
