# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Invoke-CatchActionError.ps1

function Test-ADCredentials {
    [CmdletBinding()]
    [OutputType([System.Object])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credentials,

        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )

    <#
        This function tests whether the credentials provided are valid by trying to connect to LDAP server using Kerberos authentication.
        It returns a PSCustomObject with two properties:
        - UsernameFormat: "local", "upn" or "downlevel" depending on the format of the username provided
        - CredentialsValid: $true if the credentials are valid, $false if they are not valid, $null if the function was unable to perform the validation
    #>

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $credentialsValid = $null
        # Username formats: https://learn.microsoft.com/windows/win32/secauthn/user-name-formats
        $usernameFormat = "local"
        try {
            Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop
        } catch {
            Write-Verbose "Failed to load System.DirectoryServices.Protocols"
            Write-Verbose "Exception: $_"
            Invoke-CatchActionError $CatchActionFunction
        }
    }
    process {
        $domain = $Credentials.GetNetworkCredential().Domain
        if ([System.String]::IsNullOrEmpty($domain)) {
            Write-Verbose "Domain is empty which could be an indicator that UPN was passed instead of domain\username"
            $domain = ($Credentials.GetNetworkCredential().UserName).Split("@")
            if ($domain.Count -eq 2) {
                Write-Verbose "Domain was extracted from UPN"
                $domain = $domain[-1]
                $usernameFormat = "upn"
            } else {
                Write-Verbose "Failed to extract domain from UPN - seems that username was passed without domain and so cannot be validated"
                $domain = $null
            }
        } else {
            Write-Verbose "Username was provided in down-level logon name format"
            $usernameFormat = "downlevel"
        }

        if (-not([System.String]::IsNullOrEmpty($domain))) {
            $ldapDirectoryIdentifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($domain)
            # Use Kerberos authentication as NTLM might lead to false/positive results in case the password was changed recently
            $ldapConnection = New-Object -TypeName System.DirectoryServices.Protocols.LdapConnection($ldapDirectoryIdentifier, $Credentials, [DirectoryServices.Protocols.AuthType]::Kerberos)
            # Enable Kerberos encryption (sign and seal)
            $ldapConnection.SessionOptions.Signing = $true
            $ldapConnection.SessionOptions.Sealing = $true
            try {
                $ldapConnection.Bind()
                Write-Verbose "Connection succeeded with credentials"
                $credentialsValid = $true
            } catch [System.DirectoryServices.Protocols.LdapException] {
                if ($_.Exception.ErrorCode -eq 49) {
                    # ErrorCode 49 means invalid credentials
                    Write-Verbose "Failed to connect to LDAP server with credentials provided"
                    $credentialsValid = $false
                } else {
                    Write-Verbose "Failed to connect to LDAP server for other reason"
                    Write-Verbose "ErrorCode: $($_.Exception.ErrorCode)"
                }
                Write-Verbose "Exception: $_"
                Invoke-CatchActionError $CatchActionFunction
            } catch {
                Write-Verbose "Exception occurred while connecting to LDAP server - unable to perform credential validation"
                Write-Verbose "Exception: $_"
                Invoke-CatchActionError $CatchActionFunction
            }
        }
    }
    end {
        if ($null -ne $ldapConnection) {
            $ldapConnection.Dispose()
        }
        return [PSCustomObject]@{
            UsernameFormat   = $usernameFormat
            CredentialsValid = $credentialsValid
        }
    }
}
