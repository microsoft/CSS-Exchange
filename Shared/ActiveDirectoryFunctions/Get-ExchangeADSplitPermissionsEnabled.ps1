# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Invoke-CatchActionError.ps1

function Get-ExchangeADSplitPermissionsEnabled {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [ScriptBlock]$CatchActionFunction
    )

    <#
        The following bullets are AD split permissions indicators:
        - An organizational unit (OU) named Microsoft 'Exchange Protected Groups' is created
        - The 'Exchange Windows Permissions' security group is created/moved in/to the 'Microsoft Exchange Protected Groups' OU
        - The 'Exchange Trusted Subsystem' security group isn't member of the 'Exchange Windows Permissions' security group
        - ACEs that would have been assigned to the 'Exchange Windows Permissions' security group aren't added to the Active Directory domain object
        See: https://learn.microsoft.com/exchange/permissions/split-permissions/split-permissions?view=exchserver-2019#active-directory-split-permissions
    #>

    $isADSplitPermissionsEnabled = $false
    try {
        $rootDSE = [ADSI]("LDAP://$([System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name)/RootDSE")
        $exchangeTrustedSubsystemDN = ("CN=Exchange Trusted Subsystem,OU=Microsoft Exchange Security Groups," + $rootDSE.rootDomainNamingContext)
        $adSearcher = New-Object DirectoryServices.DirectorySearcher
        $adSearcher.Filter = '(&(objectCategory=group)(cn=Exchange Windows Permissions))'
        $adSearcher.SearchRoot = ("LDAP://OU=Microsoft Exchange Protected Groups," + $rootDSE.rootDomainNamingContext)
        $adSearcherResult = $adSearcher.FindOne()

        if ($null -ne $adSearcherResult) {
            Write-Verbose "'Exchange Windows Permissions' in 'Microsoft Exchange Protected Groups' OU detected"
            # AD split permissions is enabled if 'Exchange Trusted Subsystem' isn't a member of the 'Exchange Windows Permissions' security group
            $isADSplitPermissionsEnabled = (($null -eq $adSearcherResult.Properties.member) -or
            (-not($adSearcherResult.Properties.member).ToLower().Contains($exchangeTrustedSubsystemDN.ToLower())))
        }
    } catch {
        Write-Verbose "OU 'Microsoft Exchange Protected Groups' was not found - AD split permissions not enabled"
        Invoke-CatchActionError $CatchActionFunction
    }

    return $isADSplitPermissionsEnabled
}
