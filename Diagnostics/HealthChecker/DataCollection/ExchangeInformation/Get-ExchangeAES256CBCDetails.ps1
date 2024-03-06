# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\CompareExchangeBuildLevel.ps1
. $PSScriptRoot\..\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1
. $PSScriptRoot\..\..\..\..\Shared\ErrorMonitorFunctions.ps1
function Get-ExchangeAES256CBCDetails {
    param(
        [Parameter(Mandatory = $false)]
        [String]$Server = $env:COMPUTERNAME,

        [Parameter(Mandatory = $true)]
        [System.Object]$VersionInformation
    )

    <#
        AES256-CBC encryption support check
        https://techcommunity.microsoft.com/t5/security-compliance-and-identity/encryption-algorithm-changes-in-microsoft-purview-information/ba-p/3831909
    #>

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"

        function GetRegistryAclCheckScriptBlock {
            $sbMsipcRegistryAclAsExpected = $false
            $regPathToCheck = "HKLM:\SOFTWARE\Microsoft\MSIPC\Server"
            # Translates to: "NetworkService", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow"
            # See: https://learn.microsoft.com/dotnet/api/system.security.accesscontrol.registryaccessrule.-ctor?view=net-7.0#system-security-accesscontrol-registryaccessrule-ctor(system-security-principal-identityreference-system-security-accesscontrol-registryrights-system-security-accesscontrol-inheritanceflags-system-security-accesscontrol-propagationflags-system-security-accesscontrol-accesscontroltype)
            $networkServiceAcl = New-Object System.Security.AccessControl.RegistryAccessRule(
                (New-Object System.Security.Principal.SecurityIdentifier("S-1-5-20")), 983103, 3, 0, 0
            )
            $pathExists = Test-Path $regPathToCheck

            if ($pathExists -eq $false) {
                Write-Verbose "Unable to query Acl of registry key $regPathToCheck assuming that the key doesn't exist"
            } else {
                $acl = Get-Acl -Path $regPathToCheck
                # ToDo: As we have multiple places in HC where we query acls, we should consider creating a function
                # that can be used to do the acl call, similar to what we do in Get-ExchangeRegistryValues.ps1.
                Write-Verbose "Registry key exists and Acl was successfully queried - validating Acl now"
                try {
                    $aclMatch = $acl.Access.Where({
                    ($_.RegistryRights -eq $networkServiceAcl.RegistryRights) -and
                    ($_.AccessControlType -eq $networkServiceAcl.AccessControlType) -and
                    ($_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -eq $networkServiceAcl.IdentityReference) -and
                    ($_.InheritanceFlags -eq $networkServiceAcl.InheritanceFlags) -and
                    ($_.PropagationFlags -eq $networkServiceAcl.PropagationFlags)
                        })

                    if (@($aclMatch).Count -ge 1) {
                        Write-Verbose "Acl for NetworkService is as expected"
                        $sbMsipcRegistryAclAsExpected = $true
                    } else {
                        Write-Verbose "Acl for NetworkService was not found or is not as expected"
                    }
                } catch {
                    Write-Verbose "Unable to verify Acl on registry key $regPathToCheck"
                    # Unable to use Invoke-CatchActions because of remote script block
                }
            }

            return [PSCustomObject]@{
                PathExits                       = $pathExists
                RegistryKeyConfiguredAsExpected = $sbMsipcRegistryAclAsExpected
            }
        }

        $aes256CBCSupported = $false
        $msipcRegistryAclAsExpected = $false
    } process {
        # First, check if the build running on the server supports AES256-CBC
        if (Test-ExchangeBuildGreaterOrEqualThanSecurityPatch -CurrentExchangeBuild $VersionInformation -SU "Aug23SU") {

            Write-Verbose "AES256-CBC encryption for information protection is supported by this Exchange Server build"
            $aes256CBCSupported = $true

            $params = @{
                ComputerName        = $Server
                ScriptBlock         = ${Function:GetRegistryAclCheckScriptBlock}
                CatchActionFunction = ${Function:Invoke-CatchActions}
            }
            $results = Invoke-ScriptBlockHandler @params
            Write-Verbose "Found Registry Path: $($results.PathExits)"
            Write-Verbose "Configured Correctly: $($results.RegistryKeyConfiguredAsExpected)"
            $msipcRegistryAclAsExpected = $results.RegistryKeyConfiguredAsExpected
        } else {
            Write-Verbose "AES256-CBC encryption for information protection is not supported by this Exchange Server build"
        }
    } end {
        return [PSCustomObject]@{
            AES256CBCSupportedBuild         = $aes256CBCSupported
            RegistryKeyConfiguredAsExpected = $msipcRegistryAclAsExpected
            ValidAESConfiguration           = (($aes256CBCSupported) -and ($msipcRegistryAclAsExpected))
        }
    }
}
