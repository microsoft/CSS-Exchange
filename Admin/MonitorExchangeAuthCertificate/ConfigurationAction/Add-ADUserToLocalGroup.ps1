# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\Shared\Invoke-CatchActionError.ps1

function Add-ADUserToLocalGroup {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([bool])]
    param(
        [string]$MemberUPN,
        [string]$Group,
        [ScriptBlock]$CatchActionFunction
    )

    <#
        This function adds an Active Directory user to a local group.
    #>

    try {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        Add-Type -AssemblyName "System.DirectoryServices.AccountManagement" -ErrorAction Stop

        $localContext = [System.DirectoryServices.AccountManagement.ContextType]::Machine
        $domainContext = [System.DirectoryServices.AccountManagement.ContextType]::Domain
        $localMachine = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext($localContext)
        $localGroup = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($localMachine, $Group)

        if (-not($localGroup.Members.Contains($domainContext, [System.DirectoryServices.AccountManagement.IdentityType]::UserPrincipalName, $MemberUPN))) {
            if ($PSCmdlet.ShouldProcess($Group, "Add user $($MemberUPN) to local group")) {
                $localGroup.Members.Add($domainContext, [System.DirectoryServices.AccountManagement.IdentityType]::UserPrincipalName, $MemberUPN)
                $localGroup.Save()
            }
        } else {
            Write-Verbose ("User: $($MemberUPN) is already a member of group: $($Group)")
        }
    } catch [System.DirectoryServices.AccountManagement.PrincipalOperationException] {
        throw ("There are users in the local administrators group which cannot be resolved - please remove them and run the script again")
        Invoke-CatchActionError $CatchActionFunction
        return
    } catch {
        Write-Verbose ("Exception: $($Error[0].Exception.Message)")
        Invoke-CatchActionError $CatchActionFunction
        return
    } finally {
        if ($null -ne $localGroup) {
            $localGroup.Dispose()
        }
    }

    return $true
}
