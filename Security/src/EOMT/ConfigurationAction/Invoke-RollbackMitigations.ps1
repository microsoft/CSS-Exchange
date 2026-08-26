# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\IISManagement\Invoke-IISConfigurationManagerAction.ps1

<#
.DESCRIPTION
    Rolls back mitigations applied by EOMT by using the IIS management restore pipeline.
    When mitigations are applied, per-CVE JSON backup files are created at:
    %WINDIR%\System32\inetSrv\config\IISManagementRestoreCmdlets-<CVE-ID>.json

    The restore mechanism feeds an InputObject with a .Restore property to
    Invoke-IISConfigurationManagerAction, which calls Invoke-IISConfigurationRemoteAction.
    The remote action reads the JSON, executes each restore cmdlet, and renames the file to .bak.
#>
function Invoke-RollbackMitigations {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CVE,

        [Parameter()]
        [string]$ServerName = $env:COMPUTERNAME
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $rollbackAttempted = $false
        $success = $false
    }
    process {
        if ($PSCmdlet.ShouldProcess($ServerName, "Rollback mitigation for $CVE")) {
            $rollbackAttempted = $true

            $inputObject = [PSCustomObject]@{
                ServerName = $ServerName
                Restore    = @{
                    FileName     = $CVE
                    PassedWhatIf = $WhatIfPreference
                }
            }

            $managerResult = $inputObject | Invoke-IISConfigurationManagerAction -ConfigurationDescription "Rollback $CVE Mitigation"
            if ($managerResult.AllSucceeded) {
                $success = $true
            }
        }
    }
    end {
        return [PSCustomObject]@{
            RollbackAttempted = $rollbackAttempted
            CVE               = $CVE
            Success           = $success
        }
    }
}
