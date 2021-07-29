# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Get-RemoteRegistryValue.ps1
Function Get-CredentialGuardEnabled {

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    $registryValue = Get-RemoteRegistryValue -MachineName $Script:Server `
        -SubKey "SYSTEM\CurrentControlSet\Control\LSA" `
        -GetValue "LsaCfgFlags" `
        -CatchActionFunction ${Function:Invoke-CatchActions}

    if ($null -ne $registryValue -and
        $registryValue -ne 0) {
        return $true
    }

    return $false
}
