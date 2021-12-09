# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Get-RemoteRegistrySubKey.ps1

Function Get-RemoteRegistryValue {
    [CmdletBinding()]
    param(
        [string]$RegistryHive = "LocalMachine",
        [string]$MachineName,
        [string]$SubKey,
        [string]$GetValue,
        [string]$ValueType,
        [scriptblock]$CatchActionFunction
    )

    <#
    Valid ValueType return values (case-sensitive)
    (https://docs.microsoft.com/en-us/dotnet/api/microsoft.win32.registryvaluekind?view=net-5.0)
    Binary = REG_BINARY
    DWord = REG_DWORD
    ExpandString = REG_EXPAND_SZ
    MultiString = REG_MULTI_SZ
    None = No data type
    QWord = REG_QWORD
    String = REG_SZ
    Unknown = An unsupported registry data type
    #>

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $registryGetValue = $null
    }
    process {

        try {

            $regSubKey = Get-RemoteRegistrySubKey -RegistryHive $RegistryHive `
                -MachineName $MachineName `
                -SubKey $SubKey

            if (-not ([System.String]::IsNullOrWhiteSpace($regSubKey))) {
                Write-Verbose "Attempting to get the value $GetValue"
                $registryGetValue = $regSubKey.GetValue($GetValue)
                Write-Verbose "Finished running GetValue()"

                if ($null -ne $registryGetValue -and
                    (-not ([System.String]::IsNullOrWhiteSpace($ValueType)))) {
                    Write-Verbose "Validating ValueType $ValueType"
                    $registryValueType = $regSubKey.GetValueKind($GetValue)
                    Write-Verbose "Finished running GetValueKind()"

                    if ($ValueType -ne $registryValueType) {
                        Write-Verbose "ValueType: $ValueType is different to the returned ValueType: $registryValueType"
                        $registryGetValue = $null
                    } else {
                        Write-Verbose "ValueType matches: $ValueType"
                    }
                }
            }
        } catch {
            Write-Verbose "Failed to get the value on the registry"

            if ($null -ne $CatchActionFunction) {
                & $CatchActionFunction
            }
        }
    }
    end {
        Write-Verbose "Get-RemoteRegistryValue Return Value: '$registryGetValue'"
        return $registryGetValue
    }
}
