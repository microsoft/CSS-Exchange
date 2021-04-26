Function Get-RemoteRegistryValue {
    [CmdletBinding()]
    param(
        [string]$RegistryHive = "LocalMachine",
        [string]$MachineName,
        [string]$SubKey,
        [string]$GetValue,
        [scriptblock]$CatchActionFunction
    )
    begin {
        Write-Verbose "Calling: Get-RemoteRegistryValue"
        $registryGetValue = $null
    }
    process {
        $regSubKey = Get-RemoteRegistrySubKey -RegistryHive $RegistryHive `
            -MachineName $MachineName `
            -SubKey $SubKey

        try {

            if ($null -ne $regSubKey) {
                Write-Verbose "Attempting to get the value $GetValue"
                $registryGetValue = $regSubKey.GetValue($GetValue)
                Write-Verbose "Finished running GetValue()"
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
