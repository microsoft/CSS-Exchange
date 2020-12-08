Function Get-CredentialGuardEnabled {

    Write-VerboseOutput("Calling: Get-CredentialGuardEnabled")

    $registryValue = Invoke-RegistryGetValue -MachineName $Script:Server -SubKey "SYSTEM\CurrentControlSet\Control\LSA" -GetValue "LsaCfgFlags" -CatchActionFunction ${Function:Invoke-CatchActions}

    if ($registryValue -ne $null -and
        $registryValue -ne 0)
    {
        return $true
    }

    return $false
}