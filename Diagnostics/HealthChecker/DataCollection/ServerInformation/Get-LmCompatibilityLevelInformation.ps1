# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\..\Shared\Get-RemoteRegistryValue.ps1
Function Get-LmCompatibilityLevelInformation {

    Write-Verbose "Calling: $($MyInvocation.MyCommand)"

    [HealthChecker.LmCompatibilityLevelInformation]$ServerLmCompatObject = New-Object -TypeName HealthChecker.LmCompatibilityLevelInformation
    $registryValue = Get-RemoteRegistryValue -RegistryHive "LocalMachine" `
        -MachineName $Script:Server `
        -SubKey "SYSTEM\CurrentControlSet\Control\Lsa" `
        -GetValue "LmCompatibilityLevel" `
        -ValueType "DWord" `
        -CatchActionFunction ${Function:Invoke-CatchActions}

    if ($null -eq $registryValue) {
        $registryValue = 3
    }

    $ServerLmCompatObject.RegistryValue = $registryValue
    Write-Verbose "LmCompatibilityLevel Registry Value: $registryValue"

    Switch ($ServerLmCompatObject.RegistryValue) {
        0 { $ServerLmCompatObject.Description = "Clients use LM and NTLM authentication, but they never use NTLMv2 session security. Domain controllers accept LM, NTLM, and NTLMv2 authentication." }
        1 { $ServerLmCompatObject.Description = "Clients use LM and NTLM authentication, and they use NTLMv2 session security if the server supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication." }
        2 { $ServerLmCompatObject.Description = "Clients use only NTLM authentication, and they use NTLMv2 session security if the server supports it. Domain controller accepts LM, NTLM, and NTLMv2 authentication." }
        3 { $ServerLmCompatObject.Description = "Clients use only NTLMv2 authentication, and they use NTLMv2 session security if the server supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication." }
        4 { $ServerLmCompatObject.Description = "Clients use only NTLMv2 authentication, and they use NTLMv2 session security if the server supports it. Domain controller refuses LM authentication responses, but it accepts NTLM and NTLMv2." }
        5 { $ServerLmCompatObject.Description = "Clients use only NTLMv2 authentication, and they use NTLMv2 session security if the server supports it. Domain controller refuses LM and NTLM authentication responses, but it accepts NTLMv2." }
    }

    Write-Verbose "Exiting: $($MyInvocation.MyCommand)"
    Return $ServerLmCompatObject
}
