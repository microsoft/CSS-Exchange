Function Get-LmCompatibilityLevelInformation {

    Write-VerboseOutput("Calling: Get-LmCompatibilityLevelInformation")

    [HealthChecker.LmCompatibilityLevelInformation]$ServerLmCompatObject = New-Object -TypeName HealthChecker.LmCompatibilityLevelInformation
    $ServerLmCompatObject.RegistryValue = Invoke-RegistryGetValue -RegistryHive "LocalMachine" -MachineName $Script:Server -SubKey "SYSTEM\CurrentControlSet\Control\Lsa" -GetValue "LmCompatibilityLevel" -CatchActionFunction ${Function:Invoke-CatchActions} -DefaultValue 3
    Switch ($ServerLmCompatObject.RegistryValue) {
        0 { $ServerLmCompatObject.Description = "Clients use LM and NTLM authentication, but they never use NTLMv2 session security. Domain controllers accept LM, NTLM, and NTLMv2 authentication." }
        1 { $ServerLmCompatObject.Description = "Clients use LM and NTLM authentication, and they use NTLMv2 session security if the server supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication." }
        2 { $ServerLmCompatObject.Description = "Clients use only NTLM authentication, and they use NTLMv2 session security if the server supports it. Domain controller accepts LM, NTLM, and NTLMv2 authentication." }
        3 { $ServerLmCompatObject.Description = "Clients use only NTLMv2 authentication, and they use NTLMv2 session security if the server supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication." }
        4 { $ServerLmCompatObject.Description = "Clients use only NTLMv2 authentication, and they use NTLMv2 session security if the server supports it. Domain controller refuses LM authentication responses, but it accepts NTLM and NTLMv2." }
        5 { $ServerLmCompatObject.Description = "Clients use only NTLMv2 authentication, and they use NTLMv2 session security if the server supports it. Domain controller refuses LM and NTLM authentication responses, but it accepts NTLMv2." }
    }

    Write-VerboseOutput("Exiting: Get-LmCompatibilityLevelInformation")
    Return $ServerLmCompatObject
}