# PowerShell Serialization Payload Signing

## Description

Certificate-based signing of PowerShell Serialization Payload is a Defense-in-Depth security feature to prevent malicious manipulation of serialized data exchanged in Exchange Management Shell (EMS) sessions.

The Serialized Data Signing feature was introduced with the January 2023 Exchange Server Security Update (SU). It's available on Exchange Server 2013, Exchange Server 2016 and Exchange Server 2019.

In the first stage of rollout, this feature needs to be manually enabled by the Exchange Server administrator. This can be done by following the steps outlined below.

The HealthChecker check validates that the feature is enabled on supported Exchange builds. It will also check if multiple `SettingOverrides` are available that collide with each other.

### Important

!!! warning "If you have an Exchange Server 2013 in your environment"

    Turning on the signing of serialization payload feature might lead to several issues impacting management in your organization. We recommend not to turn on this feature for now. We will address this in the future update. Customers with Exchange Server 2016 / 2019 only can proceed with using the certificate signing of PowerShell serialization payload feature.

Ensure all the Exchange Servers (Exchange Server 2019, 2016 and 2013) in the environment are running the January 2023 (or later) SU before turning the feature on. Enabling the feature before all servers are updated might lead to failures and errors when managing your organization.

This features uses the `Exchange Server Auth Certificate` to sign the serialized data. Therefore, it's very important that the certificate which is configured as Auth Certificate is valid (not expired) and available on all Exchange Servers (except Edge Transport role and Exchange Management Tools role) within the organization.

### Exchange Server 2013
The feature must be enabled on a per-server base by creating the following `registry value`:

Key: `HKLM\SOFTWARE\Microsoft\ExchangeServer\v15\Diagnostics\`

ValueType: `String`

Value: `EnableSerializationDataSigning`

Data: `1`

You can create the required string value by running the following PowerShell command:

`New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Diagnostics -Name "EnableSerializationDataSigning" -Value 1 -Type String`

### Exchange Server 2016/2019
The feature can be enabled on an organizational level (strongly recommended) or per-server base via `SettingOverride`:

Organizational-wide: `New-SettingOverride -Name "EnableSigningVerification" -Component Data -Section EnableSerializationDataSigning -Parameters @("Enabled=true") -Reason "Enabling Signing Verification"`

Per-server base: `New-SettingOverride -Name "EnableSigningVerification" -Component Data -Section EnableSerializationDataSigning -Parameters @("Enabled=true") -Reason "Enabling Signing Verification" -Server <ExchangeServerName>`

Next, refresh the VariantConfiguration argument by running the following cmdlet:
`Get-ExchangeDiagnosticInfo -Process Microsoft.Exchange.Directory.TopologyService -Component VariantConfiguration -Argument Refresh`

### Required on Exchange 2013, 2016 and 2019 after the feature was enabled (via Registry Value or VariantConfiguration)
Restart the `World Wide Web Publishing service` and the `Windows Process Activation Service (WAS)` to apply the new settings. To do this, run the following cmdlet:
`Restart-Service -Name W3SVC, WAS -Force`

**NOTE:**

Exchange 2016/2019: It's sufficient to restart the services on the server where the change was made.

Exchange 2013: It's required to restart these services on all Exchange 2013 servers whenever the registry value is updated.

## Included in HTML Report?

Yes

## Additional resources

[Released: January 2023 Exchange Server Security Updates](https://techcommunity.microsoft.com/t5/exchange-team-blog/released-january-2023-exchange-server-security-updates/ba-p/3711808)

[Certificate signing of PowerShell serialization payload in Exchange Server](https://support.microsoft.com/kb/5022988)

[MonitorExchangeAuthCertificate.ps1 script](https://aka.ms/MonitorExchangeAuthCertificate)
