# Setting Overrides

## Description

Setting Overrides can be configured via `New-SettingOverride` cmdlet and in certain cases with the help of registry values.
They can be created to change default values for common Exchange services and features (e.g., the [default run cycle of the Managed Folder Assistant](https://learn.microsoft.com/exchange/policy-and-compliance/mrm/configure-managed-folder-assistant?view=exchserver-2019#step-1-use-the-exchange-management-shell-to-configure-the-work-cycle-for-the-managed-folder-assistant)).

Sometimes they are used to enable new features like the recently introduced [Serialized Data Signing for PowerShell payload](SerializedDataSigningCheck.md).

In very rare cases, Microsoft recommends to disable a feature or component by the help of an override (e.g., [EWS web application pool stops after the February 2023 Security Update is installed](https://support.microsoft.com/topic/ews-web-application-pool-stops-after-the-february-2023-security-update-is-installed-f7ead47c-2303-4132-963e-b66548017340)) to work around known issues.

HealthChecker checks for known overrides which should be removed as a solution for to a particular problem is available.

!!! warning "Important"

    Incorrect usage of the setting override cmdlets can cause serious damage to your Exchange organization. This damage could require you to reinstall Exchange. Only use these cmdlets as instructed by product documentation or under the direction of Microsoft Customer Service and Support.

## Setting Overrides

Feature | Exchange Version(s) | Controlled via | Recommended setting
--------|---------------------|----------------|--------------------
BaseTypeCheckForDeserialization | 2013, 2016, 2019 | Registry Value | Disabled

**Enable:**
```powershell
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Diagnostics -Name "DisableBaseTypeCheckForDeserialization" -Value 1 -Type String
```

**Disable:**
```powershell
Remove-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Diagnostics -Name "DisableBaseTypeCheckForDeserialization"
```

Feature | Exchange Version(s) | Controlled via | Recommended setting
--------|---------------------|----------------|--------------------
Strict Mode for ClientExtensionCollectionFormatter | 2016, 2019 | New-SettingOverride | Enabled

**Enable:**
```powershell
Get-SettingOverride | Where-Object {$_.ComponentName -eq "Data" -and $_.SectionName -eq "DeserializationBinderSettings" -and $_.Parameters -eq "LearningLocations=ClientExtensionCollectionFormatter"} | Remove-SettingOverride
```

**Disable:**
```powershell
New-SettingOverride -Name "Adding learning location ClientExtensionCollectionFormatter" -Component Data -Section DeserializationBinderSettings -Parameters @("LearningLocations=ClientExtensionCollectionFormatter") -Reason "Deserialization failed"
```

## Included in HTML Report?

Yes

## Additional resources

[New-SettingOverride](https://learn.microsoft.com/powershell/module/exchange/new-settingoverride?view=exchange-ps)

[Remove-SettingOverride](https://learn.microsoft.com/powershell/module/exchange/remove-settingoverride?view=exchange-ps)
