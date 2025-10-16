# Credential Guard Check

**Description:**

In this check we validate, weather `Credential Guard` was activated or not. `Credential Guard` is not supported on an Exchange Server. This can cause a performance hit on the server.

This check is checking both the CimInstance to see if the service is running or if the registry key is set.

Registry: `SYSTEM\CurrentControlSet\Control\LSA\LsaCfgFlags`

CimInstance: `(Get-CimInstance -ClassName "Win32_DeviceGuard" -Namespace "root\Microsoft\Windows\DeviceGuard").SecurityServicesRunning`

!!! warning "NOTE"

      By default with Windows Server 2025 this feature is enabled by default. However, at this time this is still not supported to run with Exchange Server.

**Included in HTML Report?**

Yes

**Additional resources:**

[Manage Windows Defender Credential Guard](https://docs.microsoft.com/windows/security/identity-protection/credential-guard/credential-guard-manage)

