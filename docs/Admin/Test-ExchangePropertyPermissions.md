# Test-ExchangePropertyPermissions

Download the latest release: [Test-ExchangePropertyPermissions.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Test-ExchangePropertyPermissions.ps1)

## Syntax

```powershell
Test-ExchangePropertyPermissions.ps1
    [-TargetObjectDN] <string>
    [-ComputerAccountDN] <string>
    [[-DomainController] <string>]
    [-OutputDebugInfo]
    [<CommonParameters>]
```

## Example

.\Test-ExchangePropertyPermissions.ps1 -TargetObjectDN "CN=SomeRecipient,OU=Users,DC=contoso,DC=com" -ComputerAccountDN "CN=SomeServerName,OU=Computers,DC=contoso,DC=com"

This example retrieves the group memberships of the SomeServerName computer account and then examines the ACL of SomeRecipient
to determine if that computer account can write to all expected attributes of that recipient.

## Description

Test-ExchangePropertyPermissions is designed to detect certain schema issues which can manifest as
permissions problems and can be challenging to identify manually, including:

* Scenarios where a property set does not include all the expected properties.
* Scenarios where an objectClass definition is missing expected properties.

Note that the script does not perform an exhaustive check for all possible schema issues. It is
only designed to identify a specific subset of issues which we have encountered. For example, using
AD Schema Analyzer as described here is one such scenario:

https://learn.microsoft.com/en-us/previous-versions/technet-magazine/dd547839(v=msdn.10)

As noted in that article, this is known to corrupt the Exchange attributes. This script is able
to detect that scenario, and other similar scenarios.

Further, note that such issues cannot be fixed by the script. Using AD Schema Analyzer as described
results in an unsupported forest that should be torn down.
