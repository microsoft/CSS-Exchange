# Sync-ModernMailPublicFolders

Download the latest release: [Sync-ModernMailPublicFolders.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Sync-ModernMailPublicFolders.ps1)

## Syntax

```powershell
Sync-ModernMailPublicFolders.ps1
  -CsvSummaryFile <String>
  [-Credential <PSCredential>]
  [-ConnectionUri <String>]
  [-AzureADAuthorizationEndpointUri <String>]
  [-Confirm <Boolean>]
  [-FixInconsistencies]
  [-Force]
  [-WhatIf]
  [-SkipVersionCheck]
  [<CommonParameters>]

Sync-ModernMailPublicFolders.ps1
  -ScriptUpdateOnly
  [-SkipVersionCheck]
  [<CommonParameters>]
```

## Parameters

- `-CsvSummaryFile` (required for synchronization): Path for the operation summary CSV. The directory must exist and be writable. Existing files are preserved; see [Summary output](#summary-output).
- `-Credential` (optional): Exchange Online credentials. Omit this parameter when using MFA.
- `-ConnectionUri` (optional): Exchange Online connection endpoint. Defaults to `https://outlook.office365.com/powerShell-liveID`.
- `-AzureADAuthorizationEndpointUri` (optional): Authorization endpoint passed to `Connect-ExchangeOnline`. When omitted, the Exchange Online module uses its default. For a different cloud, supply the appropriate connection and authorization endpoints together.
- `-Confirm` (optional): Whether to prompt before applying synchronization changes. Defaults to `$true`.
- `-FixInconsistencies` (optional): Fix inconsistencies identified by the mail-enabled public-folder validation script.
- `-Force` (optional): Bypass the empty-source warning. An empty source can cause all Exchange Online mail-enabled public folders to be removed; use with care.
- `-WhatIf` (optional): Simulate synchronization create, update, and delete commands. Summary files are still written. This does not make `-FixInconsistencies` a simulation; do not combine the two for a read-only run.
- `-ScriptUpdateOnly` (optional): Only updates the script to the latest released version without performing any other actions.
- `-SkipVersionCheck` (optional): Skips the automatic version check and script update.

## Usage

For usage details, please see [Batch migrate Exchange Server public folders to Microsoft 365 or Office 365 | Microsoft Learn](https://learn.microsoft.com/en-us/exchange/collaboration/public-folders/migrate-to-exchange-online?view=exchserver-2019).

Run from the on-premises Exchange Management Shell with the Exchange Online Management module installed:

```powershell
.\Sync-ModernMailPublicFolders.ps1 -CsvSummaryFile .\sync_summary.csv
```

For a cloud requiring different endpoints, set both endpoint variables to the values documented for that cloud:

```powershell
.\Sync-ModernMailPublicFolders.ps1 -CsvSummaryFile .\sync_summary.csv `
    -ConnectionUri $connectionUri `
    -AzureADAuthorizationEndpointUri $authorizationEndpointUri
```

The script retains the `Remote` command prefix when applying these overrides. Do not replace its `Connect-ExchangeOnline` call manually. Connection failures stop synchronization instead of being reported as successful.

See [Connect-ExchangeOnline](https://learn.microsoft.com/powershell/module/exchangepowershell/connect-exchangeonline) for endpoint guidance. Endpoint overrides do not remove the script's download requirements. In a disconnected environment, obtain the current scripts in advance, place `ValidateMailEnabledPublicFolders.ps1` in the working directory, and use `-SkipVersionCheck` to skip the update check.

### Address handling

Address processing accepts individual address strings, string arrays, and collections such as `ArrayList` or `ProxyAddressCollection`. Individual proxy-address objects, including `SmtpProxyAddress`, are read through their `ProxyAddressString` property. The same normalization is applied during creation, updates, and address consolidation.

Normalization preserves address casing, including primary `SMTP:` and secondary `smtp:` prefixes. Existing rules for legacy X500 and cloud-only addresses are unchanged. Unsupported or empty address entries cause an explicit error rather than silently dropping addresses.

### Summary output

The script never overwrites an existing summary file. If the requested name already exists, it creates a uniquely named sibling CSV and displays a warning with the new path.

If an active summary file becomes locked, the script tries opening it up to three times, waiting 200 milliseconds between attempts. If it remains locked, the pending record and subsequent output go to a new sibling CSV with its own header. Earlier records stay in the previous file; retain all summary files listed by the script.

Other file errors, or failure to write the alternate file, stop execution. A summary-writing failure does not retry an Exchange operation or reclassify a completed operation as a failed migration. Review the recorded operations and error before rerunning synchronization.
