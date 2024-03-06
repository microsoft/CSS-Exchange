# ConfigureFipFsTextExtractionOverrides

Download the latest release: [ConfigureFipFsTextExtractionOverrides.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/ConfigureFipFsTextExtractionOverrides.ps1)

!!! warning "Note"

      With the Exchange Server March 2024 security update we disable the use of the OutsideInModule in Microsoft Exchange Server due to multiple security flaws in the module. The OutsideInModule was used by the Microsoft Forefront Filtering Module to extract information from different file types, to perform content inspection as part of the Exchange Server Data Loss Prevention (DLP) feature.

The `ConfigureFipFsTextExtractionOverrides.ps1` script can be used to enable file types that should be processed by the help of the `Oracle Outside In Technology` (also known as `OutsideInModule`). The module is used by the `Microsoft Forefront Filtering Module` when Exchange Transport Rules (ETR) or Data Loss Prevention (DLP) rules are in place.

The script can also be used to override the version of the `OutsideInModule` that should be used. After installing the March 2024 Security Update, Exchange Server will use the latest version of the `OutsideInModule`, which is `8.5.7`, if processing for a file type was explicitly enabled by the help of this script.

Details about the change that was done as part of the March 2024 security update can be found in [KB5037191](https://support.microsoft.com/topic/5037191).

Details about the security flaw can be found in the [MSRC security advisory](https://portal.msrc.microsoft.com/security-guidance/advisory/ADV24199947).

!!! warning "Warning"

      We strongly recommend to not override the OutsideInModule version as this could make the server vulnerable! Do not use this override unless explicitly advised by Microsoft to do so.

## Requirements

This script **must** be run as Administrator in `Exchange Management Shell (EMS)`. The user must be a member of the `Organization Management` role group.

## How To Run

### Examples:

This syntax enables processing of `Jpeg` and `AutoCad` file types by the help of the `OutsideInModule` on the server where the command was executed.

```powershell
.\ConfigureFipFsTextExtractionOverrides.ps1 -ConfigureOverride "Jpeg", "AutoCad" -Action "Allow"
```

This syntax disables processing of `Jpeg` and `AutoCad` file types by the help of the `OutsideInModule` on the server `ExchangeSrv01` and `ExchangeSrv02`.

```powershell
.\ConfigureFipFsTextExtractionOverrides.ps1 -ExchangeServerNames ExchangeSrv01, ExchangeSrv02 -ConfigureOverride "Jpeg", "AutoCad" -Action "Block"
```

This syntax causes Exchange Server to use the previous version of the `OutsideInModule`. The override will be enabled on the system on which the script was executed. Note that this can make your system vulnerable to known vulnerabilities in the previous version and should not be used unless explicitly advised by Microsoft.

```powershell
.\ConfigureFipFsTextExtractionOverrides.ps1 -ConfigureOverride "OutsideInModule" -Action "Allow"
```

This syntax disables the override of the version of the `OutsideInModule` module on the server `ExchangeSrv01` and `ExchangeSrv02`.

```powershell
.\ConfigureFipFsTextExtractionOverrides.ps1 -ExchangeServerNames ExchangeSrv01, ExchangeSrv02 -ConfigureOverride "OutsideInModule" -Action "Block"
```

This syntax restores the `configuration.xml` from the backup that was created by a previous run of the script on the Exchange server where the script was executed.

```powershell
.\ConfigureFipFsTextExtractionOverrides.ps1 -Rollback
```

## Parameters

Parameter | Description
----------|------------
ExchangeServerNames | A list of Exchange servers that you want to run the script against.
SkipExchangeServerNames | A list of Exchange servers that you don't want to execute the configuration action.
ConfigureOverride | A list of file types that should be allowed to be processed by the `OutsideInModule`. It also allows you to override the version of the `OutsideInModule.dll` that should be used by Exchange Server. The following input can be used: `OutsideInModule`, `XlsbOfficePackage`, `XlsmOfficePackage`, `XlsxOfficePackage`, `ExcelStorage`, `DocmOfficePackage`, `DocxOfficePackage`, `PptmOfficePackage`, `PptxOfficePackage`, `WordStorage`, `PowerPointStorage`, `VisioStorage`, `Rtf`, `Xml`, `OdfTextDocument`, `OdfSpreadsheet`, `OdfPresentation`, `OneNote`, `Pdf`, `Html`, `AutoCad`, `Jpeg`, `Tiff`. `OutsideInModule` cannot be used together with other file types. The input is case-sensitive.
Action | String parameter to define the action that should be performed. Input can be `Allow` or `Block`. The default value is: `Block`
Rollback | Switch parameter to restore the `configuration.xml` that was backed-up during a previous run of the script.
ScriptUpdateOnly | Switch parameter to only update the script without performing any other actions.
SkipVersionCheck | Switch parameter to skip the automatic version check and script update.
