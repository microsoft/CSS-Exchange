# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    This script can be used to remove vulnerable file types from the FIP-FS configuration.xml file.
.DESCRIPTION
    The script removes vulnerable file types from the FIP-FS configuration.xml file.
    It can also be used to add these file types back. It also allows you to completely disable the usage of the OutsideInModule
    or enable it back.
.PARAMETER ConfigureMitigation
    Use this parameter to specify the mitigation that should be applied.
    Values that can be passed with this parameter are: ConfigureOutsideIn and ConfigureFileTypes
.PARAMETER ConfigureOverride
    Use this parameter to specify the override that should be set.
    Note that setting an override works only if the Exchange Server March 2024 security update was installed.
    Values that can be passed with this parameter are: OutsideInVersionOverride and FileTypesOverride
.PARAMETER OutsideInEnabledFileTypes
    Use this parameter to specify the file types that should be allowed to use the OutsideInModule.
    By default, the only file types that are allowed to use the OutsideInModule are: AutoCad, Jpeg and Tiff
.PARAMETER RestoreFileTypeList
    Use this parameter if you want to restore the file type list. All existing file type overrides will be removed.
.PARAMETER Action
    Use this parameter to specify the action that should be performed.
    Values that can be passed with this parameter are: Allow, Block
.PARAMETER ScriptUpdateOnly
    This optional parameter allows you to only update the script without performing any other actions.
.PARAMETER SkipVersionCheck
    This optional parameter allows you to skip the automatic version check and script update.
.EXAMPLE
    PS C:\> .\ConfigureFipFsTextExtractionOverrides.ps1 -ConfigureOverride OutsideInVersionOverride -Action Allow
    It will add the 'NO' override flag to the OutsideInModule.dll which is defined in the 'OutsideInOnly' module list.
.EXAMPLE
    PS C:\> .\ConfigureFipFsTextExtractionOverrides.ps1 -ConfigureOverride OutsideInVersionOverride -Action Block
    It will remove the 'NO' override flag from the OutsideInModule.dll which is defined in the 'OutsideInOnly' module list.
.EXAMPLE
    PS C:\> .\ConfigureFipFsTextExtractionOverrides.ps1 -ConfigureOverride FileTypesOverride -OutsideInEnabledFileTypes "ExcelStorage" -Action Allow
    It will add 'ExcelStorage' file type to the 'OutsideInOnly' file type list and will add the 'NO' flag to the file type.
.EXAMPLE
    PS C:\> .\ConfigureFipFsTextExtractionOverrides.ps1 -RestoreFileTypeList
    It will restore the default file type to file type list mapping and removes any file type override.
#>

[CmdletBinding(DefaultParameterSetName = "ConfigureOverride", SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $false, ValueFromPipeline, ParameterSetName = "ConfigureOverride")]
    [Parameter(Mandatory = $false, ValueFromPipeline, ParameterSetName = "Rollback")]
    [string[]]$ExchangeServerNames,

    [Parameter(Mandatory = $false, ParameterSetName = "ConfigureOverride")]
    [Parameter(Mandatory = $false, ParameterSetName = "Rollback")]
    [string[]]$SkipExchangeServerNames,

    [Parameter(Mandatory = $true, ParameterSetName = "ConfigureOverride")]
    [ValidateSet("OutsideInModule", "XlsbOfficePackage", "XlsmOfficePackage", "XlsxOfficePackage", "ExcelStorage" , "DocmOfficePackage",
        "DocxOfficePackage", "PptmOfficePackage", "PptxOfficePackage", "WordStorage", "PowerPointStorage", "VisioStorage", "Rtf",
        "Xml", "OdfTextDocument", "OdfSpreadsheet", "OdfPresentation", "OneNote", "Pdf", "Html", "AutoCad", "Jpeg", "Tiff", IgnoreCase = $false)]
    [string[]]$ConfigureOverride,

    [Parameter(Mandatory = $false, ParameterSetName = "ConfigureOverride")]
    [ValidateSet("Allow", "Block")]
    [string]$Action = "Block",

    [Parameter(Mandatory = $true, ParameterSetName = "Rollback")]
    [switch]$Rollback,

    [Parameter(Mandatory = $false, ParameterSetName = "ScriptUpdateOnly")]
    [switch]$ScriptUpdateOnly,

    [switch]$SkipVersionCheck
)

begin {
    . $PSScriptRoot\ConfigurationAction\Invoke-TextExtractionOverride.ps1
    . $PSScriptRoot\..\..\..\Shared\GenericScriptStartLogging.ps1
    . $PSScriptRoot\..\..\..\Shared\ScriptUpdateFunctions\GenericScriptUpdate.ps1

    if ($ConfigureOverride.Count -gt 1 -and $ConfigureOverride -contains "OutsideInModule") {
        Write-Error "OutsideInModule ConfigureOverride can only be processed by itself."
        exit
    }

    $includeExchangeServerNames = New-Object System.Collections.Generic.List[string]
} process {
    foreach ($server in $ExchangeServerNames) {
        $includeExchangeServerNames.Add($server)
    }
} end {
    try {
        # TODO adjust the disclaimer wording to match the latest adjustment
        $exchangeServicesWording = "Note that each Exchange server's MSExchangeTransport and FMS service will be restarted to backup and apply the setting change action."
        $vulnerabilityMoreInformationWording = "More information about the vulnerability can be found here: https://portal.msrc.microsoft.com/security-guidance/advisory/CVE-2024-xxxxx."

        # TODO: Update Disclaimer section.

        if ($Configuration -eq "ConfigureOutsideIn" -and
            $Action -eq "Block") {
            $params = @{
                Message   = "Display warning about OutsideInModule removal operation"
                Target    = "Disabling OutsideInModule can be done to mitigate CVE-2024-xxxxx vulnerability. " +
                "`r`nRemoval of this module might have impact on xxxxx. " +
                "$exchangeServicesWording" +
                "`r`n$vulnerabilityMoreInformationWording" +
                "`r`nDo you want to proceed?"
                Operation = "Disabling FIP-FS OutsideInModule usage"
            }
        } elseif ($Configuration -eq "ConfigureFileTypes" -and
            $Action -eq "Block") {
            $params = @{
                Message   = "Display warning about ConfigureFileTypes removal operation"
                Target    = "Configuring file types that can be processed by the OutsideInModule can be done to mitigate CVE-2024-xxxxx vulnerability. " +
                "`r`Configuring these file types might have impact on xxxxx. " +
                "$exchangeServicesWording" +
                "`r`n$vulnerabilityMoreInformationWording" +
                "`r`nDo you want to proceed?"
                Operation = "Configure file types that can be processed by the FIP-FS OutsideInModule"
            }
        } else {
            $params = @{
                Message   = "Display warning about OutsideInModule rollback operation"
                Target    = "Restoring the previous OutsideInModule configuration state will make your system vulnerable to CVE-2024-xxxxx again. " +
                "$exchangeServicesWording" +
                "`r`n$vulnerabilityMoreInformationWording" +
                "`r`nDo you want to proceed?"
                Operation = "Rollback FIP-FS OutsideInModule configuration"
            }
        }

        Show-Disclaimer @params

        if (-not([string]::IsNullOrEmpty($ConfigureMitigation))) {
            # Mitigation mode was selected. In this mode the script will:
            # a) disable the OutsideInModule.dll for all file types
            # or
            # b) remove vulnerable file types from the file types lists that make use of OutsideInModule.dll
            $invokeOutsideInModuleActionParams = @{
                Configuration = $ConfigureMitigation
                Action        = $Action
            }

            if ($ConfigureMitigation -eq "ConfigureFileTypes") {
                $invokeOutsideInModuleActionParams.Add("FileTypesDictionary", $fileTypesDictionary)
            }
        } elseif (-not([string]::IsNullOrEmpty($ConfigureOverride))) {
            # Configuration override mode was selected. In this mode the script will:
            # a) allows you to add the override flag ('NO') to the OutsideInVersion.dll which is part of the OutsideInOnly module list
            # or
            # b) allows you to add the override flag to file types that are part of the file type list
            # the file type will also moved to the OutsideInOnly file type list (if it's yet part of it)
            $invokeOutsideInModuleActionParams = @{
                Configuration = $ConfigureOverride
                Action        = $Action
            }

            if (-not([string]::IsNullOrWhiteSpace($OutsideInEnabledFileTypes))) {
                $invokeOutsideInModuleActionParams.Add("FileTypesDictionary", $OutsideInEnabledFileTypes)
            }
        } elseif ($RestoreFileTypeList) {
            # File type list restore mode was selected. In this mode the script will:
            # a) restore the file type to file type list mapping
            # and
            # b) remove the override from any file type that has an override ('NO') set
            $invokeOutsideInModuleActionParams = @{
                Configuration = "FileTypesOverride"
                Action        = "Block"
            }
        }

        $params = @{
            ComputerName      = $includeExchangeServerNames
            ConfigureOverride = $ConfigureOverride
            Action            = $Action
            Rollback          = $Rollback
        }

        Invoke-TextExtractionOverride @params
    } finally {
        Write-Host ""
        Write-Host "Do you have feedback regarding the script? Please let us know: ExToolsFeedback@microsoft.com."
    }
}
