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
    . $PSScriptRoot\..\Shared\Get-ProcessedServerList.ps1
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

        if ($includeExchangeServerNames.Count -eq 0 -and
            ($null -eq $SkipExchangeServerNames -or $SkipExchangeServerNames.Count -eq 0)) {
            Write-Host "Only going to attempt to run against the local server '$($env:COMPUTERNAME)' since no servers were provided."
            $includeExchangeServerNames.Add($env:COMPUTERNAME)
        }

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

        $processParams = @{
            ExchangeServerNames              = $includeExchangeServerNames
            SkipExchangeServerNames          = $SkipExchangeServerNames
            CheckOnline                      = $true
            DisableGetExchangeServerFullList = $includeExchangeServerNames.Count -gt 0 # if we pass a list, we shouldn't need to get all the servers in the org.
        }

        $processedExchangeServers = Get-ProcessedServerList @processParams

        $params = @{
            ComputerName      = $processedExchangeServers.OnlineExchangeServerFqdn
            ConfigureOverride = $ConfigureOverride
            Action            = $Action
            Rollback          = $Rollback
        }

        Write-Host "Running the configuration change against the following server(s): $([string]::Join(", ", $params.ComputerName))"
        Invoke-TextExtractionOverride @params
    } finally {
        Write-Host ""
        Write-Host "Do you have feedback regarding the script? Please let us know: ExToolsFeedback@microsoft.com."
    }
}
