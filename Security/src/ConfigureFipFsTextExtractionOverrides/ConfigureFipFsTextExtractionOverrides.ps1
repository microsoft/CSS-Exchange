# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    This script can be used revert the 'secure by default' change which was introduced as part of the Exchange Server March 2024 security update.
    More information can be found in https://support.microsoft.com/help/5036795
.DESCRIPTION
    The script can be used to add overrides to the FIP-FS configuration.xml file.
    This can be done to reactivate the use of the OutsideInModule for file types, which are no longer processed by the help of this module.
    An override can also be done to the version of the OutsideInModule.dll. After the March 2024 security update was installed,
    Exchange Server uses OutsideInModule version 8.5.7 by default, which is the latest version that was available at the time the SU was published.
    By the help of the script, usage of the previous version 8.5.3 can be enforced.
.PARAMETER ExchangeServerNames
    Use this parameter to specify the Exchange Server on which the change to the configuration should be done.
.PARAMETER SkipExchangeServerNames
    Use this parameter to specify the Exchange Server, which should be excluded from the configuration action.
.PARAMETER ConfigureOverride
    Use this parameter to specify the file types for which the override should be added or from which the override should be removed.
    You can also use this parameter to configure the override of the OutsideInModule version.
    The values are case sensitive. Values that can be used with this parameter are:
    OutsideInModule, XlsbOfficePackage, XlsmOfficePackage, XlsxOfficePackage, ExcelStorage , DocmOfficePackage,
    DocxOfficePackage, PptmOfficePackage, PptxOfficePackage, WordStorage, PowerPointStorage, VisioStorage, Rtf,
    Xml, OdfTextDocument, OdfSpreadsheet, OdfPresentation, OneNote, Pdf, Html, AutoCad, Jpeg, Tiff
.PARAMETER Action
    Use this parameter to specify the action that should be performed. The override flag will be added if the Allow value was used.
    Values that can be passed are: Allow, Block
    The default value is: Block
.PARAMETER Rollback
    Use this parameter to restore the configuration.xml based on the backup that was automatically created during a previous run of the script.
    The restore operation will fail if no backup file can be found.
.PARAMETER ScriptUpdateOnly
    This optional parameter allows you to only update the script without performing any other actions.
.PARAMETER SkipVersionCheck
    This optional parameter allows you to skip the automatic version check and script update.
.EXAMPLE
    PS C:\> .\ConfigureFipFsTextExtractionOverrides.ps1 -ConfigureOverride OutsideInModule -Action Allow
    It will add the override flag to the OutsideInModule.dll which is defined in the 'OutsideInOnly' module list. The action will be performed on
    the machine where the script was executed.
.EXAMPLE
    PS C:\> .\ConfigureFipFsTextExtractionOverrides.ps1 -ConfigureOverride OutsideInModule -Action Block
    It will remove the override flag from the OutsideInModule.dll which is defined in the 'OutsideInOnly' module list. The action will be performed on
    the machine where the script was executed.
.EXAMPLE
    PS C:\> .\ConfigureFipFsTextExtractionOverrides.ps1 -ConfigureOverride AutoCad -Action Allow
    It will add the override flag to the 'AutoCad' file type. The action will be performed on the machine where the script was executed.
.EXAMPLE
    PS C:\> Get-ExchangeServer | .\ConfigureFipFsTextExtractionOverrides.ps1 -ConfigureOverride AutoCad -Action Allow
    It will add the override flag to the 'AutoCad' file type. The action will be performed on all Exchange servers.
.EXAMPLE
    PS C:\> Get-ExchangeServer | .\ConfigureFipFsTextExtractionOverrides.ps1 -Rollback -SkipExchangeServerNames "ExchSrv02"
    It will restore the configuration.xml from the backup file that was created during a previous run of the script.
    The action will be performed on all Exchange servers except ExchSrv02.
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
    $versionsUrl = "https://aka.ms/ConfigureFipFsTextExtractionOverrides-VersionsURL"

    . $PSScriptRoot\ConfigurationAction\Invoke-TextExtractionOverride.ps1
    . $PSScriptRoot\..\Shared\Get-ProcessedServerList.ps1
    . $PSScriptRoot\..\..\..\Shared\Confirm-ExchangeManagementShell.ps1
    . $PSScriptRoot\..\..\..\Shared\GenericScriptStartLogging.ps1
    . $PSScriptRoot\..\..\..\Shared\ScriptUpdateFunctions\GenericScriptUpdate.ps1

    $includeExchangeServerNames = New-Object System.Collections.Generic.List[string]
} process {
    foreach ($server in $ExchangeServerNames) {
        $includeExchangeServerNames.Add($server)
    }
} end {
    try {
        Write-Verbose "Url to check for new versions of the script is: $versionsUrl"

        if (-not (Confirm-ExchangeManagementShell)) {
            Write-Error "This script must be run from Exchange Management Shell."
            exit
        }

        if ($ConfigureOverride.Count -gt 1 -and $ConfigureOverride -contains "OutsideInModule") {
            Write-Error "OutsideInModule ConfigureOverride can only be processed by itself."
            exit
        }

        if ($includeExchangeServerNames.Count -eq 0 -and
            ($null -eq $SkipExchangeServerNames -or $SkipExchangeServerNames.Count -eq 0)) {
            Write-Host "Only going to attempt to run against the local server '$($env:COMPUTERNAME)' since no servers were provided."
            $includeExchangeServerNames.Add($env:COMPUTERNAME)
        }

        $exchangeServicesWording = "Each Exchange server's MSExchangeTransport and FMS service will be restarted to backup and apply the configuration change."
        $vulnerabilityMoreInformationWording = "More information about the security vulnerability can be found here: https://portal.msrc.microsoft.com/security-guidance/advisory/ADV24199947."

        if ($ConfigureOverride -eq "OutsideInModule" -and
            $Action -eq "Allow") {
            $params = @{
                Message   = "Display warning about OutsideInModule override operation"
                Target    = "This operation enables an outdate version of the OutsideInModule which is known to be vulnerable." +
                "`r`n$exchangeServicesWording" +
                "`r`n$vulnerabilityMoreInformationWording" +
                "`r`nDo you want to proceed?"
                Operation = "Enabling usage of an outdated OutsideInModule version"
            }
        } elseif ($ConfigureOverride.Count -ge 1 -and
            $Action -eq "Allow") {
            $params = @{
                Message   = "Display warning about file type override operation"
                Target    = "This operation enables OutsideInModule usage for the following file types:" +
                "`r`n$([string]::Join(", ", $ConfigureOverride))" +
                "`r`n$exchangeServicesWording" +
                "`r`n$vulnerabilityMoreInformationWording" +
                "`r`nDo you want to proceed?"
                Operation = "Configure file types that should be processed by the OutsideInModule"
            }
        } else {
            $params = @{
                Message   = "Display warning about service restart operation"
                Target    = "$exchangeServicesWording" +
                "`r`nDo you want to proceed?"
                Operation = "Performing OutsideInModule configuration action"
            }
        }

        Show-Disclaimer @params

        $processParams = @{
            ExchangeServerNames              = $includeExchangeServerNames
            SkipExchangeServerNames          = $SkipExchangeServerNames
            CheckOnline                      = $true
            DisableGetExchangeServerFullList = $includeExchangeServerNames.Count -gt 0 # if we pass a list, we shouldn't need to get all the servers in the org.
            MinimumSU                        = "Mar24SU"
        }

        $processedExchangeServers = Get-ProcessedServerList @processParams

        $params = @{
            ComputerName      = $processedExchangeServers.ValidExchangeServerFqdn
            ConfigureOverride = $ConfigureOverride
            Action            = $Action
            Rollback          = $Rollback
        }

        if ($Rollback -and $processedExchangeServers.OutdatedBuildExchangeServerFqdn.Count -gt 0) {
            Write-Host "Adding the Server(s) back into the list to process because we are attempting to rollback: $([string]::Join(", ", $processedExchangeServers.OutdatedBuildExchangeServerFqdn))"
            $params.ComputerName = $processedExchangeServers.OnlineExchangeServerFqdn
        }

        if ($params.ComputerName.Count -ge 1) {
            Write-Host "Running the configuration change against the following server(s): $([string]::Join(", ", $params.ComputerName))"
            Invoke-TextExtractionOverride @params
        } else {
            Write-Host "None of the server(s) passed to the script do support OutsideInModule overrides"
        }
    } finally {
        Write-Host ""
        Write-Host "Do you have feedback regarding the script? Please let us know: ExToolsFeedback@microsoft.com."
    }
}
