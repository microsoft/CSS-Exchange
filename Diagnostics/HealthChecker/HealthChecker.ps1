# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.NOTES
	Name: HealthChecker.ps1
	Requires: Exchange Management Shell and administrator rights on the target Exchange
	server as well as the local machine.
    Major Release History:
        4/20/2021  - Initial Public Release on CSS-Exchange.
        11/10/2020 - Initial Public Release of version 3.
        1/18/2017 - Initial Public Release of version 2.
        3/30/2015 - Initial Public Release.

.SYNOPSIS
	Checks the target Exchange server for various configuration recommendations from the Exchange product group.
.DESCRIPTION
	This script checks the Exchange server for various configuration recommendations outlined in the
	"Exchange 2013 Performance Recommendations" section on Microsoft Docs, found here:

	https://docs.microsoft.com/en-us/exchange/exchange-2013-sizing-and-configuration-recommendations-exchange-2013-help

	Informational items are reported in Grey.  Settings found to match the recommendations are
	reported in Green.  Warnings are reported in yellow.  Settings that can cause performance
	problems are reported in red.  Please note that most of these recommendations only apply to latest Support Exchange versions.
.PARAMETER Server
	This optional parameter allows the target Exchange server to be specified.  If it is not the
	local server is assumed.
.PARAMETER OutputFilePath
	This optional parameter allows an output directory to be specified.  If it is not the local
	directory is assumed.  This parameter must not end in a \.  To specify the folder "logs" on
	the root of the E: drive you would use "-OutputFilePath E:\logs", not "-OutputFilePath E:\logs\".
.PARAMETER MailboxReport
	This optional parameter gives a report of the number of active and passive databases and
	mailboxes on the server.
.PARAMETER LoadBalancingReport
    This optional parameter will check the connection count of the Default Web Site for every server
    running Exchange 2013+ with the role in the org.  It then breaks down servers by percentage to
    give you an idea of how well the load is being balanced.
.PARAMETER ServerList
    Used with -LoadBalancingReport. A comma separated list of servers to operate against. Without
    this switch the report will use all 2013+ servers in the organization.
.PARAMETER SiteName
	Used with -LoadBalancingReport.  Specifies a site to pull  servers from instead of querying every server
    in the organization.
.PARAMETER XMLDirectoryPath
    Used in combination with BuildHtmlServersReport switch for the location of the HealthChecker XML files for servers
    which you want to be included in the report. Default location is the current directory.
.PARAMETER BuildHtmlServersReport
    Switch to enable the script to build the HTML report for all the servers XML results in the XMLDirectoryPath location.
.PARAMETER HtmlReportFile
    Name of the HTML output file from the BuildHtmlServersReport. Default is ExchangeAllServersReport.html
.PARAMETER DCCoreRatio
    Gathers the Exchange to DC/GC Core ratio and displays the results in the current site that the script is running in.
.PARAMETER AnalyzeDataOnly
    Switch to analyze the existing HealthChecker XML files. The results are displayed on the screen and an HTML report is generated.
.PARAMETER SkipVersionCheck
    No version check is performed when this switch is used.
.PARAMETER SaveDebugLog
    The debug log is kept even if the script is executed successfully.
.PARAMETER ScriptUpdateOnly
    Switch to check for the latest version of the script and perform an auto update. No elevated permissions or EMS are required.
.PARAMETER Verbose
	This optional parameter enables verbose logging.
.EXAMPLE
	.\HealthChecker.ps1 -Server SERVERNAME
	Run against a single remote Exchange server
.EXAMPLE
	.\HealthChecker.ps1 -Server SERVERNAME1,SERVERNAME2
	Run against a list of servers
.EXAMPLE
	.\HealthChecker.ps1 -Server SERVERNAME -MailboxReport -Verbose
	Run against a single remote Exchange server with verbose logging and mailbox report enabled.
.EXAMPLE
	Get-ExchangeServer | .\HealthChecker.ps1
	Run against all the Exchange servers in the Organization.
.EXAMPLE
    .\HealthChecker.ps1 -LoadBalancingReport
    Run a load balancing report comparing all Exchange 2013+ servers in the Organization.
.EXAMPLE
    .\HealthChecker.ps1 -LoadBalancingReport -ServerList EX01,EX02,EXS03
    Run a load balancing report comparing servers named EX01, EX02, and EX03.
.LINK
    https://docs.microsoft.com/en-us/exchange/exchange-2013-sizing-and-configuration-recommendations-exchange-2013-help
    https://docs.microsoft.com/en-us/exchange/exchange-2013-virtualization-exchange-2013-help#requirements-for-hardware-virtualization
    https://docs.microsoft.com/en-us/exchange/plan-and-deploy/virtualization?view=exchserver-2019#requirements-for-hardware-virtualization
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Variables are being used')]
[CmdletBinding(DefaultParameterSetName = "HealthChecker", SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ParameterSetName = "HealthChecker", HelpMessage = "Enter the list of servers names on which the script should execute against.")]
    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ParameterSetName = "MailboxReport", HelpMessage = "Enter the list of servers names on which the script should execute against.")]
    [string[]]$Server = ($env:COMPUTERNAME),

    [Parameter(Mandatory = $false, HelpMessage = "Provide the location of where the output files should go.")]
    [ValidateScript( {
            -not $_.ToString().EndsWith('\') -and (Test-Path $_)
        })]
    [string]$OutputFilePath = ".",

    [Parameter(Mandatory = $true, ParameterSetName = "MailboxReport", HelpMessage = "Enable the MailboxReport feature data collection against the server.")]
    [switch]$MailboxReport,

    [Parameter(Mandatory = $true, ParameterSetName = "LoadBalancingReport", HelpMessage = "Enable the LoadBalancingReport feature data collection.")]
    [Parameter(Mandatory = $true, ParameterSetName = "LoadBalancingReportBySite", HelpMessage = "Enable the LoadBalancingReport feature data collection.")]
    [switch]$LoadBalancingReport,

    [Alias("CASServerList")]
    [Parameter(Mandatory = $false, ParameterSetName = "LoadBalancingReport", HelpMessage = "Provide a list of servers to run against for the LoadBalancingReport.")]
    [string[]]$ServerList = $null,

    [Parameter(Mandatory = $true, ParameterSetName = "LoadBalancingReportBySite", HelpMessage = "Provide the AD SiteName to run the LoadBalancingReport against.")]
    [string]$SiteName = ([string]::Empty),

    [Parameter(Mandatory = $false, ParameterSetName = "HTMLReport", HelpMessage = "Provide the directory where the XML files are located at from previous runs of the Health Checker to Import the data from.")]
    [Parameter(Mandatory = $false, ParameterSetName = "AnalyzeDataOnly", HelpMessage = "Provide the directory where the XML files are located at from previous runs of the Health Checker to Import the data from.")]
    [Parameter(Mandatory = $false, ParameterSetName = "VulnerabilityReport", HelpMessage = "Provide the directory where the XML files are located at from previous runs of the Health Checker to Import the data from.")]
    [ValidateScript( {
            -not $_.ToString().EndsWith('\')
        })]
    [string]$XMLDirectoryPath = ".",

    [Parameter(Mandatory = $true, ParameterSetName = "HTMLReport", HelpMessage = "Enable the HTMLReport feature to run against the XML files from previous runs of the Health Checker script.")]
    [switch]$BuildHtmlServersReport,

    [Parameter(Mandatory = $false, ParameterSetName = "HTMLReport", HelpMessage = "Provide the name of the Report to be created.")]
    [string]$HtmlReportFile = "ExchangeAllServersReport.html",

    [Parameter(Mandatory = $true, ParameterSetName = "DCCoreReport", HelpMessage = "Enable the DCCoreReport feature data collection against the current server's AD Site.")]
    [switch]$DCCoreRatio,

    [Parameter(Mandatory = $true, ParameterSetName = "AnalyzeDataOnly", HelpMessage = "Enable to reprocess the data that was previously collected and display to the screen")]
    [switch]$AnalyzeDataOnly,

    [Parameter(Mandatory = $true, ParameterSetName = "VulnerabilityReport", HelpMessage = "Enable to collect data on the entire environment and report only the security vulnerabilities.")]
    [switch]$VulnerabilityReport,

    [Parameter(Mandatory = $false, ParameterSetName = "HealthChecker", HelpMessage = "Skip over checking for a new updated version of the script.")]
    [Parameter(Mandatory = $false, ParameterSetName = "MailboxReport", HelpMessage = "Skip over checking for a new updated version of the script.")]
    [Parameter(Mandatory = $false, ParameterSetName = "LoadBalancingReport", HelpMessage = "Skip over checking for a new updated version of the script.")]
    [Parameter(Mandatory = $false, ParameterSetName = "HTMLReport", HelpMessage = "Skip over checking for a new updated version of the script.")]
    [Parameter(Mandatory = $false, ParameterSetName = "DCCoreReport", HelpMessage = "Skip over checking for a new updated version of the script.")]
    [Parameter(Mandatory = $false, ParameterSetName = "AnalyzeDataOnly", HelpMessage = "Skip over checking for a new updated version of the script.")]
    [Parameter(Mandatory = $false, ParameterSetName = "VulnerabilityReport", HelpMessage = "Skip over checking for a new updated version of the script.")]
    [switch]$SkipVersionCheck,

    [Parameter(Mandatory = $false, HelpMessage = "Always keep the debug log output at the end of the script.")]
    [switch]$SaveDebugLog,

    [Parameter(Mandatory = $true, ParameterSetName = "ScriptUpdateOnly", HelpMessage = "Only attempt to update the script.")]
    [switch]$ScriptUpdateOnly
)

begin {

    . $PSScriptRoot\Analyzer\Invoke-AnalyzerEngine.ps1
    . $PSScriptRoot\Helpers\Get-ErrorsThatOccurred.ps1
    . $PSScriptRoot\Helpers\Get-ExportedHealthCheckerFiles.ps1
    . $PSScriptRoot\Helpers\Invoke-ConfirmExchangeShell.ps1
    . $PSScriptRoot\Helpers\Invoke-SetOutputInstanceLocation.ps1
    . $PSScriptRoot\Writers\Write-ResultsToScreen.ps1
    . $PSScriptRoot\Writers\Write-Functions.ps1
    . $PSScriptRoot\Features\Get-HtmlServerReport.ps1
    . $PSScriptRoot\Features\Get-LoadBalancingReport.ps1
    . $PSScriptRoot\Features\Get-ExchangeDcCoreRatio.ps1
    . $PSScriptRoot\Features\Get-MailboxDatabaseAndMailboxStatistics.ps1
    . $PSScriptRoot\Features\Invoke-HealthCheckerMainReport.ps1
    . $PSScriptRoot\Features\Invoke-VulnerabilityReport.ps1

    . $PSScriptRoot\..\..\Shared\Confirm-Administrator.ps1
    . $PSScriptRoot\..\..\Shared\ErrorMonitorFunctions.ps1
    . $PSScriptRoot\..\..\Shared\LoggerFunctions.ps1
    . $PSScriptRoot\..\..\Shared\OutputOverrides\Write-Host.ps1
    . $PSScriptRoot\..\..\Shared\OutputOverrides\Write-Verbose.ps1
    . $PSScriptRoot\..\..\Shared\OutputOverrides\Write-Warning.ps1
    . $PSScriptRoot\..\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1

    $BuildVersion = ""

    $Script:VerboseEnabled = $false
    #this is to set the verbose information to a different color
    if ($PSBoundParameters["Verbose"]) {
        #Write verbose output in cyan since we already use yellow for warnings
        $Script:VerboseEnabled = $true
        $VerboseForeground = $Host.PrivateData.VerboseForegroundColor
        $Host.PrivateData.VerboseForegroundColor = "Cyan"
    }

    $Script:ServerNameList = New-Object System.Collections.Generic.List[string]
    $Script:Logger = Get-NewLoggerInstance -LogName "HealthChecker-Debug" `
        -LogDirectory $Script:OutputFilePath `
        -AppendDateTime $false `
        -ErrorAction SilentlyContinue
    SetProperForegroundColor
    SetWriteVerboseAction ${Function:Write-DebugLog}
    SetWriteWarningAction ${Function:Write-DebugLog}
} process {
    $Server | ForEach-Object { $Script:ServerNameList.Add($_.ToUpper()) }
} end {
    try {

        if (-not (Confirm-Administrator) -and
            (-not $AnalyzeDataOnly -and
            -not $BuildHtmlServersReport -and
            -not $ScriptUpdateOnly)) {
            Write-Warning "The script needs to be executed in elevated mode. Start the Exchange Management Shell as an Administrator."
            $Error.Clear()
            Start-Sleep -Seconds 2;
            exit
        }

        Invoke-ErrorMonitoring
        $Script:date = (Get-Date)
        $Script:dateTimeStringFormat = $date.ToString("yyyyMMddHHmmss")

        # Some companies might already provide a full path for HtmlReportFile
        # Detect if it is just a name, if it is, then append OutputFilePath to it.
        # Otherwise, keep it as is
        if ($HtmlReportFile.Contains("\")) {
            $htmlOutFilePath = $HtmlReportFile
        } else {
            $htmlOutFilePath = [System.IO.Path]::Combine($OutputFilePath, $HtmlReportFile)
        }

        # Features that doesn't require Exchange Shell
        if ($BuildHtmlServersReport) {
            Invoke-SetOutputInstanceLocation -FileName "HealthChecker-HTMLServerReport"
            $importData = Get-ExportedHealthCheckerFiles -Directory $XMLDirectoryPath

            if ($null -eq $importData) {
                Write-Host "Doesn't appear to be any Health Check XML files here....stopping the script"
                exit
            }
            Get-HtmlServerReport -AnalyzedHtmlServerValues $importData.HtmlServerValues -HtmlOutFilePath $htmlOutFilePath
            Start-Sleep 2;
            return
        }

        if ($AnalyzeDataOnly) {
            Invoke-SetOutputInstanceLocation -FileName "HealthChecker-Analyzer"
            $importData = Get-ExportedHealthCheckerFiles -Directory $XMLDirectoryPath

            if ($null -eq $importData) {
                Write-Host "Doesn't appear to be any Health Check XML files here....stopping the script"
                exit
            }

            $analyzedResults = @()
            foreach ($serverData in $importData) {
                $analyzedServerResults = Invoke-AnalyzerEngine -HealthServerObject $serverData.HealthCheckerExchangeServer
                Write-ResultsToScreen -ResultsToWrite $analyzedServerResults.DisplayResults
                $analyzedResults += $analyzedServerResults
            }

            Get-HtmlServerReport -AnalyzedHtmlServerValues $analyzedResults.HtmlServerValues -HtmlOutFilePath $htmlOutFilePath
            return
        }

        if ($ScriptUpdateOnly) {
            Invoke-SetOutputInstanceLocation -FileName "HealthChecker-ScriptUpdateOnly"
            switch (Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/HC-VersionsUrl" -Confirm:$false) {
                ($true) { Write-Green("Script was successfully updated.") }
                ($false) { Write-Yellow("No update of the script performed.") }
                default { Write-Red("Unable to perform ScriptUpdateOnly operation.") }
            }
            return
        }

        # Features that do require Exchange Shell
        if ($LoadBalancingReport) {
            Invoke-SetOutputInstanceLocation -FileName "HealthChecker-LoadBalancingReport"
            Invoke-ConfirmExchangeShell
            Write-Grey "Script Version: $BuildVersion"
            Write-Green("Load Balancing Report on " + $date)
            Get-LoadBalancingReport
            Write-Grey("Output file written to " + $Script:OutputFullPath)
            Write-Break
            Write-Break
            return
        }

        if ($DCCoreRatio) {
            $oldErrorAction = $ErrorActionPreference
            $ErrorActionPreference = "Stop"
            try {
                Get-ExchangeDCCoreRatio
                return
            } finally {
                $ErrorActionPreference = $oldErrorAction
            }
        }

        if ($MailboxReport) {
            Invoke-ConfirmExchangeShell

            foreach ($serverName in $Script:ServerNameList) {
                Invoke-SetOutputInstanceLocation -Server $serverName -FileName "HealthChecker-MailboxReport" -IncludeServerName $true
                Get-MailboxDatabaseAndMailboxStatistics -Server $serverName
                Write-Grey("Output file written to {0}" -f $Script:OutputFullPath)
            }
            return
        }

        if ($VulnerabilityReport) {
            Invoke-ConfirmExchangeShell
            Invoke-VulnerabilityReport
            return
        }

        # Main Feature of Health Checker
        Invoke-ConfirmExchangeShell
        Invoke-HealthCheckerMainReport -ServerNames $Script:ServerNameList -EdgeServer $Script:ExchangeShellComputer.EdgeServer
    } finally {
        Get-ErrorsThatOccurred
        if ($Script:VerboseEnabled) {
            $Host.PrivateData.VerboseForegroundColor = $VerboseForeground
        }
        $Script:Logger | Invoke-LoggerInstanceCleanup
        if ($Script:Logger.PreventLogCleanup) {
            Write-Host("Output Debug file written to {0}" -f $Script:Logger.FullPath)
        }
        if (((Get-Date).Ticks % 2) -eq 1) {
            Write-Host("Do you like the script? Visit https://aka.ms/HC-Feedback to rate it and to provide feedback.") -ForegroundColor Green
            Write-Host
        }
        RevertProperForegroundColor
    }
}
