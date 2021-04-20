<#
.NOTES
	Name: HealthChecker.ps1
	Original Author: Marc Nivens
    Author: David Paulson
    Contributor: Jason Shinbaum, Michael Schatte, Lukas Sassl
	Requires: Exchange Management Shell and administrator rights on the target Exchange
	server as well as the local machine.
    Major Release History:
        11/10/2020 - Initial Public Release of version 3.
        1/18/2017 - Initial Public Release of version 2. - rewritten by David Paulson.
        3/30/2015 - Initial Public Release.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
	BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
	NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
	DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
.SYNOPSIS
	Checks the target Exchange server for various configuration recommendations from the Exchange product group.
.DESCRIPTION
	This script checks the Exchange server for various configuration recommendations outlined in the
	"Exchange 2013 Performance Recommendations" section on Microsoft Docs, found here:

	https://docs.microsoft.com/en-us/exchange/exchange-2013-sizing-and-configuration-recommendations-exchange-2013-help

	Informational items are reported in Grey.  Settings found to match the recommendations are
	reported in Green.  Warnings are reported in yellow.  Settings that can cause performance
	problems are reported in red.  Please note that most of these recommendations only apply to Exchange
	2013/2016.  The script will run against Exchange 2010/2007 but the output is more limited.
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
    running Exchange 2013/2016 with the Client Access role in the org.  It then breaks down servers by percentage to
    give you an idea of how well the load is being balanced.
.PARAMETER CasServerList
    Used with -LoadBalancingReport.  A comma separated list of CAS servers to operate against.  Without
    this switch the report will use all 2013/2016 Client Access servers in the organization.
.PARAMETER SiteName
	Used with -LoadBalancingReport.  Specifies a site to pull CAS servers from instead of querying every server
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
.PARAMETER Verbose
	This optional parameter enables verbose logging.
.EXAMPLE
	.\HealthChecker.ps1 -Server SERVERNAME
	Run against a single remote Exchange server
.EXAMPLE
	.\HealthChecker.ps1 -Server SERVERNAME -MailboxReport -Verbose
	Run against a single remote Exchange server with verbose logging and mailbox report enabled.
.EXAMPLE
    Get-ExchangeServer | ?{$_.AdminDisplayVersion -Match "^Version 15"} | %{.\HealthChecker.ps1 -Server $_.Name}
    Run against all Exchange 2013/2016 servers in the Organization.
.EXAMPLE
    .\HealthChecker.ps1 -LoadBalancingReport
    Run a load balancing report comparing all Exchange 2013/2016 CAS servers in the Organization.
.EXAMPLE
    .\HealthChecker.ps1 -LoadBalancingReport -CasServerList CAS01,CAS02,CAS03
    Run a load balancing report comparing servers named CAS01, CAS02, and CAS03.
.LINK
    https://docs.microsoft.com/en-us/exchange/exchange-2013-sizing-and-configuration-recommendations-exchange-2013-help
    https://docs.microsoft.com/en-us/exchange/exchange-2013-virtualization-exchange-2013-help#requirements-for-hardware-virtualization
    https://docs.microsoft.com/en-us/exchange/plan-and-deploy/virtualization?view=exchserver-2019#requirements-for-hardware-virtualization
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Variables are being used')]
[CmdletBinding(DefaultParameterSetName = "HealthChecker")]
param(
    [Parameter(Mandatory = $false, ParameterSetName = "HealthChecker")]
    [Parameter(Mandatory = $false, ParameterSetName = "MailboxReport")]
    [string]$Server = ($env:COMPUTERNAME),
    [Parameter(Mandatory = $false)]
    [ValidateScript( { -not $_.ToString().EndsWith('\') })][string]$OutputFilePath = ".",
    [Parameter(Mandatory = $false, ParameterSetName = "MailboxReport")]
    [switch]$MailboxReport,
    [Parameter(Mandatory = $false, ParameterSetName = "LoadBalancingReport")]
    [switch]$LoadBalancingReport,
    [Parameter(Mandatory = $false, ParameterSetName = "LoadBalancingReport")]
    [array]$CasServerList = $null,
    [Parameter(Mandatory = $false, ParameterSetName = "LoadBalancingReport")]
    [string]$SiteName = ([string]::Empty),
    [Parameter(Mandatory = $false, ParameterSetName = "HTMLReport")]
    [Parameter(Mandatory = $false, ParameterSetName = "AnalyzeDataOnly")]
    [ValidateScript( { -not $_.ToString().EndsWith('\') })][string]$XMLDirectoryPath = ".",
    [Parameter(Mandatory = $false, ParameterSetName = "HTMLReport")]
    [switch]$BuildHtmlServersReport,
    [Parameter(Mandatory = $false, ParameterSetName = "HTMLReport")]
    [string]$HtmlReportFile = "ExchangeAllServersReport.html",
    [Parameter(Mandatory = $false, ParameterSetName = "DCCoreReport")]
    [switch]$DCCoreRatio,
    [Parameter(Mandatory = $false, ParameterSetName = "AnalyzeDataOnly")]
    [switch]$AnalyzeDataOnly,
    [Parameter(Mandatory = $false)][switch]$SaveDebugLog
)

$scriptVersion = "1.0.0"
$scriptBuildDate = "Today"

$VirtualizationWarning = @"
Virtual Machine detected.  Certain settings about the host hardware cannot be detected from the virtual machine.  Verify on the VM Host that:

    - There is no more than a 1:1 Physical Core to Virtual CPU ratio (no oversubscribing)
    - If Hyper-Threading is enabled do NOT count Hyper-Threaded cores as physical cores
    - Do not oversubscribe memory or use dynamic memory allocation

Although Exchange technically supports up to a 2:1 physical core to vCPU ratio, a 1:1 ratio is strongly recommended for performance reasons.  Certain third party Hyper-Visors such as VMWare have their own guidance.

VMWare recommends a 1:1 ratio.  Their guidance can be found at https://www.vmware.com/files/pdf/Exchange_2013_on_VMware_Best_Practices_Guide.pdf.
Related specifically to VMWare, if you notice you are experiencing packet loss on your VMXNET3 adapter, you may want to review the following article from VMWare:  http://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=2039495.

For further details, please review the virtualization recommendations on Microsoft Docs at the following locations:
Exchange 2013: https://docs.microsoft.com/en-us/exchange/exchange-2013-virtualization-exchange-2013-help#requirements-for-hardware-virtualization.
Exchange 2016/2019: https://docs.microsoft.com/en-us/exchange/plan-and-deploy/virtualization?view=exchserver-2019.

"@

$Script:VerboseEnabled = $false
#this is to set the verbose information to a different color
if ($PSBoundParameters["Verbose"]) {
    #Write verbose output in cyan since we already use yellow for warnings
    $Script:VerboseEnabled = $true
    $VerboseForeground = $Host.PrivateData.VerboseForegroundColor
    $Host.PrivateData.VerboseForegroundColor = "Cyan"
}

. .\Helpers\Class.ps1
. .\Writers\Write-HealthCheckerVersion.ps1
. .\Writers\Write-ResultsToScreen.ps1
. .\extern\Confirm-Administrator.ps1
. .\extern\Confirm-ExchangeShell.ps1
. .\extern\New-LoggerObject.ps1
. .\extern\Write-HostWriter.ps1
. .\extern\Write-ScriptMethodHostWriters.ps1
. .\extern\Write-ScriptMethodVerboseWriter.ps1
. .\extern\Write-VerboseWriter.ps1
. .\Writers\Write-Functions.ps1
. .\DataCollection\extern\Get-AllNicInformation.ps1
. .\DataCollection\extern\Get-AllTlsSettingsFromRegistry.ps1
. .\DataCollection\extern\Get-DotNetDllFileVersions.ps1
. .\DataCollection\extern\Get-ExchangeBuildVersionInformation.ps1
. .\DataCollection\extern\Get-NETFrameworkVersion.ps1
. .\DataCollection\extern\Get-ProcessorInformation.ps1
. .\DataCollection\extern\Get-ServerOperatingSystemVersion.ps1
. .\DataCollection\extern\Get-ServerRebootPending.ps1
. .\DataCollection\extern\Get-ServerType.ps1
. .\DataCollection\extern\Get-Smb1ServerSettings.ps1
. .\DataCollection\extern\Get-TimeZoneInformationRegistrySettings.ps1
. .\DataCollection\extern\Get-WmiObjectHandler.ps1
. .\DataCollection\extern\Invoke-RegistryGetValue.ps1
. .\DataCollection\extern\Invoke-ScriptBlockHandler.ps1
. .\DataCollection\ExchangeInformation\Get-ExchangeApplicationConfigurationFileValidation.ps1
. .\DataCollection\ExchangeInformation\Get-ExchangeAppPoolsInformation.ps1
. .\DataCollection\ExchangeInformation\Get-ExchangeInformation.ps1
. .\DataCollection\ExchangeInformation\Get-ExchangeServerCertificates.ps1
. .\DataCollection\ExchangeInformation\Get-ExchangeServerMaintenanceSate.ps1
. .\DataCollection\ExchangeInformation\Get-ExchangeUpdates.ps1
. .\DataCollection\ExchangeInformation\Get-ExSetupDetails.ps1
. .\DataCollection\ExchangeInformation\Get-HealthCheckerExchangeServer.ps1
. .\DataCollection\ServerInformation\Get-CredentialGuardEnabled.ps1
. .\DataCollection\ServerInformation\Get-HardwareInformation.ps1
. .\DataCollection\ServerInformation\Get-HttpProxySetting.ps1
. .\DataCollection\ServerInformation\Get-LmCompatibilityLevelInformation.ps1
. .\DataCollection\ServerInformation\Get-OperatingSystemInformation.ps1
. .\DataCollection\ServerInformation\Get-PageFileInformation.ps1
. .\DataCollection\ServerInformation\Get-ServerRole.ps1
. .\DataCollection\ServerInformation\Get-VisualCRedistributableVersion.ps1
. .\Analyzer\Add-AnalyzedResultInformation.ps1
. .\Analyzer\New-DisplayResultsGroupingKey.ps1
. .\Analyzer\Start-AnalyzerEngine.ps1
. .\Helpers\Get-CounterSamples.ps1
. .\Helpers\Get-ErrorsThatOccurred.ps1
. .\Helpers\Get-HealthCheckFilesItemsFromLocation.ps1
. .\Helpers\Get-OnlyRecentUniqueServersXmls.ps1
. .\Helpers\Import-MyData.ps1
. .\Helpers\Invoke-CatchActions.ps1
. .\Helpers\Set-ScriptLogFileLocation.ps1
. .\Helpers\Test-RequiresServerFqdn.ps1
. .\Helpers\Test-ScriptVersion.ps1
. .\Features\New-HtmlServerReport.ps1
. .\Features\Get-CasLoadBalancingReport.ps1
. .\Features\Get-ExchangeDcCoreRatio.ps1
. .\Features\Get-MailboxDatabaseAndMailboxStatistics.ps1

Function Main {

    if (-not (Confirm-Administrator) -and
        (-not $AnalyzeDataOnly -and
            -not $BuildHtmlServersReport)) {
        Write-Warning "The script needs to be executed in elevated mode. Start the Exchange Management Shell as an Administrator."
        $Error.Clear()
        Start-Sleep -Seconds 2;
        exit
    }

    $Error.Clear() #Always clear out the errors
    $Script:ErrorsExcludedCount = 0 #this is a way to determine if the only errors occurred were in try catch blocks. If there is a combination of errors in and out, then i will just dump it all out to avoid complex issues.
    $Script:ErrorsExcluded = @()
    $Script:date = (Get-Date)
    $Script:dateTimeStringFormat = $date.ToString("yyyyMMddHHmmss")

    if ($BuildHtmlServersReport) {
        Set-ScriptLogFileLocation -FileName "HealthChecker-HTMLServerReport"
        $files = Get-HealthCheckFilesItemsFromLocation
        $fullPaths = Get-OnlyRecentUniqueServersXMLs $files
        $importData = Import-MyData -FilePaths $fullPaths
        New-HtmlServerReport -AnalyzedHtmlServerValues $importData.HtmlServerValues
        Start-Sleep 2;
        return
    }

    if ((Test-Path $OutputFilePath) -eq $false) {
        Write-Host "Invalid value specified for -OutputFilePath." -ForegroundColor Red
        return
    }

    if ($LoadBalancingReport) {
        Set-ScriptLogFileLocation -FileName "LoadBalancingReport"
        Write-HealthCheckerVersion
        Write-Green("Client Access Load Balancing Report on " + $date)
        Get-CASLoadBalancingReport
        Write-Grey("Output file written to " + $OutputFullPath)
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
        Set-ScriptLogFileLocation -FileName "HealthCheck-MailboxReport" -IncludeServerName $true
        Get-MailboxDatabaseAndMailboxStatistics
        Write-Grey("Output file written to {0}" -f $Script:OutputFullPath)
        return
    }

    if ($AnalyzeDataOnly) {
        Set-ScriptLogFileLocation -FileName "HealthChecker-Analyzer"
        $files = Get-HealthCheckFilesItemsFromLocation
        $fullPaths = Get-OnlyRecentUniqueServersXMLs $files
        $importData = Import-MyData -FilePaths $fullPaths

        $analyzedResults = @()
        foreach ($serverData in $importData) {
            $analyzedServerResults = Start-AnalyzerEngine -HealthServerObject $serverData.HealthCheckerExchangeServer
            Write-ResultsToScreen -ResultsToWrite $analyzedServerResults.DisplayResults
            $analyzedResults += $analyzedServerResults
        }

        New-HtmlServerReport -AnalyzedHtmlServerValues $analyzedResults.HtmlServerValues
        return
    }

    Set-ScriptLogFileLocation -FileName "HealthCheck" -IncludeServerName $true
    Test-RequiresServerFqdn
    Write-HealthCheckerVersion
    [HealthChecker.HealthCheckerExchangeServer]$HealthObject = Get-HealthCheckerExchangeServer
    $analyzedResults = Start-AnalyzerEngine -HealthServerObject $HealthObject
    Write-ResultsToScreen -ResultsToWrite $analyzedResults.DisplayResults
    $currentErrors = $Error.Count

    try {
        $analyzedResults | Export-Clixml -Path $OutXmlFullPath -Encoding UTF8 -Depth 6 -ErrorAction SilentlyContinue
    } catch {
        Write-VerboseOutput("Failed to Export-Clixml. Converting HealthCheckerExchangeServer to json")
        $jsonHealthChecker = $analyzedResults.HealthCheckerExchangeServer | ConvertTo-Json

        $testOuputxml = [PSCustomObject]@{
            HealthCheckerExchangeServer = $jsonHealthChecker | ConvertFrom-Json
            HtmlServerValues            = $analyzedResults.HtmlServerValues
            DisplayResults              = $analyzedResults.DisplayResults
        }

        $testOuputxml | Export-Clixml -Path $OutXmlFullPath -Encoding UTF8 -Depth 6 -ErrorAction Stop
    } finally {
        if ($currentErrors -ne $Error.Count) {
            $index = 0
            while ($index -lt ($Error.Count - $currentErrors)) {
                Invoke-CatchActions $Error[$index]
                $index++
            }
        }

        Write-Grey("Output file written to {0}" -f $Script:OutputFullPath)
        Write-Grey("Exported Data Object Written to {0} " -f $Script:OutXmlFullPath)
    }
}

if ($scriptBuildDate -eq "Today") {
    Write-Error ("Script isn't built. Do not run source code directly.`r`nIf developer, follow build process.")
    Write-Host("`r`n`r`nDownload Built Script: https://aka.ms/ExHCDownload")
    exit
}

try {
    $Script:Logger = New-LoggerObject -LogName "HealthChecker-Debug" -LogDirectory $OutputFilePath -VerboseEnabled $Script:VerboseEnabled -EnableDateTime $false -ErrorAction SilentlyContinue
    Main
} finally {
    Get-ErrorsThatOccurred
    if ($Script:VerboseEnabled) {
        $Host.PrivateData.VerboseForegroundColor = $VerboseForeground
    }
    $Script:Logger.RemoveLatestLogFile()
    if ($Script:Logger.PreventLogCleanup) {
        Write-Host("Output Debug file written to {0}" -f $Script:Logger.FullPath)
    }
}