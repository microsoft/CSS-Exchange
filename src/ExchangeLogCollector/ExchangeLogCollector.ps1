<#
.NOTES
    Name: ExchangeLogCollector.ps1
    Author: David Paulson
    Requires: Powershell on an Exchange 2010+ Server with Administrator rights

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
	BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
	NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
	DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
.SYNOPSIS
    Collects the requested logs off the Exchange server based off the switches that are used.
.DESCRIPTION
    Collects the requested logs off the Exchange server based off the switches that are used.
.PARAMETER FilePath
    The Location of where you would like the data to be copied over to
.PARAMETER Servers
    An array of servers that you would like to collect data from.
.PARAMETER EWSLogs
    Will collect the EWS logs from the Exchange Server
.PARAMETER IISLogs
    Will Collect the IIS Logs from the Exchange Server
.PARAMETER DailyPerformanceLogs
    Used to collect Exchange 2013+ Daily Performance Logs
.PARAMETER ManagedAvailability
    Used to collect managed Availability Logs from the Exchange 2013+ Server
.PARAMETER Experfwiz
    Used to collect Experfwiz data from the server
.PARAMETER RPCLogs
    Used to collect the PRC Logs from the server
.PARAMETER EASLogs
    Used to collect the Exchange Active Sync Proxy Logs
.PARAMETER ECPLogs
    Used to collect the ECP Logs from the Exchange server
.PARAMETER AutoDLogs
    Used to Collect the AutoD Logs from the server
.PARAMETER OWALogs
    Used to collect the OWA Logs from the server
.PARAMETER ADDriverLogs
    Used to collect the AD Driver Logs from the server
.PARAMETER SearchLogs
    Used to collect the Search Logs from the server
.PARAMETER HighAvailabilityLogs
    Used to collect the High Availability Information from the server
.PARAMETER MapiLogs
    Used to collect the Mapi Logs from the server
.PARAMETER MessageTrackingLogs
    Used to collect the Message Tracking Logs from the server
.PARAMETER HubProtocolLogs
    Used to collect the Hub Protocol Logs from the server
.PARAMETER HubConnectivityLogs
    Used to collect the Hub Connectivity Logs from the server
.PARAMETER FrontEndConnectivityLogs
    Used to collect the Front End Connectivity Logs from the server
.PARAMETER FrontEndProtocolLogs
    Used to collect the Front End Protocol Logs from the server
.PARAMETER MailboxConnectivityLogs
    Used to collect the Mailbox Connectivity Logs from the server
.PARAMETER MailboxProtocolLogs
    Used to collect the Mailbox Protocol Logs from the server
.PARAMETER QueueInformationThisServer
    Used to collect the Queue Information from this server
.PARAMETER ReceiveConnectors
    Used to collect the Receive Connector information from this server
.PARAMETER SendConnectors
    Used to collect the Send connector information from the Org
.PARAMETER DAGInformation
    Used to collect the DAG Information for this DAG
.PARAMETER GetVdirs
    Used to collect the Virtual Directories of the environment
.PARAMETER OrganizationConfig
    Used to collect the Organization Configuration from the environment.
.PARAMETER TransportConfig
    Used to collect the Transport Configuration from this Exchange Server
.PARAMETER DefaultTransportLogging
    Used to Get all the default logging that is enabled on the Exchange Server for Transport Information
.PARAMETER Exmon
    Used to Collect the Exmon Information
.PARAMETER ServerInfo
    Used to collect the general Server information from the server
.PARAMETER ExchangeServerInfo
    Used to collect Exchange Server data (Get-ExchangeServer, Get-MailboxServer...). Enabled whenever ServerInfo is used as well.
.PARAMETER PopLogs
    Used to collect the POP protocol logs
.PARAMETER ImapLogs
    Used to collect the IMAP protocol logs
.PARAMETER OABLogs
    Used to collect the OAB logs
.PARAMETER PowerShellLogs
    Used to collect the Exchange PowerShell Logs
.PARAMETER MSInfo
    Old switch that was used for collecting the general Server information
.PARAMETER CollectAllLogsBasedOnDaysWorth
    Used to collect some of the default logging based off Days Worth vs the whole directory
.PARAMETER AppSysLogs
    Used to collect the Application and System Logs. Default is set to true
.PARAMETER AllPossibleLogs
    Switch to enable all default logging enabled on the Exchange server.
.PARAMETER SkipEndCopyOver
    Boolean to prevent the copy over after a remote collection.
.PARAMETER DaysWorth
    To determine how far back we would like to collect data from
.PARAMETER ScriptDebug
    To enable Debug Logging for the script to determine what might be wrong with the script
.PARAMETER DatabaseFailoverIssue
    To enable the common switches to assist with determine the cause of database failover issues
.PARAMETER PerformanceIssues
    To enable the common switches for data collection to assist with determining the cause of a Performance issue.
.PARAMETER PerformanceMailFlowIssues
    To enable the common switches for data collection to assist with determine the cause of a MailFlow Performance Type issue.
.PARAMETER OutlookConnectivityIssues
    To enable the command switches for the data collection to assist with determining outlook connectivity issues that are on the Exchange server.
.PARAMETER ExperfwizLogmanName
    To be able to set the Experfwiz Logman Name that we would be looking for. By Default "Exchange_Perfwiz"
.PARAMETER ExmonLogmanName
    To be able to set the Exmon Logman Name that we would be looking for. By Default "Exmon_Trace"
.PARAMETER AcceptEULA
    Switch used to bypass the disclaimer confirmation
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'All Parameters are used in other functions of the script')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Value is used')]
[CmdletBinding()]
Param (
    [string]$FilePath = "C:\MS_Logs_Collection",
    [Array]$Servers,
    [switch]$EWSLogs,
    [switch]$IISLogs,
    [switch]$DailyPerformanceLogs,
    [switch]$ManagedAvailability,
    [switch]$Experfwiz,
    [switch]$RPCLogs,
    [switch]$EASLogs,
    [switch]$ECPLogs,
    [switch]$AutoDLogs,
    [switch]$OWALogs,
    [switch]$ADDriverLogs,
    [switch]$SearchLogs,
    [switch]$HighAvailabilityLogs,
    [switch]$MapiLogs,
    [switch]$MessageTrackingLogs,
    [switch]$HubProtocolLogs,
    [switch]$HubConnectivityLogs,
    [switch]$FrontEndConnectivityLogs,
    [switch]$FrontEndProtocolLogs,
    [switch]$MailboxConnectivityLogs,
    [switch]$MailboxProtocolLogs,
    [switch]$MailboxDeliveryThrottlingLogs,
    [switch]$QueueInformationThisServer,
    [switch]$ReceiveConnectors,
    [switch]$SendConnectors,
    [switch]$DAGInformation,
    [switch]$GetVdirs,
    [switch]$OrganizationConfig,
    [switch]$TransportConfig,
    [switch]$DefaultTransportLogging,
    [switch]$Exmon,
    [switch]$ServerInfo,
    [switch]$ExchangeServerInfo,
    [switch]$PopLogs,
    [switch]$ImapLogs,
    [switch]$OABLogs,
    [switch]$PowerShellLogs,
    [switch]$WindowsSecurityLogs,
    [bool]$CollectAllLogsBasedOnDaysWorth = $true,
    [Bool]$AppSysLogs = $true,
    [switch]$AllPossibleLogs,
    [bool]$SkipEndCopyOver,
    [int]$DaysWorth = 3,
    [switch]$DatabaseFailoverIssue,
    [switch]$PerformanceIssues,
    [switch]$PerformanceMailflowIssues,
    [switch]$OutlookConnectivityIssues,
    [string]$ExperfwizLogmanName = "Exchange_Perfwiz",
    [string]$ExmonLogmanName = "Exmon_Trace",
    [switch]$AcceptEULA,
    [switch]$ScriptDebug
)

$scriptVersion = "1.0.0"

$Script:VerboseEnabled = $false

if ($PSBoundParameters["Verbose"]) { $Script:VerboseEnabled = $true }

. .\extern\Confirm-Administrator.ps1
. .\extern\Confirm-ExchangeShell.ps1
. .\extern\Enter-YesNoLoopAction.ps1
. .\extern\Start-JobManager.ps1
. .\ExchangeServerInfo\Confirm-LocalEdgeServer.ps1
. .\ExchangeServerInfo\Get-DAGInformation.ps1
. .\ExchangeServerInfo\Get-ExchangeBasicServerObject.ps1
. .\ExchangeServerInfo\Get-ExchangeObjectServerData.ps1
. .\ExchangeServerInfo\Get-ExchangeServerDagName.ps1
. .\ExchangeServerInfo\Get-MailboxDatabaseInformationFromDag.ps1
. .\ExchangeServerInfo\Get-ServerObjects.ps1
. .\ExchangeServerInfo\Get-TransportLoggingInformationPerServer.ps1
. .\ExchangeServerInfo\Get-VirtualDirectoriesLdap.ps1
. .\Write\Get-WritersToAddToScriptBlock.ps1
. .\Write\Start-WriteExchangeDataOnMachine.ps1
. .\Write\Write-DataOnlyOnceOnLocalMachine.ps1
. .\Write\Write-Disclaimer.ps1
. .\Write\Write-ExchangeDataOnMachines.ps1
. .\Write\Write-Feedback.ps1
. .\Get-ArgumentList.ps1
. .\Get-RemoteLogLocation.ps1
. .\Test-DiskSpace.ps1
. .\Test-DiskSpaceForCopyOver.ps1
. .\Test-NoSwitchesProvided.ps1
. .\Test-PossibleCommonScenarios.ps1
. .\Test-RemoteExecutionOfServers.ps1
. .\Test-LocalServerIsUsed.ps1

Function Invoke-RemoteFunctions {
    param(
        [Parameter(Mandatory = $true)][object]$PassedInfo
    )

    . .\RemoteScriptBlock\extern\Compress-Folder.ps1
    . .\RemoteScriptBlock\extern\Get-ClusterNodeFileVersions.ps1
    . .\RemoteScriptBlock\extern\Get-ExchangeInstallDirectory.ps1
    . .\RemoteScriptBlock\extern\Get-FreeSpace.ps1
    . .\RemoteScriptBlock\extern\New-Folder.ps1
    . .\RemoteScriptBlock\extern\New-LoggerObject.ps1
    . .\RemoteScriptBlock\extern\Save-DataToFile.ps1
    . .\RemoteScriptBlock\extern\Write-HostWriter.ps1
    . .\RemoteScriptBlock\extern\Write-InvokeCommandReturnHostWriter.ps1
    . .\RemoteScriptBlock\extern\Write-InvokeCommandReturnVerboseWriter.ps1
    . .\RemoteScriptBlock\extern\Write-ScriptMethodHostWriter.ps1
    . .\RemoteScriptBlock\extern\Write-ScriptMethodVerboseWriter.ps1
    . .\RemoteScriptBlock\extern\Write-VerboseWriter.ps1
    . .\RemoteScriptBlock\Add-ServerNameToFileName.ps1
    . .\RemoteScriptBlock\Get-ItemsSize.ps1
    . .\RemoteScriptBlock\Get-StringDataForNotEnoughFreeSpace.ps1
    . .\RemoteScriptBlock\Get-ThisServerObject.ps1
    . .\RemoteScriptBlock\Set-IISDirectoryInfo.ps1
    . .\RemoteScriptBlock\Set-InstanceRunningVars.ps1
    . .\RemoteScriptBlock\Test-CommandExists.ps1
    . .\RemoteScriptBlock\Test-FreeSpace.ps1
    . .\RemoteScriptBlock\Invoke-ZipFolder.ps1
    . .\RemoteScriptBlock\IO\Copy-BulkItems.ps1
    . .\RemoteScriptBlock\IO\Copy-FullLogFullPathRecurse.ps1
    . .\RemoteScriptBlock\IO\Copy-LogmanData.ps1
    . .\RemoteScriptBlock\IO\Copy-LogsBasedOnTime.ps1
    . .\RemoteScriptBlock\IO\Save-DataInfoToFile.ps1
    . .\RemoteScriptBlock\IO\Save-FailoverClusterInformation.ps1
    . .\RemoteScriptBlock\IO\Save-LogmanExmonData.ps1
    . .\RemoteScriptBlock\IO\Save-LogmanExperfwizData.ps1
    . .\RemoteScriptBlock\IO\Save-ServerInfoData.ps1
    . .\RemoteScriptBlock\IO\Save-WindowsEventLogs.ps1
    . .\RemoteScriptBlock\IO\Write-DebugLog.ps1
    . .\RemoteScriptBlock\IO\Write-ScriptDebug.ps1
    . .\RemoteScriptBlock\IO\Write-ScriptHost.ps1
    . .\RemoteScriptBlock\Logman\Get-LogmanData.ps1
    . .\RemoteScriptBlock\Logman\Get-LogmanExt.ps1
    . .\RemoteScriptBlock\Logman\Get-LogmanObject.ps1
    . .\RemoteScriptBlock\Logman\Get-LogmanRootPath.ps1
    . .\RemoteScriptBlock\Logman\Get-LogmanStartDate.ps1
    . .\RemoteScriptBlock\Logman\Get-LogmanStatus.ps1
    . .\RemoteScriptBlock\Logman\Start-Logman.ps1
    . .\RemoteScriptBlock\Logman\Stop-Logman.ps1
    . .\RemoteScriptBlock\Invoke-RemoteMain.ps1

    try {
        $Script:VerboseFunctionCaller = ${Function:Write-ScriptDebug}
        $Script:HostFunctionCaller = ${Function:Write-ScriptHost}

        if ($PassedInfo.ByPass -ne $true) {
            $Script:RootCopyToDirectory = "{0}{1}" -f $PassedInfo.RootFilePath, $env:COMPUTERNAME
            $Script:Logger = New-LoggerObject -LogDirectory $Script:RootCopyToDirectory -LogName ("ExchangeLogCollector-Instance-Debug")
            Write-ScriptDebug("Root Copy To Directory: $Script:RootCopyToDirectory")
            Invoke-RemoteMain
        } else {
            Write-ScriptDebug("Loading common functions")
        }
    } catch {
        Write-ScriptHost -WriteString ("An error occurred in Invoke-RemoteFunctions") -ForegroundColor "Red"
        Write-ScriptHost -WriteString ("Error Exception: {0}" -f $Error[0].Exception) -ForegroundColor "Red"
        Write-ScriptHost -WriteString ("Error Stack: {0}" -f $Error[0].ScriptStackTrace) -ForegroundColor "Red"
    } finally {
        Write-ScriptDebug("Exiting: Invoke-RemoteFunctions")
        Write-ScriptDebug("[double]TotalBytesSizeCopied: {0} | [double]TotalBytesSizeCompressed: {1} | [double]AdditionalFreeSpaceCushionGB: {2} | [double]CurrentFreeSpaceGB: {3} | [double]FreeSpaceMinusCopiedAndCompressedGB: {4}" -f $Script:TotalBytesSizeCopied,
            $Script:TotalBytesSizeCompressed,
            $Script:AdditionalFreeSpaceCushionGB,
            $Script:CurrentFreeSpaceGB,
            $Script:FreeSpaceMinusCopiedAndCompressedGB)
    }
}

Function Main {

    Start-Sleep 1
    Write-Disclaimer
    Test-PossibleCommonScenarios
    Test-NoSwitchesProvided
    if (-not (Confirm-Administrator)) {
        Write-ScriptHost -WriteString ("Hey! The script needs to be executed in elevated mode. Start the Exchange Management Shell as an Administrator.") -ForegroundColor "Yellow"
        exit
    }

    $Script:LocalExchangeShell = Confirm-ExchangeShell

    if (!($Script:LocalExchangeShell.ShellLoaded)) {
        Write-ScriptHost -WriteString ("It appears that you are not on an Exchange 2010 or newer server. Sorry I am going to quit.") -ShowServer $false
        exit
    }

    if ((Confirm-LocalEdgeServer) -and
        $null -ne $Servers) {
        #If we are on an Exchange Edge Server, we are going to treat it like a single server on purpose as we recommend that the Edge Server is a non domain joined computer.
        #Because it isn't a domain joined computer, we can't use remote execution
        Write-ScriptHost -WriteString ("Determined that we are on an Edge Server, we can only use locally collection for this role.") -ForegroundColor "Yellow"
        $Script:EdgeRoleDetected = $true
        $Servers = $null
    }

    if ($null -ne $Servers) {

        #possible to return null or only a single server back (localhost)
        $Script:ValidServers = Test-RemoteExecutionOfServers -ServerList $Servers
        if ($null -ne $Script:ValidServers) {
            $Script:ValidServers = Test-DiskSpace -Servers $Script:ValidServers -Path $FilePath -CheckSize $Script:StandardFreeSpaceInGBCheckSize
            Test-LocalServerIsUsed $Script:ValidServers

            $argumentList = Get-ArgumentList -Servers $Script:ValidServers
            #I can do a try catch here, but i also need to do a try catch in the remote so i don't end up failing here and assume the wrong failure location
            try {
                Invoke-Command -ComputerName $Script:ValidServers -ScriptBlock ${Function:Invoke-RemoteFunctions} -ArgumentList $argumentList -ErrorAction Stop
            } catch {
                Write-Error "An error has occurred attempting to call Invoke-Command to do a remote collect all at once. Please notify ExToolsFeedback@microsoft.com of this issue. Stopping the script."
                $Script:Logger.WriteVerbose($Error[0])
                exit
            }

            Start-WriteExchangeDataOnMachines
            Write-DataOnlyOnceOnLocalMachine
            #New Logger Instance incase we want the data for the copy.
            $Script:ErrorsFromStartOfCopy = $Error.Count
            $Script:Logger = New-LoggerObject -LogDirectory $Script:RootFilePath -LogName "ExchangeLogCollector-Copy-Debug"
            $LogPaths = Get-RemoteLogLocation -Servers $Script:ValidServers -RootPath $Script:RootFilePath

            if ((-not($SkipEndCopyOver)) -and
                (Test-DiskSpaceForCopyOver -LogPathObject $LogPaths -RootPath $Script:RootFilePath)) {
                Write-ScriptHost -ShowServer $false -WriteString (" ")
                Write-ScriptHost -ShowServer $false -WriteString ("Copying over the data may take some time depending on the network")
                foreach ($svr in $LogPaths) {
                    #Don't want to do the local host
                    if ($svr.ServerName -ne $env:COMPUTERNAME) {
                        $remoteCopyLocation = "\\{0}\{1}" -f $svr.ServerName, ($svr.ZipFolder.Replace(":", "$"))
                        Write-ScriptHost -ShowServer $false -WriteString ("[{0}] : Copying File {1}...." -f $svr.ServerName, $remoteCopyLocation)
                        Copy-Item -Path $remoteCopyLocation -Destination $Script:RootFilePath
                        Write-ScriptHost -ShowServer $false -WriteString ("[{0}] : Done copying file" -f $svr.ServerName)
                    }
                }
            } else {
                Write-ScriptHost -ShowServer $false -WriteString (" ")
                Write-ScriptHost -ShowServer $false -WriteString ("Please collect the following files from these servers and upload them: ")
                foreach ($svr in $LogPaths) {
                    Write-ScriptHost -ShowServer $false -WriteString ("Server: {0} Path: {1}" -f $svr.ServerName, $svr.ZipFolder)
                }
            }
        } else {
            #We have failed to do invoke-command on all the servers.... so we are going to do the same logic locally
            Write-ScriptHost -ShowServer $false -WriteString ("Failed to do remote collection for all the servers in the list...") -ForegroundColor "Yellow"
            #want to test local server's free space first before moving to just collecting the data
            if ($null -eq (Test-DiskSpace -Servers $env:COMPUTERNAME -Path $FilePath -CheckSize $Script:StandardFreeSpaceInGBCheckSize)) {
                Write-ScriptHost -ShowServer $false -WriteString ("Failed to have enough space available locally as well. We can't continue with the data collection") -ForegroundColor "Yellow"
                exit
            }
            if ((Enter-YesNoLoopAction -Question "Do you want to collect from the local server only?" -YesAction { return $true } -NoAction { return $false })) {
                Invoke-RemoteFunctions -PassedInfo (Get-ArgumentList -Servers $env:COMPUTERNAME)
                $Script:ValidServers = @($env:COMPUTERNAME)
                Start-WriteExchangeDataOnMachines
                Write-DataOnlyOnceOnLocalMachine
            }
        }
    } else {

        if ($null -eq (Test-DiskSpace -Servers $env:COMPUTERNAME -Path $FilePath -CheckSize $Script:StandardFreeSpaceInGBCheckSize)) {
            exit
        }
        if (-not($Script:EdgeRoleDetected)) {
            Write-ScriptHost -ShowServer $false -WriteString ("Note: Remote Collection is now possible for Windows Server 2012 and greater on the remote machine. Just use the -Servers paramater with a list of Exchange Server names") -ForegroundColor "Yellow"
            Write-ScriptHost -ShowServer $false -WriteString ("Going to collect the data locally")
        }
        Invoke-RemoteFunctions -PassedInfo (Get-ArgumentList -Servers $env:COMPUTERNAME)
        $Script:ValidServers = @($env:COMPUTERNAME)
        Start-WriteExchangeDataOnMachines
        Write-DataOnlyOnceOnLocalMachine
    }

    Write-FeedBack
}

try {
    <#
    Added the ability to call functions from within a bundled function so i don't have to duplicate work.
    Loading the functions into memory by using the '.' allows me to do this,
    providing that the calling of that function doesn't do anything of value when doing this.
    #>
    $obj = [PSCustomObject]@{
        ByPass = $true
    }
    . Invoke-RemoteFunctions -PassedInfo $obj
    $Script:RootFilePath = "{0}\{1}\" -f $FilePath, (Get-Date -Format yyyyMd)
    $Script:Logger = New-LoggerObject -LogDirectory ("{0}{1}" -f $RootFilePath, $env:COMPUTERNAME) -LogName "ExchangeLogCollector-Main-Debug"
    Main
} finally {

    if ($Script:VerboseEnabled -or
        ($Error.Count -ne $Script:ErrorsFromStartOfCopy)) {
        $Script:Logger.RemoveLatestLogFile()
    }
}
