﻿# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Value is used')]
[CmdletBinding(DefaultParameterSetName = "LogAge")]
param (
    [string]$FilePath = "C:\MS_Logs_Collection",
    [array]$Servers = @($env:COMPUTERNAME),
    [switch]$ADDriverLogs,
    [bool]$AppSysLogs = $true,
    [bool]$AppSysLogsToXml = $true,
    [switch]$AutoDLogs,
    [switch]$CollectFailoverMetrics,
    [switch]$DAGInformation,
    [switch]$DailyPerformanceLogs,
    [switch]$DefaultTransportLogging,
    [switch]$EASLogs,
    [switch]$ECPLogs,
    [switch]$EWSLogs,
    [Alias("ExchangeServerInfo")]
    [switch]$ExchangeServerInformation,
    [switch]$Exmon,
    [switch]$Experfwiz,
    [switch]$FrontEndConnectivityLogs,
    [switch]$FrontEndProtocolLogs,
    [switch]$GetVdirs,
    [switch]$HighAvailabilityLogs,
    [switch]$HubConnectivityLogs,
    [switch]$HubProtocolLogs,
    [switch]$IISLogs,
    [switch]$ImapLogs,
    [switch]$MailboxAssistantsLogs,
    [switch]$MailboxConnectivityLogs,
    [switch]$MailboxDeliveryThrottlingLogs,
    [switch]$MailboxProtocolLogs,
    [Alias("ManagedAvailability")]
    [switch]$ManagedAvailabilityLogs,
    [switch]$MapiLogs,
    [switch]$MessageTrackingLogs,
    [switch]$MitigationService,
    [switch]$OABLogs,
    [switch]$OrganizationConfig,
    [switch]$OWALogs,
    [switch]$PopLogs,
    [switch]$PowerShellLogs,
    [switch]$QueueInformation,
    [switch]$ReceiveConnectors,
    [switch]$RPCLogs,
    [switch]$SearchLogs,
    [switch]$SendConnectors,
    [Alias("ServerInfo")]
    [switch]$ServerInformation,
    [switch]$TransportAgentLogs,
    [switch]$TransportConfig,
    [switch]$TransportRoutingTableLogs,
    [switch]$WindowsSecurityLogs,
    [switch]$AcceptEULA,
    [switch]$AllPossibleLogs,
    [Alias("CollectAllLogsBasedOnDaysWorth")]
    [bool]$CollectAllLogsBasedOnLogAge = $true,
    [switch]$ConnectivityLogs,
    [switch]$DatabaseFailoverIssue,
    [Parameter(ParameterSetName = "Worth")]
    [int]$DaysWorth = 3,
    [Parameter(ParameterSetName = "Worth")]
    [int]$HoursWorth = 0,
    [switch]$DisableConfigImport,
    [string]$ExmonLogmanName = "Exmon_Trace",
    [array]$ExperfwizLogmanName = @("Exchange_Perfwiz", "ExPerfwiz", "SimplePerf"),
    [Parameter(ParameterSetName = "LogAge")]
    [timespan]$LogAge = "3.00:00:00",
    [switch]$OutlookConnectivityIssues,
    [switch]$PerformanceIssues,
    [switch]$PerformanceMailflowIssues,
    [switch]$ProtocolLogs,
    [switch]$ScriptDebug,
    [bool]$SkipEndCopyOver
)

$BuildVersion = ""

if ($PSBoundParameters["Verbose"]) { $Script:ScriptDebug = $true }

if ($PSCmdlet.ParameterSetName -eq "Worth") { $Script:LogAge = New-TimeSpan -Days $DaysWorth -Hours $HoursWorth }

function Invoke-RemoteFunctions {
    param(
        [Parameter(Mandatory = $true)][object]$PassedInfo
    )

    . $PSScriptRoot\..\..\Shared\OutputOverrides\Write-Host.ps1
    . $PSScriptRoot\..\..\Shared\OutputOverrides\Write-Verbose.ps1
    . $PSScriptRoot\..\..\Shared\LoggerFunctions.ps1
    . $PSScriptRoot\..\..\Shared\ErrorMonitorFunctions.ps1
    . $PSScriptRoot\RemoteScriptBlock\Get-ExchangeInstallDirectory.ps1
    . $PSScriptRoot\RemoteScriptBlock\Invoke-ZipFolder.ps1
    . $PSScriptRoot\RemoteScriptBlock\IO\WriteFunctions.ps1
    . $PSScriptRoot\RemoteScriptBlock\Invoke-RemoteMain.ps1

    try {

        if ($PassedInfo.ByPass -ne $true) {
            $Script:RootCopyToDirectory = "{0}{1}" -f $PassedInfo.RootFilePath, $env:COMPUTERNAME
            $Script:Logger = Get-NewLoggerInstance -LogName "ExchangeLogCollector-Instance-Debug" -LogDirectory $Script:RootCopyToDirectory
            SetWriteHostManipulateObjectAction ${Function:Get-ManipulateWriteHostValue}
            SetWriteVerboseManipulateMessageAction ${Function:Get-ManipulateWriteVerboseValue}
            SetWriteHostAction ${Function:Write-DebugLog}
            SetWriteVerboseAction ${Function:Write-DebugLog}

            if ($PassedInfo.ScriptDebug) {
                $Script:VerbosePreference = "Continue"
            }

            Write-Verbose("Root Copy To Directory: $Script:RootCopyToDirectory")
            Invoke-RemoteMain
        } else {
            Write-Verbose("Loading common functions")
        }
    } catch {
        Write-Host "An error occurred in Invoke-RemoteFunctions" -ForegroundColor "Red"
        Invoke-CatchActions
        #This is a bad place to catch the error that just occurred
        #Being that there is a try catch block around each command that we run now, we should never hit an issue here unless it is is prior to that.
        Write-Verbose "Critical Failure occurred."
    } finally {
        Write-Verbose("Exiting: Invoke-RemoteFunctions")
        Write-Verbose("[double]TotalBytesSizeCopied: {0} | [double]TotalBytesSizeCompressed: {1} | [double]AdditionalFreeSpaceCushionGB: {2} | [double]CurrentFreeSpaceGB: {3} | [double]FreeSpaceMinusCopiedAndCompressedGB: {4}" -f $Script:TotalBytesSizeCopied,
            $Script:TotalBytesSizeCompressed,
            $Script:AdditionalFreeSpaceCushionGB,
            $Script:CurrentFreeSpaceGB,
            $Script:FreeSpaceMinusCopiedAndCompressedGB)
    }
}

# Need to dot load the files outside of the remote functions after them to avoid issues with encapsulation
. $PSScriptRoot\..\..\Shared\Confirm-Administrator.ps1
. $PSScriptRoot\..\..\Shared\Confirm-ExchangeShell.ps1
. $PSScriptRoot\Write\Write-DataOnlyOnceOnMasterServer.ps1
. $PSScriptRoot\Write\Write-LargeDataObjectsOnMachine.ps1
. $PSScriptRoot\Helpers\Enter-YesNoLoopAction.ps1
. $PSScriptRoot\Helpers\Get-ArgumentList.ps1
. $PSScriptRoot\Helpers\Import-ScriptConfigFile.ps1
. $PSScriptRoot\Helpers\Invoke-ServerRootZipAndCopy.ps1
. $PSScriptRoot\Helpers\Test-DiskSpace.ps1
. $PSScriptRoot\Helpers\Test-NoSwitchesProvided.ps1
. $PSScriptRoot\Helpers\Test-PossibleCommonScenarios.ps1
. $PSScriptRoot\Helpers\Test-RemoteExecutionOfServers.ps1

function Main {

    Start-Sleep 1
    Test-PossibleCommonScenarios
    Test-NoSwitchesProvided

    $display = @"

        Exchange Log Collector v{0}

        THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
        BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
        NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
        DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
        OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

        -This script will copy over data based off the switches provided.
        -We will check for at least {1} GB of free space at the local target directory BEFORE
            attempting to do the remote execution. It will continue to check to make sure that we have
            at least {2} GB of free space throughout the data collection. If some data is determined
            that if we were to copy it over it would place us over that threshold, we will not copy that
            data set over. The script will continue to run while still constantly check the free space
            available before doing a copy action.
        -Please run this script at your own risk.

"@ -f $BuildVersion, ($Script:StandardFreeSpaceInGBCheckSize = 10), $Script:StandardFreeSpaceInGBCheckSize

    Clear-Host
    Write-Host $display

    if (-not($AcceptEULA)) {
        Enter-YesNoLoopAction -Question "Do you wish to continue? " -YesAction {} -NoAction { exit }
    }

    if (-not (Confirm-Administrator)) {
        Write-Host "Hey! The script needs to be executed in elevated mode. Start the Exchange Management Shell as an Administrator." -ForegroundColor "Yellow"
        exit
    }

    $Script:LocalExchangeShell = Confirm-ExchangeShell -Identity $env:COMPUTERNAME

    if (!($Script:LocalExchangeShell.ShellLoaded)) {
        Write-Host "It appears that you are not on an Exchange 2010 or newer server. Sorry I am going to quit."
        exit
    }

    if (!$Script:LocalExchangeShell.RemoteShell) {
        $Script:localExInstall = Get-ExchangeInstallDirectory
    }

    if ($Script:LocalExchangeShell.EdgeServer) {
        #If we are on an Exchange Edge Server, we are going to treat it like a single server on purpose as we recommend that the Edge Server is a non domain joined computer.
        #Because it isn't a domain joined computer, we can't use remote execution
        Write-Host "Determined that we are on an Edge Server, we can only use locally collection for this role." -ForegroundColor "Yellow"
        $Script:EdgeRoleDetected = $true
        $Servers = @($env:COMPUTERNAME)
    }

    if ($null -ne $Servers -and
        !($Servers.Count -eq 1 -and
            $Servers[0].ToUpper().Equals($env:COMPUTERNAME.ToUpper()))) {
        [array]$Script:ValidServers = Test-RemoteExecutionOfServers -ServerList $Servers
    } else {
        [array]$Script:ValidServers = $Servers
    }

    #possible to return null or only a single server back (localhost)
    if (!($null -ne $Script:ValidServers -and
            $Script:ValidServers.Count -eq 1 -and
            $Script:ValidServers[0].ToUpper().Equals($env:COMPUTERNAME.ToUpper()))) {

        $Script:ArgumentList = Get-ArgumentList -Servers $Script:ValidServers
        #I can do a try catch here, but i also need to do a try catch in the remote so i don't end up failing here and assume the wrong failure location
        try {
            Invoke-Command -ComputerName $Script:ValidServers -ScriptBlock ${Function:Invoke-RemoteFunctions} -ArgumentList $argumentList -ErrorAction Stop
        } catch {
            Write-Error "An error has occurred attempting to call Invoke-Command to do a remote collect all at once. Please notify ExToolsFeedback@microsoft.com of this issue. Stopping the script."
            Invoke-CatchActions
            exit
        }

        Write-DataOnlyOnceOnMasterServer
        Write-LargeDataObjectsOnMachine
        Invoke-ServerRootZipAndCopy
    } else {

        if ($null -eq (Test-DiskSpace -Servers $env:COMPUTERNAME -Path $FilePath -CheckSize $Script:StandardFreeSpaceInGBCheckSize)) {
            Write-Host "Failed to have enough space available locally. We can't continue with the data collection" -ForegroundColor "Yellow"
            exit
        }
        if (-not($Script:EdgeRoleDetected)) {
            Write-Host "Note: Remote Collection is now possible for Windows Server 2012 and greater on the remote machine. Just use the -Servers parameter with a list of Exchange Server names" -ForegroundColor "Yellow"
            Write-Host "Going to collect the data locally"
        }
        $Script:ArgumentList = (Get-ArgumentList -Servers $env:COMPUTERNAME)
        Invoke-RemoteFunctions -PassedInfo $Script:ArgumentList
        # Don't manipulate the host object when running locally after the Invoke-RemoteFunctions to
        # make it the same as when having multiple servers executing the script against.
        SetWriteHostManipulateObjectAction $null
        Write-DataOnlyOnceOnMasterServer
        Write-LargeDataObjectsOnMachine
        Invoke-ServerRootZipAndCopy -RemoteExecute $false
    }

    Write-Host "`r`n`r`n`r`nLooks like the script is done. If you ran into any issues or have additional feedback, please feel free to reach out ExToolsFeedback@microsoft.com."
}
#Need to do this here otherwise can't find the script path
$configPath = "{0}\{1}.json" -f (Split-Path -Parent $MyInvocation.MyCommand.Path), (Split-Path -Leaf $MyInvocation.MyCommand.Path)

try {
    <#
    Added the ability to call functions from within a bundled function so i don't have to duplicate work.
    Loading the functions into memory by using the '.' allows me to do this,
    providing that the calling of that function doesn't do anything of value when doing this.
    #>
    . Invoke-RemoteFunctions -PassedInfo ([PSCustomObject]@{
            ByPass = $true
        })

    Invoke-ErrorMonitoring

    if ((Test-Path $configPath) -and
        !$DisableConfigImport) {
        try {
            Import-ScriptConfigFile -ScriptConfigFileLocation $configPath
        } catch {
            Write-Host "Failed to load the config file at $configPath. `r`nPlease update the config file to be able to run 'ConvertFrom-Json' against it" -ForegroundColor "Red"
            Invoke-CatchActions
            Enter-YesNoLoopAction -Question "Do you wish to continue?" -YesAction {} -NoAction { exit }
        }
    }
    $Script:RootFilePath = "{0}\{1}\" -f $FilePath, (Get-Date -Format yyyyMd)
    $Script:Logger = Get-NewLoggerInstance -LogName "ExchangeLogCollector-Main-Debug" -LogDirectory ("$RootFilePath$env:COMPUTERNAME")
    SetWriteVerboseAction ${Function:Write-DebugLog}
    SetWriteHostAction ${Function:Write-DebugLog}

    Main
} finally {

    if ($Script:VerboseEnabled -or
        ($Error.Count -ne $Script:ErrorsFromStartOfCopy)) {
        #$Script:Logger.RemoveLatestLogFile()
    }
}
