# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Value is used')]
[CmdletBinding()]
Param (
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
    [switch]$TransportConfig,
    [switch]$WindowsSecurityLogs,
    [switch]$AcceptEULA,
    [switch]$AllPossibleLogs,
    [bool]$CollectAllLogsBasedOnDaysWorth = $true,
    [switch]$DatabaseFailoverIssue,
    [int]$DaysWorth = 3,
    [switch]$DisableConfigImport,
    [string]$ExmonLogmanName = "Exmon_Trace",
    [array]$ExperfwizLogmanName = @("Exchange_Perfwiz", "ExPerfwiz"),
    [switch]$ConnectivityLogs,
    [switch]$OutlookConnectivityIssues,
    [switch]$PerformanceIssues,
    [switch]$PerformanceMailflowIssues,
    [switch]$ProtocolLogs,
    [switch]$ScriptDebug,
    [bool]$SkipEndCopyOver
)

$BuildVersion = ""

$Script:VerboseEnabled = $false

if ($PSBoundParameters["Verbose"]) { $Script:VerboseEnabled = $true }

. $PSScriptRoot\..\..\Shared\Confirm-Administrator.ps1
. $PSScriptRoot\..\..\Shared\Confirm-ExchangeShell.ps1
. .\extern\Enter-YesNoLoopAction.ps1
. .\extern\Import-ScriptConfigFile.ps1
. .\extern\Start-JobManager.ps1
. .\ExchangeServerInfo\Get-DAGInformation.ps1
. .\ExchangeServerInfo\Get-ExchangeBasicServerObject.ps1
. .\ExchangeServerInfo\Get-ServerObjects.ps1
. .\ExchangeServerInfo\Get-TransportLoggingInformationPerServer.ps1
. .\ExchangeServerInfo\Get-VirtualDirectoriesLdap.ps1
. .\Write\Get-WritersToAddToScriptBlock.ps1
. .\Write\Write-DataOnlyOnceOnMasterServer.ps1
. .\Write\Write-LargeDataObjectsOnMachine.ps1
. .\Helpers\Get-ArgumentList.ps1
. .\Helpers\Invoke-ServerRootZipAndCopy.ps1
. .\Helpers\Test-DiskSpace.ps1
. .\Helpers\Test-NoSwitchesProvided.ps1
. .\Helpers\Test-PossibleCommonScenarios.ps1
. .\Helpers\Test-RemoteExecutionOfServers.ps1

Function Invoke-RemoteFunctions {
    param(
        [Parameter(Mandatory = $true)][object]$PassedInfo
    )

    . .\RemoteScriptBlock\extern\Compress-Folder.ps1
    . .\RemoteScriptBlock\extern\Get-ClusterNodeFileVersions.ps1
    . .\RemoteScriptBlock\extern\Get-ExchangeInstallDirectory.ps1
    . .\RemoteScriptBlock\extern\Get-FreeSpace.ps1
    . .\RemoteScriptBlock\extern\New-Folder.ps1
    . $PSScriptRoot\..\..\Shared\New-LoggerObject.ps1
    . .\RemoteScriptBlock\extern\Save-DataToFile.ps1
    . $PSScriptRoot\..\..\Shared\Write-HostWriter.ps1
    . .\RemoteScriptBlock\extern\Write-InvokeCommandReturnHostWriter.ps1
    . .\RemoteScriptBlock\extern\Write-InvokeCommandReturnVerboseWriter.ps1
    . .\RemoteScriptBlock\extern\Write-ScriptMethodHostWriter.ps1
    . $PSScriptRoot\..\..\Shared\Write-ScriptMethodVerboseWriter.ps1
    . $PSScriptRoot\..\..\Shared\Write-VerboseWriter.ps1
    . .\RemoteScriptBlock\Add-ServerNameToFileName.ps1
    . .\RemoteScriptBlock\Get-ItemsSize.ps1
    . .\RemoteScriptBlock\Get-StringDataForNotEnoughFreeSpace.ps1
    . .\RemoteScriptBlock\Get-IISLogDirectory.ps1
    . .\RemoteScriptBlock\Test-CommandExists.ps1
    . .\RemoteScriptBlock\Test-FreeSpace.ps1
    . .\RemoteScriptBlock\Invoke-ZipFolder.ps1
    . .\RemoteScriptBlock\IO\Copy-BulkItems.ps1
    . .\RemoteScriptBlock\IO\Copy-FullLogFullPathRecurse.ps1
    . .\RemoteScriptBlock\IO\Copy-LogmanData.ps1
    . .\RemoteScriptBlock\IO\Copy-LogsBasedOnTime.ps1
    . .\RemoteScriptBlock\IO\Invoke-CatchBlockActions.ps1
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
            $Script:Logger = New-LoggerObject -LogDirectory $Script:RootCopyToDirectory -LogName ("ExchangeLogCollector-Instance-Debug") `
                -HostFunctionCaller $Script:HostFunctionCaller `
                -VerboseFunctionCaller $Script:VerboseFunctionCaller
            Write-ScriptDebug("Root Copy To Directory: $Script:RootCopyToDirectory")
            Invoke-RemoteMain
        } else {
            Write-ScriptDebug("Loading common functions")
        }
    } catch {
        Write-ScriptHost -WriteString ("An error occurred in Invoke-RemoteFunctions") -ForegroundColor "Red"
        Invoke-CatchBlockActions
        #This is a bad place to catch the error that just occurred
        #Being that there is a try catch block around each command that we run now, we should never hit an issue here unless it is is prior to that.
        Write-ScriptDebug "Critical Failure occurred."
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
    Write-ScriptHost -WriteString $display -ShowServer $false

    if (-not($AcceptEULA)) {
        Enter-YesNoLoopAction -Question "Do you wish to continue? " -YesAction {} -NoAction { exit }
    }

    if (-not (Confirm-Administrator)) {
        Write-ScriptHost -WriteString ("Hey! The script needs to be executed in elevated mode. Start the Exchange Management Shell as an Administrator.") -ForegroundColor "Yellow"
        exit
    }

    $Script:LocalExchangeShell = Confirm-ExchangeShell -Identity $env:COMPUTERNAME

    if (!($Script:LocalExchangeShell.ShellLoaded)) {
        Write-ScriptHost -WriteString ("It appears that you are not on an Exchange 2010 or newer server. Sorry I am going to quit.") -ShowServer $false
        exit
    }

    if (!$Script:LocalExchangeShell.RemoteShell) {
        $Script:localExInstall = Get-ExchangeInstallDirectory
    }

    if ($Script:LocalExchangeShell.EdgeServer) {
        #If we are on an Exchange Edge Server, we are going to treat it like a single server on purpose as we recommend that the Edge Server is a non domain joined computer.
        #Because it isn't a domain joined computer, we can't use remote execution
        Write-ScriptHost -WriteString ("Determined that we are on an Edge Server, we can only use locally collection for this role.") -ForegroundColor "Yellow"
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
            Invoke-CatchBlockActions
            exit
        }

        Write-DataOnlyOnceOnMasterServer
        Write-LargeDataObjectsOnMachine
        Invoke-ServerRootZipAndCopy
    } else {

        if ($null -eq (Test-DiskSpace -Servers $env:COMPUTERNAME -Path $FilePath -CheckSize $Script:StandardFreeSpaceInGBCheckSize)) {
            Write-ScriptHost -ShowServer $false -WriteString ("Failed to have enough space available locally. We can't continue with the data collection") -ForegroundColor "Yellow"
            exit
        }
        if (-not($Script:EdgeRoleDetected)) {
            Write-ScriptHost -ShowServer $false -WriteString ("Note: Remote Collection is now possible for Windows Server 2012 and greater on the remote machine. Just use the -Servers paramater with a list of Exchange Server names") -ForegroundColor "Yellow"
            Write-ScriptHost -ShowServer $false -WriteString ("Going to collect the data locally")
        }
        $Script:ArgumentList = (Get-ArgumentList -Servers $env:COMPUTERNAME)
        Invoke-RemoteFunctions -PassedInfo $Script:ArgumentList
        Write-DataOnlyOnceOnMasterServer
        Write-LargeDataObjectsOnMachine
        Invoke-ServerRootZipAndCopy -RemoteExecute $false
    }

    Write-ScriptHost -WriteString "`r`n`r`n`r`nLooks like the script is done. If you ran into any issues or have additional feedback, please feel free to reach out ExToolsFeedback@microsoft.com." -ShowServer $false
}
#Need to do this here otherwise can't find the script path
$configPath = "{0}\{1}.json" -f (Split-Path -Parent $MyInvocation.MyCommand.Path), (Split-Path -Leaf $MyInvocation.MyCommand.Path)

try {
    $Error.Clear()
    <#
    Added the ability to call functions from within a bundled function so i don't have to duplicate work.
    Loading the functions into memory by using the '.' allows me to do this,
    providing that the calling of that function doesn't do anything of value when doing this.
    #>
    . Invoke-RemoteFunctions -PassedInfo ([PSCustomObject]@{
            ByPass = $true
        })

    if ((Test-Path $configPath) -and
        !$DisableConfigImport) {
        try {
            Import-ScriptConfigFile -ScriptConfigFileLocation $configPath
        } catch {
            Write-ScriptHost "Failed to load the config file at $configPath. `r`nPlease update the config file to be able to run 'ConvertFrom-Json' against it" -ForegroundColor "Red"
            Invoke-CatchBlockActions
            Enter-YesNoLoopAction -Question "Do you wish to continue?" -YesAction {} -NoAction { exit }
        }
    }
    $Script:RootFilePath = "{0}\{1}\" -f $FilePath, (Get-Date -Format yyyyMd)
    $Script:Logger = New-LoggerObject -LogDirectory ("{0}{1}" -f $RootFilePath, $env:COMPUTERNAME) -LogName "ExchangeLogCollector-Main-Debug" `
        -HostFunctionCaller $Script:HostFunctionCaller `
        -VerboseFunctionCaller $Script:VerboseFunctionCaller

    Main
} finally {

    if ($Script:VerboseEnabled -or
        ($Error.Count -ne $Script:ErrorsFromStartOfCopy)) {
        $Script:Logger.RemoveLatestLogFile()
    }
}
