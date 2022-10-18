# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\Shared\Confirm-ExchangeShell.ps1
function Invoke-ScriptLogFileLocation {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $true)]
        [string]$FileName,

        [Parameter(Mandatory = $false)]
        [bool]$IncludeServerName = $false
    )
    $endName = "-{0}.txt" -f $dateTimeStringFormat

    if ($IncludeServerName) {
        $endName = "-{0}{1}" -f $Server, $endName
    }

    $Script:OutputFullPath = "{0}\{1}{2}" -f $OutputFilePath, $FileName, $endName
    $Script:OutXmlFullPath = $Script:OutputFullPath.Replace(".txt", ".xml")

    if ($AnalyzeDataOnly -or
        $BuildHtmlServersReport -or
        $ScriptUpdateOnly) {
        return
    }

    $Script:ExchangeShellComputer = Confirm-ExchangeShell `
        -CatchActionFunction ${Function:Invoke-CatchActions}

    if (!($Script:ExchangeShellComputer.ShellLoaded)) {
        Write-Yellow("Failed to load Exchange Shell... stopping script")
        $Script:Logger.PreventLogCleanup = $true
        exit
    }

    if ($Script:ExchangeShellComputer.ToolsOnly -and
        $env:COMPUTERNAME -eq $Server -and
        !($LoadBalancingReport)) {
        Write-Yellow("Can't run Exchange Health Checker Against a Tools Server. Use the -Server Parameter and provide the server you want to run the script against.")
        $Script:Logger.PreventLogCleanup = $true
        exit
    }

    Write-Verbose("Script Executing on Server $env:COMPUTERNAME")
    Write-Verbose("ToolsOnly: $($Script:ExchangeShellComputer.ToolsOnly) | RemoteShell $($Script:ExchangeShellComputer.RemoteShell)")
}
