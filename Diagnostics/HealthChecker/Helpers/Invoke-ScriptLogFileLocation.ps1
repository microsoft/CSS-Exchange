# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\Shared\Confirm-ExchangeShell.ps1
Function Invoke-ScriptLogFileLocation {
    param(
        [Parameter(Mandatory = $true)][string]$FileName,
        [Parameter(Mandatory = $false)][bool]$IncludeServerName = $false
    )
    $endName = "-{0}.txt" -f $dateTimeStringFormat

    if ($IncludeServerName) {
        $endName = "-{0}{1}" -f $Script:Server, $endName
    }

    $Script:OutputFullPath = "{0}\{1}{2}" -f $OutputFilePath, $FileName, $endName
    $Script:OutXmlFullPath = $Script:OutputFullPath.Replace(".txt", ".xml")

    if ($AnalyzeDataOnly -or
        $BuildHtmlServersReport -or
        $ScriptUpdateOnly) {
        return
    }

    $Script:ExchangeShellComputer = Confirm-ExchangeShell -Identity $Script:Server -CatchActionFunction ${Function:Invoke-CatchActions}

    if (!($Script:ExchangeShellComputer.ShellLoaded)) {
        Write-Yellow("Failed to load Exchange Shell... stopping script")
        exit
    }

    if ($Script:ExchangeShellComputer.ToolsOnly -and
        $env:COMPUTERNAME -eq $Script:Server -and
        !($LoadBalancingReport)) {
        Write-Yellow("Can't run Exchange Health Checker Against a Tools Server. Use the -Server Parameter and provide the server you want to run the script against.")
        exit
    }

    Write-Verbose("Script Executing on Server $env:COMPUTERNAME")
    Write-Verbose("ToolsOnly: $($Script:ExchangeShellComputer.ToolsOnly) | RemoteShell $($Script:ExchangeShellComputer.RemoteShell)")
}
