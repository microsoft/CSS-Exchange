# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Find HttpProxy protocol activity for one or more users.
.DESCRIPTION
    When an Exchange client experiences issues, the HttpProxy logs are often the starting
    point for determining whether the issue is with the client, the network, or the server.
    However, since an Exchange environment may have dozens of front-end servers, it can be
    difficult to find the relevant logs for a given user.

    This script is designed to search the logs of all Exchange servers in parallel to quickly
    find the HttpProxy logs related to specified users.

    The default mode of the script is intended for finding slow MAPI calls from Outlook
    clients. The -Protocol switch can be used to search more protocols, while specifying
    -LatencyThreshold allows the admin to filter more aggressively or remove the
    latency filter entirely. Running in -Quiet mode skips the filtering and just reports
    any servers that have the specified users in the HttpProxy logs for the specified
    protocols. See the parameters and examples for more information.
.PARAMETER ServerName
    The name of one or more Exchange servers to search. An easy way to search all Exchange
    servers in the forest is to simply pipe Get-ExchangeServer to the script.
.PARAMETER SamAccountName
    The samAccountNames of one or more users to search for.
.PARAMETER LatencyThreshold
    The minimum latency (in milliseconds) to search for. This is useful for filtering out
    noise from the logs. (Default: 1000). This parameter has no effect when -Quiet is used.
.PARAMETER Protocol
    The protocols to search. Valid values are: Autodiscover, EAS, ECP, EWS, MAPI, OWA, PowerShell,
    RpcHttp. (Default: MAPI)
.PARAMETER IncludeNonExecutes
    By default, only Executes from the MAPI logs are included. This filters out things like
    NotificationWait, which are slow by design. This also filters out all NSPI calls.
    Specify this switch to include them.
.PARAMETER Quiet
    This switch causes the script to only report the server names rather than the full log
    entries. This may be somewhat faster. However, there is no filtering for LatencyThreshold
    and NotificationWait when this option is used.
.PARAMETER TimeSpan
    Specify how far back to search the logs. This is a TimeSpan value, such as "01:00" for the
    last hour or "00:30" for the last 30 minutes. (Default: 15 minutes). Use this parameter to
    search the most recent logs. Use StartTime and EndTime to search older logs.
.PARAMETER StartTime
    Logs older than this time are not searched. This is a DateTime value, such as (Get-Date).AddDays(-1)
    or "2023-02-11 08:00". Use this parameter to search old logs. Use -TimeSpan to search the
    most recent logs.
.PARAMETER EndTime
    Logs newer than this time are not searched. This is a DateTime value, such as (Get-Date).AddDays(-1)
    or "2023-02-11 09:00". Use this parameter to search old logs. Use -TimeSpan to search the
    most recent logs.
.LINK
    https://aka.ms/FindFrontEndActivity
.EXAMPLE
    Get-ExchangeServer | .\FindFrontEndActivity.ps1 -SamAccountName "user1", "user2" | ft
    Show any MAPI HttpProxy activity that took more than 1 second for user1 or user2 within the last 15 minutes on all Exchange servers in the forest.
.EXAMPLE
    Get-ExchangeServer | .\FindFrontEndActivity.ps1 -SamAccountName "user1", "user2" -Quiet
    Show only the server names where user1 or user2 are found in the MAPI HttpProxy logs within the last 15 minutes.
.EXAMPLE
    Get-ExchangeServer | .\FindFrontEndActivity.ps1 -SamAccountName "user1", "user2" -Protocol "ews", "mapi" -LatencyThreshold 100 -TimeSpan "00:30"
    Show any EWS or MAPI HttpProxy activity that took more than 100 milliseconds for user1 or user2 within the last 30 minutes on all Exchange servers in the forest.
#>
[CmdletBinding(DefaultParameterSetName = 'Recent')]
param (
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [Alias('Fqdn')]
    [string[]]
    $ServerName,

    [Parameter(Mandatory = $true)]
    [ValidateScript({ $_ -notmatch "[\[\]:;\|=\+\*\?<>/\\]" })]
    [string[]]
    $SamAccountName,

    [Parameter()]
    [int]
    $LatencyThreshold = 1000,

    [Parameter()]
    [ValidateSet('Autodiscover', 'EAS', 'ECP', 'EWS', 'MAPI', 'OWA', 'PowerShell', 'RpcHttp')]
    [string[]]
    $Protocol = @('MAPI'),

    [Parameter()]
    [switch]
    $IncludeNonExecutes,

    [Parameter()]
    [switch]
    $Quiet,

    [Parameter(ParameterSetName = 'Recent')]
    [TimeSpan]
    $TimeSpan = (New-TimeSpan -Minutes 15),

    [Parameter(ParameterSetName = 'Range', Mandatory = $true)]
    [DateTime]
    $StartTime,

    [Parameter(ParameterSetName = 'Range', Mandatory = $true)]
    [DateTime]
    $EndTime
)

begin {
    . $PSScriptRoot\..\Shared\Confirm-Administrator.ps1

    if (-not (Confirm-Administrator)) {
        Write-Host "This script must be run as an Administrator."
        exit
    }

    $serverNames = New-Object System.Collections.ArrayList
    $escapedSamAccountNames = $SamAccountName | ForEach-Object { [Regex]::Escape($_) }
    $samAccountRegexForFileMatch = [string]::Join('|', ($escapedSamAccountNames | ForEach-Object { "\\$_," }))
    $samAccountRegexForFieldMatch = [string]::Join('|', ($escapedSamAccountNames | ForEach-Object { "\\$_$" }))
}

process {
    foreach ($name in $ServerName) {
        [void]$serverNames.Add($name)
    }
}

end {
    $timeThreshold = $null
    if ($PSCmdlet.ParameterSetName -eq 'Recent') {
        $timeThreshold = (Get-Date).Add(-$TimeSpan)
    }

    $jobs = $serverNames | ForEach-Object {
        Invoke-Command -AsJob -ComputerName $_ -ScriptBlock {
            $exchangeInstallPath = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction SilentlyContinue).MsiInstallPath
            $httpProxyLogPath = Join-Path $exchangeInstallPath "Logging\HttpProxy"
            $results = New-Object System.Collections.ArrayList
            foreach ($thisProtocol in $using:Protocol) {
                $logPathForThisProtocol = Join-Path $httpProxyLogPath $thisProtocol
                if (-not (Test-Path $logPathForThisProtocol)) {
                    continue
                }

                $files = Get-ChildItem "$logPathForThisProtocol\*.log" | Where-Object {
                    if ($null -ne $using:timeThreshold) {
                        $_.LastWriteTime -gt $using:timeThreshold
                    } else {
                        $_.LastWriteTime -gt $using:StartTime -and $_.LastWriteTime -lt $using:EndTime
                    }
                } | Sort-Object LastWriteTime

                $files = @($files | Where-Object { Select-String $using:samAccountRegexForFileMatch $_.FullName -Quiet })

                if ($files.Count -gt 0) {
                    if ($using:Quiet) {
                        return $env:COMPUTERNAME
                    } else {
                        $files | ForEach-Object {
                            $relevantEntries = Import-Csv -Path $_ | Where-Object {
                                $_.AuthenticatedUser -match $using:samAccountRegexForFieldMatch -and [int]::Parse($_.TotalRequestTime) -gt $using:LatencyThreshold
                            }

                            if ($thisProtocol -eq "MAPI" -and -not $using:IncludeNonExecutes) {
                                $relevantEntries = $relevantEntries | Where-Object { $_.ClientRequestId -like "*Execute*" }
                            }

                            $relevantEntries | ForEach-Object { [void]$results.Add($_) }
                        }
                    }
                }
            }

            return $results
        }
    }

    $total = $jobs.Count
    $completed = 0
    $results = New-Object System.Collections.ArrayList
    $jobs | ForEach-Object {
        $location = $_.Location
        Write-Progress -Activity "Processing jobs" -Status "Waiting for $location" -PercentComplete (($completed / $total) * 100)
        try {
            $jobResult = Receive-Job $_ -Wait -AutoRemoveJob -ErrorAction Stop
            if ($null -ne $jobResult -and $jobResult.GetType().Name -eq "string") {
                $jobResult
            } else {
                $jobResult | ForEach-Object { [void]$results.Add(($_ | Select-Object -ExcludeProperty PSComputerName -Property *)) }
            }
        } catch {
            Write-Warning "Failed to process job for $location. Error: $_"
        }
    }

    if ($Quiet) {
        $results | Sort-Object
    } else {
        if ($null -eq (Get-TypeData "CSSExchange.FrontEndActivity")) {
            Update-TypeData -TypeName "CSSExchange.FrontEndActivity" -DefaultDisplayPropertySet "DateTime", "AuthenticatedUser", "UrlStem", "ServerHostName", "TargetServer", "TotalRequestTime"
        }

        $results | ForEach-Object {
            $_.PSObject.TypeNames.Insert(0, 'CSSExchange.FrontEndActivity')
            $_
        } | Sort-Object DateTime
    }
}
