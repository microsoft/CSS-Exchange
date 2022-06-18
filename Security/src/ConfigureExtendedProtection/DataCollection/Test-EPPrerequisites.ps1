# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\Test-LatestSUInstalled.ps1

# This function validates if there are any old servers present in the organization
function Test-EPPrerequisites {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    Write-Verbose ("Checking if any Ex2013 or older servers are present in the setup")

    # Exchange 2013 or older currently don't fully support Extended Protection and will break some Mailbox access scenarios
    try {
        $UnSupportedExchangeServers = $ExchangeServers | Where-Object { -not($_.AdminDisplayVersion -like "Version 15*") -and $_.ServerRole -like "*ClientAccess*" }
        $ClientAccessExchangeServers = $ExchangeServers | Where-Object { $_.AdminDisplayVersion -like "Version 15*" }

        foreach ($server in $ClientAccessExchangeServers) {
            $ProductVersion = $server.AdminDisplayVersion.ToString()
            $minor = [int]$ProductVersion.Substring(($ProductVersion.IndexOf(" ")) + 4, 1)
            $start = $ProductVersion.LastIndexOf(" ") + 1
            $build = [int]$ProductVersion.Substring($start, ($ProductVersion.LastIndexOf(".") - $start))

            if (($minor -eq 2 -and $build -ge 1118) -or ($minor -eq 1 -and $build -ge 2507)) {
                continue
            } elseif (($minor -eq 2 -and $build -lt 986) -or ($minor -eq 1 -and $build -lt 2375)) {
                $UnSupportedExchangeServers.Add($server)
            } elseif (Test-LatestSUInstalled -Server $server -Version $minor) {
                $UnSupportedExchangeServers.Add($server)
            }
        }
    } catch {
        throw
    }

    if ($UnSupportedExchangeServers.Count -eq 0) {
        Write-Verbose ("No Ex2013 or old servers detected in the setup")
    } else {
        # Admins have option to bypass the prerequisite check. However, it is strongly NOT RECOMMENDED as it can cause some mailbox access issues.
        if ($SkipEx2013OrOlderServers) {
            # Remove all the Ex2013 and older servers from the Exchange Server list
            Write-Verbose ("Skipping {0}" -f $UnSupportedExchangeServers)
            $ExchangeServers = $ExchangeServers | Where-Object { $_ -notin $UnSupportedExchangeServers }
        } else {
            Write-Host ("Older Exchange Servers detected. Enabling EPA on older servers can potentially regress mailbox operations. Please proceed with caution.")

            if (-not($PSCmdlet.ShouldProcess($UnSupportedExchangeServers, "ConfigureExtendedProtection"))) {
                exit
            }
        }
    }

    return
}
