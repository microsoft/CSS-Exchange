# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
    Registry of ScriptBlock colorizers used to color HealthChecker table
    output. Analyzer code references entries by ID so the ScriptBlock bodies
    do not travel across a PowerShell remoting boundary; the writer resolves
    the ID back to the local ScriptBlock at render time.

    The registry lives inside the function body so that injecting this
    function into a remote script block also carries the registry with it.
#>

function Get-HealthCheckerColorizer {
    [CmdletBinding()]
    [OutputType([ScriptBlock[]])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseOutputTypeCorrectly', '', Justification = 'Comma-wrap idiom returns [ScriptBlock[]] at runtime; static analyzer cannot infer the unwrap.')]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ColorizerId
    )

    $colorizers = @{
        IisState                     = {
            param($o, $p)
            if ($p -eq "State") {
                if ($o."$p" -eq "Started") { "Green" } else { "Red" }
            }
        }

        IisAppPoolRestart            = {
            param($o, $p)
            if ($p -eq "RestartConditionSet") {
                if ($o."$p") { "Red" } else { "Green" }
            }
        }

        IisAppPoolRestartMetrics     = {
            param($o, $p)
            switch ($p) {
                { $_ -in "PrivateMemory", "Memory", "Requests" } {
                    if ($o."$p" -eq "0") { "Green" } else { "Red" }
                }
                "Time" {
                    if ($o."$p" -eq "00:00:00") { "Green" } else { "Red" }
                }
                "Schedule" {
                    if ($o."$p" -eq "null") { "Green" } else { "Red" }
                }
            }
        }

        LegacyExchangeSecurityGroups = {
            param($o, $p)
            if ($p -eq "Members") {
                if ($o.$p -gt 0) {
                    "Yellow"
                }
            } else {
                "Yellow"
            }
        }

        ExtendedProtectionConfig     = {
            param($o, $p)
            if ($p -eq "ConfigSupported") {
                if ($o.$p -ne $true) {
                    "Red"
                }
            } elseif ($p -eq "IPFilterEnabled") {
                if ($o.$p -eq $true) {
                    "Green"
                }
            } elseif ($p -eq "ConfigSecure") {
                if ($o.$p -ne $true) {
                    "Red"
                } else {
                    "Green"
                }
            }
        }

        IisModulesConfig             = {
            param($o, $p)
            if ($p -eq "Signer") {
                if ($o.$p -eq "N/A") {
                    "Red"
                } else {
                    "Yellow"
                }
            } elseif ($p -eq "Status") {
                if ($o.$p -eq "Not signed") {
                    "Red"
                } elseif ($o.$p -ne 0) {
                    "Yellow"
                }
            } elseif ($p -eq "PathNotFound") {
                if ($o.$p -eq $true) {
                    "Red"
                }
            }
        }

        TlsCipherValue               = {
            param($o, $p)
            if ($p -eq "Value") {
                if ($o.$p -eq "NULL" -and -not $o.Location.Contains("1.3")) {
                    "Red"
                }
            }
        }

        TlsNetValue                  = {
            param($o, $p)
            if ($p -eq "Value") {
                if ($o.$p -eq "NULL" -and $o.Location -like "*v4.0.30319") {
                    "Red"
                }
            }
        }
    }

    $result = @()
    foreach ($id in $ColorizerId) {
        if (-not $colorizers.ContainsKey($id)) {
            throw "Unknown HealthChecker colorizer ID '$id'."
        }
        $result += $colorizers[$id]
    }

    # Return the array typed as [ScriptBlock[]] to honor [OutputType([ScriptBlock[]])] even for a single-element result.
    # The leading unary comma prevents the PowerShell pipeline from unwrapping the array.
    return , ([ScriptBlock[]]$result)
}
