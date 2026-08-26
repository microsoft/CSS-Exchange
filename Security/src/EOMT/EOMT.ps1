# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
    .SYNOPSIS
        Exchange On-premises Mitigation Tool (EOMT) - Unified CVE mitigation script.
    .DESCRIPTION
        This script applies IIS URL Rewrite mitigations for known Exchange Server CVEs.
        It replaces the legacy EOMT.ps1 and EOMTv2.ps1 scripts with a single, extensible tool
        that uses the IIS configuration management pipeline for reliable apply/rollback operations.

        Features:
            - Apply URL Rewrite mitigations for supported CVEs
            - JSON-backed rollback for reliable restore of original settings
            - Remote execution support via Exchange Management Shell pipeline
            - Optional Microsoft Safety Scanner (MSERT) malware scanning
            - Extensible design: new CVEs require only a definition file addition

        For the legacy single-CVE scripts, see EOMT-Legacy.ps1 and EOMTv2-Legacy.ps1
        in the Security/src/Archive directory.
    .PARAMETER ExchangeServerNames
        One or more Exchange server names to target. Accepts pipeline input from Get-ExchangeServer
        (ValueFromPipelineByPropertyName on Name and Fqdn). If omitted, targets the local server only.
    .PARAMETER SkipExchangeServerNames
        Exchange server names to exclude when processing multiple servers.
    .PARAMETER CVE
        The CVE to mitigate. Must match a supported CVE with a definition file in the
        Mitigations/ directory. If omitted, an interactive prompt displays available CVEs
        sorted by priority and allows selection by number, CVE ID, or Enter for the default.
    .PARAMETER RollbackMitigation
        Rolls back the IIS URL Rewrite mitigation for the specified CVE by restoring the
        original configuration from the JSON backup file created during apply.
    .PARAMETER ShowMitigationStatus
        Display the current vulnerability status for the specified CVE on each target server.
        This is a read-only check that examines the Exchange build/patch level. No changes are made.
    .PARAMETER RunMSERT
        Download and run the Microsoft Safety Scanner (MSERT) in quick scan mode after
        applying mitigations. Local execution only — skipped for remote servers.
    .PARAMETER RunMSERTFullScan
        Run MSERT in full scan mode instead of quick scan. Implies -RunMSERT. Local execution only.
        Full scan may take hours or days to complete.
    .PARAMETER DoNotRunMitigation
        Skip applying the URL Rewrite mitigation. Useful in combination with -RunMSERT
        to run a malware scan without modifying IIS configuration.
    .PARAMETER DoNotRemediate
        When used with -RunMSERT, MSERT will detect but not auto-remove threats.
    .PARAMETER SkipAutoUpdate
        Skip checking for a newer version of this script from GitHub.
    .PARAMETER SkipDisclaimer
        Bypass the interactive disclaimer prompt that warns about mitigation limitations.
    .EXAMPLE
        PS C:\> .\EOMT.ps1
        Applies the default (highest priority) CVE mitigation to the local server.
        If -CVE is not specified, an interactive prompt allows selection.
    .EXAMPLE
        PS C:\> .\EOMT.ps1 -CVE "CVE-2026-42897"
        Applies the CVE-2026-42897 mitigation to the local server.
    .EXAMPLE
        PS C:\> Get-ExchangeServer | .\EOMT.ps1 -CVE "CVE-2026-42897"
        Applies the CVE-2026-42897 mitigation to all Exchange servers in the organization
        via pipeline input from Exchange Management Shell.
    .EXAMPLE
        PS C:\> .\EOMT.ps1 -ExchangeServerNames "EX01", "EX02" -CVE "CVE-2026-42897"
        Applies the CVE-2026-42897 mitigation to specific servers by name.
    .EXAMPLE
        PS C:\> .\EOMT.ps1 -RollbackMitigation -CVE "CVE-2026-42897"
        Rolls back the CVE-2026-42897 mitigation on the local server using the JSON backup.
    .EXAMPLE
        PS C:\> Get-ExchangeServer | .\EOMT.ps1 -RollbackMitigation -CVE "CVE-2026-42897"
        Rolls back the CVE-2026-42897 mitigation on all Exchange servers.
    .EXAMPLE
        PS C:\> .\EOMT.ps1 -ShowMitigationStatus -CVE "CVE-2026-42897"
        Displays whether each target server is missing the security fix for CVE-2026-42897.
    .EXAMPLE
        PS C:\> .\EOMT.ps1 -RunMSERT -DoNotRunMitigation
        Runs the Microsoft Safety Scanner without applying any IIS mitigation.
    .EXAMPLE
        PS C:\> .\EOMT.ps1 -WhatIf -CVE "CVE-2026-42897"
        Shows what IIS configuration changes would be made without applying them.
    .LINK
        https://microsoft.github.io/CSS-Exchange/Security/EOMT/
        https://aka.ms/exchangevulns
        https://www.iis.net/downloads/microsoft/url-rewrite
        https://aka.ms/privacy
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('CustomRules\AvoidUsingReadHost', '', Justification = 'Interactive CVE selection prompt required when -CVE parameter is not provided')]
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = "High")]
param(
    [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
    [Alias("Name", "Fqdn")]
    [string[]]$ExchangeServerNames = $null,

    [Parameter(Mandatory = $false)]
    [string[]]$SkipExchangeServerNames = $null,

    [ValidateSet("CVE-2021-26855", "CVE-2022-41040", "CVE-2026-42897")]
    [string]$CVE,

    [switch]$RollbackMitigation,

    [switch]$ShowMitigationStatus,

    [switch]$RunMSERT,
    [switch]$RunMSERTFullScan,
    [switch]$DoNotRunMitigation,
    [switch]$DoNotRemediate,

    [switch]$SkipAutoUpdate,
    [switch]$SkipDisclaimer
)

begin {
    $ProgressPreference = "SilentlyContinue"
    $EOMTDir = Join-Path $env:TEMP "EOMT"

    # auto populated by CSS-Exchange build
    $BuildVersion = ""

    # Force TLS1.2 for HTTPS downloads
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Dot-source dependencies
    . $PSScriptRoot\Mitigations\MitigationDefinitions.ps1
    . $PSScriptRoot\ConfigurationAction\Invoke-ApplyMitigations.ps1
    . $PSScriptRoot\ConfigurationAction\Invoke-RollbackMitigations.ps1
    . $PSScriptRoot\DataCollection\Get-VulnerabilityStatus.ps1
    . $PSScriptRoot\SharedFunctions\Install-IISUrlRewriteModule.ps1
    . $PSScriptRoot\MSERT\Invoke-MSERTScan.ps1
    . $PSScriptRoot\..\..\..\Shared\Confirm-Administrator.ps1
    . $PSScriptRoot\..\..\..\Shared\Confirm-ExchangeShell.ps1
    . $PSScriptRoot\..\..\..\Shared\Show-Disclaimer.ps1
    . $PSScriptRoot\..\..\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1
    . $PSScriptRoot\..\..\..\Shared\Invoke-ScriptBlockHandler.ps1
    . $PSScriptRoot\..\..\..\Shared\Write-ErrorInformation.ps1
    . $PSScriptRoot\..\..\..\Shared\GenericScriptStartLogging.ps1

    # Log file path for user-facing messages — points to the debug logger output
    $EOMTLogFile = $Script:DebugLogger.FullPath

    # Prompt for CVE selection if not provided via parameter
    if ([string]::IsNullOrEmpty($CVE)) {
        # Load all definitions to get Priority, then sort by Priority (lowest = default)
        $allDefinitions = $script:MitigationDefinitionMap.Keys | ForEach-Object {
            & $script:MitigationDefinitionMap[$_]
        } | Sort-Object -Property Priority
        $availableCVEs = @($allDefinitions.Id)
        $defaultCVE = $availableCVEs[0]

        Write-Host ""
        Write-Host "Available CVE mitigations:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $availableCVEs.Count; $i++) {
            $label = if ($i -eq 0) { " (default)" } else { "" }
            Write-Host "  [$($i + 1)] $($availableCVEs[$i])$label"
        }
        Write-Host ""

        $validSelection = $false
        while (-not $validSelection) {
            $selection = Read-Host "Select CVE by number or ID [$defaultCVE]"

            if ([string]::IsNullOrEmpty($selection)) {
                $CVE = $defaultCVE
                $validSelection = $true
            } elseif ($selection -match '^\d+$') {
                $index = [int]$selection - 1
                if ($index -ge 0 -and $index -lt $availableCVEs.Count) {
                    $CVE = $availableCVEs[$index]
                    $validSelection = $true
                } else {
                    Write-Host "Invalid selection. Please enter a number between 1 and $($availableCVEs.Count)." -ForegroundColor Red
                }
            } elseif ($selection -in $availableCVEs) {
                $CVE = $selection
                $validSelection = $true
            } else {
                Write-Host "Invalid input. Please enter a number (1-$($availableCVEs.Count)) or a CVE ID ($($availableCVEs -join ', '))." -ForegroundColor Red
            }
        }
    }

    $serversToProcess = New-Object System.Collections.Generic.List[string]
} process {
    if ($null -ne $ExchangeServerNames) {
        foreach ($server in $ExchangeServerNames) {
            $serversToProcess.Add($server)
        }
    }
} end {
    # Pre-checks
    if (-not (Confirm-Administrator)) {
        Write-Error "Unable to launch EOMT.ps1: please re-run as administrator."
        exit
    }

    if ($PSVersionTable.PSVersion.Major -lt 3) {
        Write-Error "Unsupported version of PowerShell on $env:COMPUTERNAME - EOMT supports PowerShell 3 and later"
        exit
    }

    # Main
    try {
        if (-not (Test-Path $EOMTDir)) {
            New-Item -ItemType Directory -Path $EOMTDir | Out-Null
        }

        Write-Host "Starting EOMT.ps1 version $BuildVersion on $env:COMPUTERNAME"
        Write-Verbose "Script Execution Line: $($script:MyInvocation.Line)"
        Write-Verbose "Download directory for MSERT and IIS URL Rewrite Module: $EOMTDir"

        # Auto-update check
        if (-not $SkipAutoUpdate) {
            if (Test-ScriptVersion -AutoUpdate -VersionsUrl "https://aka.ms/EOMT-VersionsUri") {
                Write-Warning "Script was updated. Please rerun the command."
                exit
            }
        }

        # Resolve server list
        $isRemoteExecution = $serversToProcess.Count -gt 1 -or
        ($serversToProcess.Count -eq 1 -and
        $serversToProcess[0].Split(".")[0] -ne $env:COMPUTERNAME)
        if ($serversToProcess.Count -eq 0) {
            # Local-only mode: verify Exchange is installed on this machine
            if (-not ((Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction 0).MsiInstallPath)) {
                Write-Error "A supported version of Exchange was not found on $env:COMPUTERNAME. EOMT supports Exchange Server SE."
                exit
            }
            $serversToProcess.Add($env:COMPUTERNAME)
        } else {
            # Servers provided: requires Exchange Management Shell for server resolution
            if ($isRemoteExecution) {
                $exchangeShell = Confirm-ExchangeShell
                if (-not ($exchangeShell.ShellLoaded)) {
                    Write-Error "Failed to load the Exchange Management Shell. Remote execution requires Exchange Management Shell."
                    exit
                }
            }

            # Apply skip list
            if ($null -ne $SkipExchangeServerNames -and $SkipExchangeServerNames.Count -gt 0) {
                Write-Host "Skipping servers: $([string]::Join(", ", $SkipExchangeServerNames))"
                $serversToProcess = [System.Collections.Generic.List[string]]($serversToProcess | Where-Object {
                        $_ -notin $SkipExchangeServerNames
                    })
            }

            if ($serversToProcess.Count -eq 0) {
                Write-Host "No servers to process after applying filters."
                exit
            }

            Write-Host "Targeting $($serversToProcess.Count) server(s): $([string]::Join(", ", $serversToProcess))"
        }

        $mitigationDefinition = Get-MitigationDefinition -CVE $CVE
        $resolvedCVE = $mitigationDefinition.Id
        Write-Host "Resolved mitigation target: $resolvedCVE - $($mitigationDefinition.Description)"

        # Show mitigation status mode (read-only)
        if ($ShowMitigationStatus) {
            $statusCheckBlock = {
                param([string]$TestVulnerableCode)
                $testVulnerable = [ScriptBlock]::Create($TestVulnerableCode)
                return (& $testVulnerable)
            }
            $testVulnerableString = $mitigationDefinition.TestVulnerable.ToString()

            foreach ($server in $serversToProcess) {
                Write-Host ""
                Write-Host "Checking mitigation status for $resolvedCVE on $server"
                $statusResult = Invoke-ScriptBlockHandler -ComputerName $server -ScriptBlock $statusCheckBlock -ArgumentList $testVulnerableString

                if ($null -eq $statusResult) {
                    Write-Warning "$server : Unable to reach server"
                } else {
                    $codeFixColor = if ($statusResult.CodeFixApplied) { "Green" } else { "Red" }
                    Write-Host -NoNewline "$server : Code Fix Applied: "
                    Write-Host -NoNewline "$($statusResult.CodeFixApplied)" -ForegroundColor $codeFixColor

                    if ($statusResult.CodeFixApplied) {
                        if ($statusResult.MitigationApplied) {
                            Write-Host -NoNewline " | Mitigation Applied: "
                            Write-Host -NoNewline "True" -ForegroundColor Green
                            Write-Host " (can be safely rolled back)" -ForegroundColor Yellow
                        } else {
                            Write-Host -NoNewline " | Mitigation: "
                            Write-Host "N/A (protected by security update)" -ForegroundColor Green
                        }
                    } else {
                        Write-Host -NoNewline " | Mitigation Applied: "
                        if ($statusResult.MitigationApplied) {
                            Write-Host "$($statusResult.MitigationApplied)" -ForegroundColor Green
                        } elseif ($statusResult.RuleNameMatch) {
                            if ($statusResult.DisabledRules.Count -gt 0) {
                                Write-Host -NoNewline "DISABLED" -ForegroundColor Red
                            } else {
                                Write-Host -NoNewline "CONFLICT" -ForegroundColor Red
                            }
                            Write-Host " — rollback then re-apply" -ForegroundColor Red
                        } elseif ($statusResult.DisabledRules.Count -gt 0) {
                            Write-Host -NoNewline "False" -ForegroundColor Red
                            Write-Host " — a matching rule exists but is disabled under a different name. Run EOMT to apply." -ForegroundColor Red
                        } else {
                            Write-Host -NoNewline "$($statusResult.MitigationApplied)" -ForegroundColor Red
                            Write-Host " — ACTION REQUIRED" -ForegroundColor Red
                        }
                    }
                }
            }
            return
        }

        # Disclaimer
        if (-not $RollbackMitigation -and -not $DoNotRunMitigation -and -not $SkipDisclaimer) {
            $params = @{
                Message   = "Display Warning about $resolvedCVE mitigation"
                Target    = "This tool applies an IIS URL Rewrite mitigation for $resolvedCVE." +
                "`r`nMitigations are a temporary measure. Installation of the applicable Security Update" +
                "`r`nis the ***only way to fully protect your servers***." +
                "`r`nGet the latest Exchange Server update here: https://aka.ms/LatestExchangeServerUpdate" +
                "`r`nDo you want to proceed?"
                Operation = "Applying $resolvedCVE mitigation"
            }
            Show-Disclaimer @params
        }

        if ($RollbackMitigation -and -not $SkipDisclaimer) {
            $params = @{
                Message   = "Display Warning about rolling back mitigation"
                Target    = "You are about to rollback $CVE on $($serversToProcess.Count) server(s)." +
                "`r`nThis will restore IIS configuration to the state before the mitigation was applied." +
                "`r`nDo you want to proceed?"
                Operation = "Rollback CVE mitigation"
            }
            Show-Disclaimer @params
        }

        # --- Call 1: Remote prerequisite check (vulnerability + URL Rewrite) ---
        # This script block runs on each target server and returns a result object.
        # If it returns $null, the server is unreachable.
        # NOTE: script blocks don't survive serialization across PS remoting, so we pass
        # the TestVulnerable script block as a string and recreate it on the remote side
        # using [ScriptBlock]::Create().
        $testVulnerableString = $mitigationDefinition.TestVulnerable.ToString()
        $prerequisiteCheckBlock = {
            param([string]$TestVulnerableCode, [bool]$CheckUrlRewrite)

            $result = @{
                CodeFixApplied      = $false
                MitigationApplied   = $false
                DisabledRules       = @()
                RuleNameMatch       = $false
                UrlRewriteInstalled = $true
                ErrorContext        = $null
            }

            try {
                $testVulnerable = [ScriptBlock]::Create($TestVulnerableCode)
                $vulnResult = & $testVulnerable
                $result.CodeFixApplied = [bool]$vulnResult.CodeFixApplied
                $result.MitigationApplied = [bool]$vulnResult.MitigationApplied
                $result.DisabledRules = @($vulnResult.DisabledRules)
                $result.RuleNameMatch = [bool]$vulnResult.RuleNameMatch
            } catch {
                $result.ErrorContext = "Unable to determine vulnerability status: $_"
                return $result
            }

            if ($CheckUrlRewrite) {
                try {
                    $uninstallPaths = @(
                        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
                        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
                    )
                    $rewriteModule = Get-ItemProperty $uninstallPaths -ErrorAction SilentlyContinue |
                        Where-Object { $_.DisplayName -like "*IIS*" -and $_.DisplayName -like "*URL*" -and $_.DisplayName -like "*2*" }
                    $result.UrlRewriteInstalled = ($null -ne $rewriteModule)
                } catch {
                    $result.UrlRewriteInstalled = $false
                    $result.ErrorContext = "URL Rewrite check failed: $_"
                }
            }

            return $result
        }

        # Categorize servers
        $vulnerableServers = New-Object System.Collections.Generic.List[string]
        $notVulnerableServers = New-Object System.Collections.Generic.List[string]
        $unreachableServers = New-Object System.Collections.Generic.List[string]
        $missingUrlRewrite = New-Object System.Collections.Generic.List[string]
        $conflictServers = New-Object System.Collections.Generic.List[string]

        if (-not $RollbackMitigation -and -not $DoNotRunMitigation) {
            $serverCount = 0
            $totalServers = $serversToProcess.Count

            foreach ($server in $serversToProcess) {
                $serverCount++
                Write-Host "[$serverCount/$totalServers] Checking prerequisites on $server"

                $prerequisiteResult = Invoke-ScriptBlockHandler -ComputerName $server -ScriptBlock $prerequisiteCheckBlock -ArgumentList $testVulnerableString, $mitigationDefinition.RequiresUrlRewrite

                if ($null -eq $prerequisiteResult) {
                    Write-Warning "$server : Unable to reach server — skipping (may still be vulnerable)"
                    $unreachableServers.Add($server)
                    continue
                }

                if ($null -ne $prerequisiteResult.ErrorContext) {
                    Write-Warning "$server : $($prerequisiteResult.ErrorContext) — skipping"
                    $unreachableServers.Add($server)
                    continue
                }

                if ($prerequisiteResult.CodeFixApplied) {
                    Write-Host "$server : Code fix applied for $resolvedCVE — skipping"
                    $notVulnerableServers.Add($server)
                    continue
                }

                if ($prerequisiteResult.MitigationApplied) {
                    Write-Host "$server : Mitigation already applied for $resolvedCVE — skipping"
                    $notVulnerableServers.Add($server)
                    continue
                }

                if ($prerequisiteResult.RuleNameMatch) {
                    if ($prerequisiteResult.DisabledRules.Count -gt 0) {
                        Write-Warning "$server : Mitigation rules for $resolvedCVE are DISABLED."
                    } else {
                        Write-Warning "$server : A rule with the expected name exists but does not match the current mitigation configuration for $resolvedCVE."
                    }
                    Write-Warning "$server : Run '.\EOMT.ps1 -RollbackMitigation -CVE $resolvedCVE' first, then re-run EOMT to apply the updated mitigation."
                    $conflictServers.Add($server)
                    continue
                }

                if ($mitigationDefinition.RequiresUrlRewrite -and -not $prerequisiteResult.UrlRewriteInstalled -and $isRemoteExecution) {
                    Write-Warning "$server : IIS URL Rewrite Module not installed — skipping. Install the module manually or run the script locally on that server."
                    $missingUrlRewrite.Add($server)
                    continue
                }

                Write-Host "$server : Vulnerable to $resolvedCVE — will apply mitigation"
                $vulnerableServers.Add($server)
            }

            Write-Host ""
            if ($unreachableServers.Count -gt 0) {
                Write-Warning "Unreachable servers (may still be vulnerable): $([string]::Join(", ", $unreachableServers))"
            }
            if ($missingUrlRewrite.Count -gt 0) {
                Write-Warning "Servers missing URL Rewrite Module (skipped): $([string]::Join(", ", $missingUrlRewrite))"
            }
            if ($conflictServers.Count -gt 0) {
                Write-Warning "Servers with rule conflicts (rollback required): $([string]::Join(", ", $conflictServers))"
            }
            if ($notVulnerableServers.Count -gt 0) {
                Write-Host "Servers not vulnerable (skipped): $([string]::Join(", ", $notVulnerableServers))"
            }
        }

        # --- Rollback mode ---
        if ($RollbackMitigation) {
            foreach ($server in $serversToProcess) {
                Write-Host "Starting rollback of $CVE on $server"
                $rollbackResult = Invoke-RollbackMitigations -CVE $CVE -ServerName $server

                if ($WhatIfPreference) {
                    Write-Host "WhatIf: No rollback changes were made on $server"
                } elseif ($rollbackResult.Success) {
                    Write-Host "Rollback of $CVE completed successfully on $server"
                } else {
                    Write-Warning "Rollback of $CVE encountered issues on $server. Please review the log at $EOMTLogFile"
                }
            }
            return
        }

        # --- Call 2: Apply mitigations to qualifying servers ---
        if (-not $DoNotRunMitigation -and $vulnerableServers.Count -gt 0) {
            # For local execution, install URL Rewrite Module if needed
            if (-not $isRemoteExecution -and $mitigationDefinition.RequiresUrlRewrite) {
                Write-Host "Checking IIS URL Rewrite Module on local server"
                Install-IISUrlRewriteModule -DownloadDir $EOMTDir
            }

            foreach ($server in $vulnerableServers) {
                Write-Host "Applying $resolvedCVE mitigation on $server"
                $applyResult = Invoke-ApplyMitigations -MitigationDefinition $mitigationDefinition -ServerName $server

                if ($WhatIfPreference) {
                    Write-Host "WhatIf: No changes were made to IIS configuration on $server"
                } elseif ($applyResult.Success) {
                    Write-Host "Mitigation for $resolvedCVE applied on $server" -ForegroundColor Green
                } else {
                    Write-Warning "Mitigation for $resolvedCVE failed on $server. Please review the log at $EOMTLogFile"
                    if ($isRemoteExecution) {
                        Write-Warning "For remote server details, check the IIS management debug log on $server at: %WINDIR%\System32\inetsrv\config\IISManagementDebugLog.txt"
                    }
                    if ($null -ne $applyResult.Result -and $applyResult.Result.FailedServers.Count -gt 0) {
                        Write-Host "Failed servers: $($applyResult.Result.FailedServers -join ', ')"
                    }
                }
            }
        } elseif (-not $DoNotRunMitigation -and $vulnerableServers.Count -eq 0) {
            Write-Host "No vulnerable servers to apply mitigation to."
        } elseif ($DoNotRunMitigation) {
            Write-Host "Skipping mitigation - DoNotRunMitigation set"
        }

        # MSERT scan — local only, only if explicitly requested
        if (($RunMSERT -or $RunMSERTFullScan) -and -not $RollbackMitigation) {
            if ($isRemoteExecution) {
                Write-Warning "MSERT scanning is only supported on the local server. Skipping MSERT for remote servers."
            } else {
                $msertParams = @{
                    WorkingDir     = $EOMTDir
                    DoNotRemediate = $DoNotRemediate
                }

                if ($RunMSERTFullScan) {
                    $msertParams["RunFullScan"] = $true
                }

                $msertResult = Invoke-MSERTScan @msertParams

                if ($msertResult.ScanCompleted -and $msertResult.ThreatsDetected) {
                    Write-Warning "THREATS DETECTED on $env:COMPUTERNAME! Please review $($msertResult.LogPath)"
                } elseif ($msertResult.ScanCompleted) {
                    Write-Host "MSERT scan complete on $env:COMPUTERNAME - no known threats detected"
                }
            }
        }

        Write-Host "EOMT.ps1 complete. Review logs at $EOMTLogFile"
    } catch {
        Write-Host "EOMT.ps1 failed on $env:COMPUTERNAME - $_ . Review logs at $EOMTLogFile" -ForegroundColor Red
        Write-VerboseErrorInformation $_
    }
}
