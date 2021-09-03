# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-NonIpmSubtree {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0)]
        [string]
        $Server,

        [Parameter(Position = 1)]
        [bool]
        $SlowTraversal = $false
    )

    begin {
        $WarningPreference = "SilentlyContinue"
        $progressCount = 0
        $maxRetries = 10
        $retryDelay = [timespan]::FromMinutes(5)
        $nonIpmSubtree = New-Object System.Collections.ArrayList
        $sw = New-Object System.Diagnostics.Stopwatch
        $sw.Start()
        $progressParams = @{
            Activity = "Retrieving NON_IPM_SUBTREE folders"
        }

        # Only used for slow traversal to save progress in case of failure
        $foldersProcessed = New-Object 'System.Collections.Generic.HashSet[string]'

        # This must be defined in the function scope because this function is runs as a job
        function Get-FoldersRecursive {
            [CmdletBinding()]
            param (
                [Parameter(Position = 0)]
                [object]
                $Folder,

                [Parameter(Position = 1)]
                [object]
                $FoldersProcessed
            )

            $children = Get-PublicFolder $Folder.EntryId -GetChildren -ResultSize Unlimited
            foreach ($child in $children) {
                if (-not $FoldersProcessed.Contains($child.EntryId.ToString())) {
                    if ($child.HasSubfolders) {
                        Get-FoldersRecursive $child $FoldersProcessed
                    }

                    $child
                }
            }
        }
    }

    process {
        $getCommand = { Get-PublicFolder "\non_ipm_subtree" -Recurse -ResultSize Unlimited }

        if ($SlowTraversal) {
            $getCommand = { $top = Get-PublicFolder "\non_ipm_subtree"; Get-FoldersRecursive $top $foldersProcessed; $top }
        }

        $outputResultsScriptBlock = {
            [CmdletBinding()]
            param (
                [Parameter(ValueFromPipeline = $true)]
                [object]
                $Folder
            )

            process {
                $progressCount++
                if ($sw.ElapsedMilliseconds -gt 1000) {
                    $sw.Restart()
                    Write-Progress @progressParams -Status $progressCount
                }

                $result = [PSCustomObject]@{
                    Identity        = $Folder.Identity.ToString()
                    EntryId         = $Folder.EntryId.ToString()
                    DumpsterEntryId = if ($Folder.DumpsterEntryId) { $Folder.DumpsterEntryId.ToString() } else { $null }
                    MailEnabled     = $Folder.MailEnabled
                }

                $null = $nonIpmSubtree.Add($result)

                $null = $foldersProcessed.Add($Folder.EntryId.ToString())
            }
        }

        for ($retryCount = 1; $retryCount -le $maxRetries; $retryCount++) {
            try {
                Get-PSSession | Remove-PSSession
                Import-PSSession (New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$Server/powershell" -Authentication Kerberos) -AllowClobber | Out-Null
                Invoke-Command $getCommand | &$outputResultsScriptBlock
                break
            } catch {
                if (-not $SlowTraversal) {
                    throw
                }

                $sw.Restart()
                while ($sw.ElapsedMilliseconds -lt $retryDelay.TotalMilliseconds) {
                    Write-Progress @progressParams -Status "Retry $retryCount of $maxRetries. Error: $($_.Message)"
                    Start-Sleep -Seconds 5
                    $remainingMilliseconds = $retryDelay.TotalMilliseconds - $sw.ElapsedMilliseconds
                    if ($remainingMilliseconds -lt 0) { $remainingMilliseconds = 0 }
                    Write-Progress @progressParams -Status "Retry $retryCount of $maxRetries. Will retry in $([TimeSpan]::FromMilliseconds($remainingMilliseconds))"
                    Start-Sleep -Seconds 5
                }
            }
        }
    }

    end {
        Write-Progress @progressParams -Completed

        return [PSCustomObject]@{
            NonIpmSubtree = $nonIpmSubtree
        }
    }
}
