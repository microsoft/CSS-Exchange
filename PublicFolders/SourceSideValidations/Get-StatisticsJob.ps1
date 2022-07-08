# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-StatisticsJob {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0)]
        [string]
        $Server,

        [Parameter(Position = 1)]
        [string]
        $Mailbox,

        [Parameter(Position = 2)]
        [PSCustomObject[]]
        $Folders
    )

    begin {
        $statistics = New-Object System.Collections.ArrayList
        $errors = New-Object System.Collections.ArrayList
        $permanentFailureOccurred = $false
        $permanentFailures = @(
            "Kerberos",
            "Cannot process argument transformation on parameter 'Identity'",
            "Starting a command on the remote server failed"
        )
        $WarningPreference = "SilentlyContinue"
        $Error.Clear()
        Import-PSSession (New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$Server/powershell" -Authentication Kerberos) -AllowClobber | Out-Null
        if ($Error.Count -gt 0) {
            $permanentFailureOccurred = $true
            foreach ($err in $Error) {
                $errorReport = @{
                    TestName       = "Get-Statistics"
                    ResultType     = "ImportSessionFailure"
                    Severity       = "Error"
                    FolderIdentity = ""
                    FolderEntryId  = ""
                    ResultData     = $err.ToString()
                }

                [void]$errors.Add($errorReport)
            }
        }

        if (-not $permanentFailureOccurred -and $null -eq (Get-Command Get-PublicFolderStatistics -ErrorAction SilentlyContinue)) {
            $permanentFailureOccurred = $true
            $errorReport = @{
                TestName       = "Get-Statistics"
                ResultType     = "CommandNotFound"
                Severity       = "Error"
                FolderIdentity = ""
                FolderEntryId  = ""
                ResultData     = ""
            }

            [void]$errors.Add($errorReport)
        }

        $startTime = Get-Date
        $progressCount = 0
        $sw = New-Object System.Diagnostics.Stopwatch
        $sw.Start()
        $progressParams = @{
            Activity = "Getting public folder statistics"
        }
    }

    process {
        if ($permanentFailureOccurred) {
            return
        }

        $ErrorActionPreference = "Stop" # So our try/catch works
        $statistics = New-Object System.Collections.ArrayList
        foreach ($folder in $Folders) {
            $progressCount++
            if ($sw.ElapsedMilliseconds -gt 1000) {
                $sw.Restart()
                Write-Progress @progressParams -Status $progressCount
            }

            try {
                if ([string]::IsNullOrEmpty($folder.EntryId)) {
                    $folderObject = $folder | Format-List | Out-String
                    $foldersCollection = $Folders | Format-List | Out-String
                    $errorDetails = "$folderObject`n`n$foldersCollection"
                    $errorReport = @{
                        TestName       = "Get-Statistics"
                        ResultType     = "NullEntryId"
                        Severity       = "Error"
                        FolderIdentity = $folder.Identity
                        FolderEntryId  = $folder.EntryId
                        ResultData     = $errorDetails
                    }

                    [void]$errors.Add($errorReport)
                }
                $stats = Get-PublicFolderStatistics $folder.EntryId | Select-Object EntryId, ItemCount, TotalItemSize

                [Int64]$totalItemSize = -1
                if ($stats.TotalItemSize.ToString() -match "\(([\d|,|.]+) bytes\)") {
                    $totalItemSize = [Int64]::Parse($Matches[1], "AllowThousands")
                }

                [void]$statistics.Add([PSCustomObject]@{
                        EntryId       = $stats.EntryId
                        ItemCount     = $stats.ItemCount
                        TotalItemSize = $totalItemSize
                    })
            } catch {
                $errorText = $_.ToString()
                $isPermanentFailure = $null -ne ($permanentFailures | Where-Object { $errorText.Contains($_) })
                if ($isPermanentFailure) {
                    $errorReport = @{
                        TestName       = "Get-Statistics"
                        ResultType     = "JobFailure"
                        Severity       = "Error"
                        FolderIdentity = $folder.Identity
                        FolderEntryId  = $folder.EntryId
                        ResultData     = $errorText
                    }

                    [void]$errors.Add($errorReport)
                    $permanentFailureOccurred = $true
                    break
                } else {
                    $errorReport = @{
                        TestName       = "Get-Statistics"
                        ResultType     = "CouldNotGetStatistics"
                        Severity       = "Error"
                        FolderIdentity = $folder.Identity
                        FolderEntryId  = $folder.EntryId
                        ResultData     = $errorText
                    }

                    [void]$errors.Add($errorReport)
                }
            }
        }
    }

    end {
        Write-Progress @progressParams -Completed
        $duration = ((Get-Date) - $startTime)
        return [PSCustomObject]@{
            Statistics       = $statistics
            Errors           = $errors
            PermanentFailure = $permanentFailureOccurred
            Server           = $Server
            Mailbox          = $Mailbox
            Folders          = $Folders
            Duration         = $duration
        }
    }
}
