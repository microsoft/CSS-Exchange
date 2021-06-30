# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-IpmSubtree {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0)]
        [string]
        $Server
    )

    begin {
        $WarningPreference = "SilentlyContinue"
        Import-PSSession (New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$Server/powershell" -Authentication Kerberos) | Out-Null
        $progressCount = 0
        $errors = 0
        $ipmSubtree = @()
        $sw = New-Object System.Diagnostics.Stopwatch
        $sw.Start()
        $progressParams = @{
            Activity = "Retrieving IPM_SUBTREE folders"
        }
    }

    process {
        if (-not $startFresh -and (Test-Path $PSScriptRoot\IpmSubtree.csv)) {
            Write-Progress @progressParams
            $ipmSubtree = Import-Csv $PSScriptRoot\IpmSubtree.csv
        } else {
            $ipmSubtree = Get-PublicFolder -Recurse -ResultSize Unlimited |
                Select-Object Identity, EntryId, ParentFolder, DumpsterEntryId, FolderPath, FolderSize, HasSubfolders, ContentMailboxName, MailEnabled, MailRecipientGuid |
                ForEach-Object {
                    $progressCount++
                    $currentFolder = $_.Identity.ToString()
                    try {
                        if ($sw.ElapsedMilliseconds -gt 1000) {
                            $sw.Restart()
                            Write-Progress @progressParams -Status $progressCount
                        }

                        [PSCustomObject]@{
                            Identity          = $_.Identity.ToString()
                            EntryId           = $_.EntryId.ToString()
                            ParentEntryId     = $_.ParentFolder.ToString()
                            DumpsterEntryId   = if ($_.DumpsterEntryId) { $_.DumpsterEntryId.ToString() } else { $null }
                            FolderPathDepth   = $_.FolderPath.Depth
                            FolderSize        = $_.FolderSize
                            HasSubfolders     = $_.HasSubfolders
                            ContentMailbox    = $_.ContentMailboxName
                            MailEnabled       = $_.MailEnabled
                            MailRecipientGuid = $_.MailRecipientGuid
                            ItemCount         = 0
                        }
                    } catch {
                        $errors++
                        Write-Error -Message $currentFolder -Exception $_.Exception
                        break
                    }
                }
        }
    }

    end {
        Write-Progress @progressParams -Completed

        return [PSCustomObject]@{
            IpmSubtree = $ipmSubtree
        }
    }
}
