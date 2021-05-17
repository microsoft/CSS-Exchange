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
        Import-PSSession (New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "http://$Server/powershell" -Authentication Kerberos) | Out-Null
        $progressCount = 0
        $errors = 0
        $nonIpmSubtree = @()
        $sw = New-Object System.Diagnostics.Stopwatch
        $sw.Start()
        $progressParams = @{
            Activity = "Retrieving NON_IPM_SUBTREE folders"
        }

        # This must be defined in the function scope because this function is runs as a job
        function Get-FoldersRecursive {
            [CmdletBinding()]
            param (
                [Parameter(Position = 0)]
                [object]
                $Folder
            )

            $children = Get-PublicFolder $Folder.EntryId -GetChildren -ResultSize Unlimited
            foreach ($child in $children) {
                $child
                Get-FoldersRecursive $child
            }
        }
    }

    process {
        $getCommand = { Get-PublicFolder \non_ipm_subtree -Recurse -ResultSize Unlimited }

        if ($SlowTraversal) {
            $getCommand = { $top = Get-PublicFolder "\non_ipm_subtree"; $top; Get-FoldersRecursive $top }
        }

        $nonIpmSubtree = Invoke-Command $getCommand |
            Select-Object Identity, EntryId, DumpsterEntryId, MailEnabled |
            ForEach-Object {
                $progressCount++
                $currentFolder = $_.Identity.ToString()
                try {
                    if ($sw.ElapsedMilliseconds -gt 1000) {
                        $sw.Restart()
                        Write-Progress @progressParams -Status $progressCount
                    }

                    [PSCustomObject]@{
                        Identity        = $_.Identity.ToString()
                        EntryId         = $_.EntryId.ToString()
                        DumpsterEntryId = if ($_.DumpsterEntryId) { $_.DumpsterEntryId.ToString() } else { $null }
                        MailEnabled     = $_.MailEnabled
                    }
                } catch {
                    $errors++
                    Write-Error -Message $currentFolder -Exception $_.Exception
                    break
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
