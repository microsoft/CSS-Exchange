# This script reports the space taken up by various tables based on a database space dump.
# The space dump must be obtained while the database is dismounted, or on a suspended copy
# if the issue is happening there. To obtain the space dump, use the following syntax:
#
# eseutil /ms /v > C:\spacedump.txt
#
# Then, feed that file to this script as follows:
#
# .\Analyze-SpaceDump.ps1 -File C:\spacedump.txt
#
# This script will only work with Exchange 2013 and later space dumps.

param([string]$File)

$fileReader = New-Object System.IO.StreamReader($File)
$foundHeaderLine = $false
while ($null -ne ($buffer = $fileReader.ReadLine())) {
    if ($buffer.StartsWith("Name ")) {
        $foundHeaderLine = $true
        # found the header line
        # is this a csv or not?
        $isCSV = ($buffer.IndexOf(",") -gt 0)
        if ($isCSV) {
            $headerSplit = $buffer.Split(@(","))
            for ($x = 0; $x -lt $headerSplit.Length; $x++) {
                if ($headerSplit[$x].Trim() -eq "Owned(MB)") {
                    $ownedColumnIndex = $x
                } elseif ($headerSplit[$x].Trim() -eq "Avail(MB)") {
                    $availColumnIndex = $x
                }
            }

            break
        } else {
            # now find the Owned header and figure out where that column starts and ends
            $typeLabelIndex = $buffer.IndexOf("Type")
            $ownedLabelIndex = $buffer.IndexOf("Owned(MB)")
            $ownedColumnEnd = $ownedLabelIndex + 9
            $ownedColumnStart = $ownedColumnEnd - 12

            $availableColumnIndex = $buffer.IndexOf("Avail(MB)")
            $availableColumnEnd = $availableColumnIndex + 9
            $availableColumnStart = $availableColumnEnd - 12

            break
        }
    }
}

if (!($foundHeaderLine)) {
    "Couldn't find the header line in the space dump."
    return
}

$ownedColumnLength = $ownedColumnEnd - $ownedColumnStart
$availableColumnLength = $availableColumnEnd - $availableColumnStart

# Skip 3 lines to get to the start of the tables
for ($x = 0; $x -lt 3; $x++) {
    $fileReader.ReadLine() | Out-Null
}

if ($isCSV) {
    $fileReader.ReadLine() | Out-Null
}

$attachmentTableSizes = New-Object 'System.Collections.Generic.Dictionary[string, double]'
$attachmentTableFree = New-Object 'System.Collections.Generic.Dictionary[string, double]'
$piTablesPerMailbox = New-Object 'System.Collections.Generic.Dictionary[string, double]'

[double]$spaceOwnedByAttachmentTables = 0
[double]$freeSpaceByAttachmentTables = 0
[double]$numberOfAttachmentTables = 0
[double]$spaceOwnedByPiTables = 0
[double]$freeSpaceByPiTables = 0
[double]$numberOfPiTables = 0
[double]$spaceOwnedByReceiveFolderTables = 0
[double]$freeSpaceByReceiveFolderTables = 0
[double]$numberOfReceiveFolderTables = 0
[double]$spaceOwnedByFolderTables = 0
[double]$freeSpaceByFolderTables = 0
[double]$numberOfFolderTables = 0
[double]$spaceOwnedByMessageTables = 0
[double]$freeSpaceByMessageTables = 0
[double]$numberofMessageTables = 0
[double]$spaceOwnedByMsgViewTables = 0
[double]$freeSpaceByMsgViewTables = 0
[double]$numberOfMsgViewTables = 0
[double]$spaceOwnedByOtherTables = 0
[double]$freeSpaceByOtherTables = 0
[double]$numberOfOtherTables = 0

while ($null -ne ($buffer = $fileReader.ReadLine())) {
    if (!($buffer.StartsWith("    ")) -and $buffer -ne "") {
        if ($buffer.StartsWith("-----")) {
            break;
        }

        if ($isCSV) {
            $bufferSplit = $buffer.Split(@(","))
            $thisOwnedSpace = [System.Double]::Parse($bufferSplit[$ownedColumnIndex])
            $thisAvailSpace = [System.Double]::Parse($bufferSplit[$availColumnIndex])
        } else {
            $thisOwnedSpace = [System.Double]::Parse($buffer.Substring($ownedColumnStart, $ownedColumnLength))
            $thisAvailSpace = [System.Double]::Parse($buffer.Substring($availableColumnStart, $availableColumnLength))
        }

        if ($buffer.StartsWith("  Attachment_")) {
            $numberOfAttachmentTables++
            $spaceOwnedByAttachmentTables += $thisOwnedSpace
            if ($isCSV) {
                $attachmentTableName = $bufferSplit[0].Trim()
            } else {
                $attachmentTableName = $buffer.Substring(0, $typeLabelIndex).Trim()
            }

            $attachmentTableSizes.Add($attachmentTableName, $thisOwnedSpace)

            $freeSpaceByAttachmentTables += $thisAvailSpace
            $attachmentTableFree.Add($attachmentTableName, $thisAvailSpace)
        } elseif ($buffer.StartsWith("  ReceiveFolder_")) {
            $numberOfReceiveFolderTables++
            $spaceOwnedByReceiveFolderTables += $thisOwnedSpace
            $freeSpaceByReceiveFolderTables += $thisAvailSpace
        } elseif ($buffer.StartsWith("  Folder_")) {
            $numberOfFolderTables++
            $spaceOwnedByFolderTables += $thisOwnedSpace
            $freeSpaceByFolderTables += $thisAvailSpace
        } elseif ($buffer.StartsWith("  Message_")) {
            $numberofMessageTables++
            $spaceOwnedByMessageTables += $thisOwnedSpace
            $freeSpaceByMessageTables += $thisAvailSpace
        } elseif ($buffer.StartsWith("  pi")) {
            $numberOfPiTables++
            $spaceOwnedByPiTables += $thisOwnedSpace
            $freeSpaceByPiTables += $thisAvailSpace

            $mailboxNumber = "None"
            $firstUnderscoreIndex = $buffer.IndexOf("_")
            $secondUnderscoreIndex = $buffer.IndexOf("_", $firstUnderscoreIndex + 1)
            if ($secondUnderscoreIndex -gt 0) {
                $mailboxNumber = $buffer.Substring($firstUnderscoreIndex + 1, $secondUnderscoreIndex - $firstUnderscoreIndex - 1)
            }

            $tableCount = $null
            if ($piTablesPerMailbox.TryGetValue($mailboxNumber, [ref]$tableCount)) {
                $piTablesPerMailbox[$mailboxNumber] = $tableCount + 1
            } else {
                $piTablesPerMailbox.Add($mailboxNumber, 1)
            }
        } else {
            $numberOfOtherTables++
            $spaceOwnedByOtherTables += $thisOwnedSpace
            $freeSpaceByOtherTables += $thisAvailSpace
        }
    }
}

$totalSpace = $spaceOwnedByAttachmentTables + $spaceOwnedByPiTables + $spaceOwnedByReceiveFolderTables + $spaceOwnedByFolderTables + $spaceOwnedByMessageTables + $spaceOwnedByMsgViewTables + $spaceOwnedByOtherTables
$totalFree = $freeSpaceByAttachmentTables + $freeSpaceByPiTables + $freeSpaceByReceiveFolderTables + $freeSpaceByFolderTables + $freeSpaceByMessageTables + $freeSpaceByMsgViewTables + $freeSpaceByOtherTables

"    Space owned by Attachment tables: " + $spaceOwnedByAttachmentTables.ToString("F3")
"        % owned by Attachment tables: " + (($spaceOwnedByAttachmentTables / $totalSpace) * 100).ToString("F2")
"     Free space in Attachment tables: " + $freeSpaceByAttachmentTables.ToString("F3")
"         Number of Attachment tables: " + $numberOfAttachmentTables.ToString()
"Space owned by Physical Index tables: " + $spaceOwnedByPiTables.ToString("F3")
"    % owned by Physical Index tables: " + (($spaceOwnedByPiTables / $totalSpace) * 100).ToString("F2")
" Free space in Physical Index tables: " + $freeSpaceByPiTables.ToString("F3")
"     Number of Physical Index tables: " + $numberOfPiTables.ToString()
"           Space owned by DVU tables: " + $spaceOwnedByReceiveFolderTables.ToString("F3")
"               % owned by DVU tables: " + (($spaceOwnedByReceiveFolderTables / $totalSpace) * 100).ToString("F2")
"            Free space in DVU tables: " + $freeSpaceByReceiveFolderTables.ToString("F3")
"                Number of DVU tables: " + $numberOfReceiveFolderTables.ToString()
"        Space owned by Folder tables: " + $spaceOwnedByFolderTables.ToString("F3")
"            % owned by Folder tables: " + (($spaceOwnedByFolderTables / $totalSpace) * 100).ToString("F2")
"         Free space in Folder tables: " + $freeSpaceByFolderTables.ToString("F3")
"             Number of Folder tables: " + $numberOfFolderTables.ToString()
"       Space owned by Message tables: " + $spaceOwnedByMessageTables.ToString("F3")
"           % owned by Message tables: " + (($spaceOwnedByMessageTables / $totalSpace) * 100).ToString("F2")
"        Free space in Message tables: " + $freeSpaceByMessageTables.ToString("F3")
"            Number of Message tables: " + $numberOfMessageTables.ToString()
"       Space owned by MsgView tables: " + $spaceOwnedByMsgViewTables.ToString("F3")
"           % owned by MsgView tables: " + (($spaceOwnedByMsgViewTables / $totalSpace) * 100).ToString("F2")
"        Free space in MsgView tables: " + $freeSpaceByMsgViewTables.ToString("F3")
"            Number of MsgView tables: " + $numberOfMsgViewTables.ToString()
"         Space owned by other tables: " + $spaceOwnedByOtherTables.ToString("F3")
"             % owned by other tables: " + (($spaceOwnedByOtherTables / $totalSpace) * 100).ToString("F2")
"          Free space in other tables: " + $freeSpaceByOtherTables.ToString("F3")
"              Number of other tables: " + $numberOfOtherTables.ToString()
""
"     Total space owned by all tables: " + $totalSpace.ToString("F3")
"      Total space free in all tables: " + $totalFree.ToString("F3")
""
"Largest attachment tables:"
$top10AttachmentTables = $attachmentTableSizes.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 10
$top10AttachmentTables | ForEach-Object {
    [PSCustomObject]@{
        Table = $_.Key
        Owned = $_.Value.ToString("F3")
        Free  = $attachmentTableFree[$_.Key].ToString("F3")
    }
} | Format-Table | Out-Host

"Attachment tables with most free space:"
$top10FreeAttachmentTables = $attachmentTableFree.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 10
$top10FreeAttachmentTables | ForEach-Object {
    [PSCustomObject]@{
        Table = $_.Key
        Owned = $attachmentTableSizes[$_.Key].ToString("F3")
        Free  = $_.Value.ToString("F3")
    }
} | Format-Table | Out-Host

"Mailboxes with the most Physical Index tables:"
$top10Pi = $piTablesPerMailbox.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 10
$top10Pi | ForEach-Object {
    [PSCustomObject]@{
        MailboxNumber      = $_.Key
        PhysicalIndexCount = $_.Value.ToString()
    }
} | Format-Table | Out-Host

$fileReader.Close()