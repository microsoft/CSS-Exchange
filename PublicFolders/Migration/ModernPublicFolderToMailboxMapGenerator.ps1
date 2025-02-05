# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# .SYNOPSIS
# ModernPublicFolderToMailboxMapGenerator.ps1
#    Generates a CSV file that contains the mapping of 2013/2016 public folder branch to mailbox

param(
    # Mailbox size
    [Parameter(
        Mandatory=$true,
        HelpMessage = "Size (in Bytes) of any one of the Public folder mailboxes in destination. (E.g. For 1GB enter 1 followed by nine 0's)")]
    [long] $MailboxSize,

    # Mailbox Recoverable item size
    [Parameter(
        Mandatory=$true,
        HelpMessage = "Recoverable Item Size (in Bytes) of any one of the Public folder mailboxes in destination. (E.g. For 1GB enter 1 followed by nine 0's)")]
    [long] $MailboxRecoverableItemSize,

    # File to import from
    [Parameter(
        Mandatory=$true,
        HelpMessage = "This is the path to a CSV formatted file that contains the folder names and their sizes.")]
    [ValidateNotNull()]
    [string] $ImportFile,

    # File to export to
    [Parameter(
        Mandatory=$true,
        HelpMessage = "Full path of the output file to be generated. If only filename is specified, then the output file will be generated in the current directory.")]
    [ValidateNotNull()]
    [string] $ExportFile
)

################ START OF DEFAULTS ################

$script:Exchange15MajorVersion = 15
$script:Exchange15MinorVersion = 0
$script:Exchange15CUBuild = 1263
$script:Exchange16MajorVersion = 15
$script:Exchange16MinorVersion = 1
$script:Exchange16CUBuild = 669

################ END OF DEFAULTS #################

# Folder Node's member indices
# This is an optimization since creating and storing objects as PSObject types
# is an expensive operation in powershell
# ClassName_MemberName
$script:FolderNode_Path = 0
$script:FolderNode_Mailbox = 1
$script:FolderNode_TotalItemSize = 2
$script:FolderNode_AggregateTotalItemSize = 3
$script:FolderNode_TotalRecoverableItemSize = 4
$script:FolderNode_AggregateTotalRecoverableItemSize = 5
$script:FolderNode_Parent = 6
$script:FolderNode_Children = 7
$script:Mailbox_Name = 0
$script:Mailbox_UnusedSize = 1
$script:Mailbox_UnusedRecoverableItemSize = 2
$script:Mailbox_IsInherited = 3

$script:ROOT = @("`\", $null, 0, 0, 0, 0, $null, @{})

$MapGenerator_LocalizedStrings = ConvertFrom-StringData @'
MammothFolder = MailboxSize should be at least {0} to accommodate all your public folders.
MammothDumpsterFolder = MailboxRecoverableItemSize should be at least {0} to accommodate all your public folders.
ProcessFolder = Reading public folder list...
ProcessEmptyFile = Cannot generate mapping from empty file
LoadFolderHierarchy = Loading folder hierarchy...
CannotLoadFolders = Unable to load public folders...
AllocateFolders = Allocating folders to mailboxes...
AccommodateFolders = Trying to accommodate folders with their parent...
ExportFolderMap = Exporting folder mapping...
VersionErrorMessage = This script should be run on Exchange Server 2013 CU15 or later, or Exchange Server 2016 CU4 or later. The following servers are running other versions of Exchange Server:\n\t{0}
MailboxLimitError = Number of public folder mailboxes cannot exceed more than {0} for modern public folder migration.
'@

# Function that constructs the entire tree based on the folder path
# As and when it constructs it computes its aggregate folder size that included itself
function LoadFolderHierarchy() {
    foreach ($folder in $script:PublicFolders) {
        $folderSize = [long]$folder.FolderSize
        $recoverableItemSize = [long]$folder.DeletedItemSize

        # Start from root
        $parent = $script:ROOT

        #Stores the subpath of the folder currently getting processed
        $currentFolderPath = ""
        foreach ($familyMember in $folder.FolderName.Split('\', [System.StringSplitOptions]::RemoveEmptyEntries)) {
            $currentFolderPath = $currentFolderPath + "\"+ $familyMember
            # Try to locate the appropriate subfolder
            $child = $parent[$script:FolderNode_Children].Item($familyMember)
            if ($null -eq $child) {
                if ($folder.FolderName.Equals($currentFolderPath)) {
                    # Create this leaf node and add subfolder to parent's children
                    $child = @($folder.FolderName, $null, $folderSize, $folderSize, $recoverableItemSize, $recoverableItemSize, $parent, @{})
                    $parent[$script:FolderNode_Children].Add($familyMember, $child)
                } else {
                    # We have found a folder which is not in the stats file, set the size of such folders to zero.
                    $child = @($currentFolderPath, $null, 0, 0, 0, 0, $parent, @{})
                    $parent[$script:FolderNode_Children].Add($familyMember, $child)
                }
            }

            # Add child's individual size to parent's aggregate size
            $parent[$script:FolderNode_AggregateTotalItemSize] += $folderSize
            $parent[$script:FolderNode_AggregateTotalRecoverableItemSize] += $recoverableItemSize
            $parent = $child
        }
    }
}

# Function that assigns content mailboxes to public folders
# $node: Root node to be assigned to a mailbox
# $mailboxName: If not $null, we will attempt to accommodate folder in this mailbox
function AllocateMailbox() {
    param ($node, $mailboxName)

    if ($null -ne $mailboxName) {
        # Since a mailbox was supplied by the caller, we should first attempt to use it
        if ($node[$script:FolderNode_AggregateTotalItemSize] -le $script:PublicFolderMailboxes[$mailboxName][$script:Mailbox_UnusedSize] -and
            $node[$script:FolderNode_AggregateTotalRecoverableItemSize] -le $script:PublicFolderMailboxes[$mailboxName][$script:Mailbox_UnusedRecoverableItemSize]) {
            # Node's contents (including branch) can be completely fit into specified mailbox
            # Assign the folder to mailbox and update mailbox's remaining size
            $node[$script:FolderNode_Mailbox] = $mailboxName
            $script:PublicFolderMailboxes[$mailboxName][$script:Mailbox_UnusedSize] -= $node[$script:FolderNode_AggregateTotalItemSize]
            $script:PublicFolderMailboxes[$mailboxName][$script:Mailbox_UnusedRecoverableItemSize] -= $node[$script:FolderNode_AggregateTotalRecoverableItemSize]
            if ($script:PublicFolderMailboxes[$mailboxName][$script:Mailbox_IsInherited] -eq $false) {
                # This mailbox was not parent's content mailbox, but was created by a sibling
                $script:AssignedFolders += New-Object PSObject -Property @{FolderPath = $node[$script:FolderNode_Path]; TargetMailbox = $node[$script:FolderNode_Mailbox] }
            }

            return $mailboxName
        }
    }

    CheckMailboxCountLimit
    $newMailboxName = "Mailbox" + ($script:NEXT_MAILBOX++)
    $script:PublicFolderMailboxes[$newMailboxName] = @($newMailboxName, $MailboxSize, $MailboxRecoverableItemSize, $false)

    $node[$script:FolderNode_Mailbox] = $newMailboxName
    $script:AssignedFolders += New-Object PSObject -Property @{FolderPath = $node[$script:FolderNode_Path]; TargetMailbox = $node[$script:FolderNode_Mailbox] }
    if ($node[$script:FolderNode_AggregateTotalItemSize] -le $script:PublicFolderMailboxes[$newMailboxName][$script:Mailbox_UnusedSize] -and
        $node[$script:FolderNode_AggregateTotalRecoverableItemSize] -le $script:PublicFolderMailboxes[$newMailboxName][$script:Mailbox_UnusedRecoverableItemSize]) {
        # Node's contents (including branch) can be completely fit into the newly created mailbox
        # Assign the folder to mailbox and update mailbox's remaining size
        $script:PublicFolderMailboxes[$newMailboxName][$script:Mailbox_UnusedSize] -= $node[$script:FolderNode_AggregateTotalItemSize]
        $script:PublicFolderMailboxes[$newMailboxName][$script:Mailbox_UnusedRecoverableItemSize] -= $node[$script:FolderNode_AggregateTotalRecoverableItemSize]
        return $newMailboxName
    } else {
        # Since node's contents (including branch) could not be fitted into the newly created mailbox,
        # put it's individual contents into the mailbox
        $script:PublicFolderMailboxes[$newMailboxName][$script:Mailbox_UnusedSize] -= $node[$script:FolderNode_TotalItemSize]
        $script:PublicFolderMailboxes[$newMailboxName][$script:Mailbox_UnusedRecoverableItemSize] -= $node[$script:FolderNode_TotalRecoverableItemSize]
    }

    $subFolders = @(@($node[$script:FolderNode_Children].GetEnumerator()) | Sort-Object @{Expression= { $_.Value[$script:FolderNode_AggregateTotalItemSize] }; Ascending=$true })
    $script:PublicFolderMailboxes[$newMailboxName][$script:Mailbox_IsInherited] = $true
    foreach ($subFolder in $subFolders) {
        $newMailboxName = AllocateMailbox $subFolder.Value $newMailboxName
    }

    return $null
}

# Function to check if further optimization can be done on the output generated
function TryAccommodateSubFoldersWithParent() {
    $numAssignedFolders = $script:AssignedFolders.Count
    for ($index = $numAssignedFolders - 1 ; $index -ge 0 ; $index--) {
        $assignedFolder = $script:AssignedFolders[$index]

        # Locate folder's parent
        for ($jIndex = $index - 1 ; $jIndex -ge 0 ; $jIndex--) {
            if ($assignedFolder.FolderPath.StartsWith($script:AssignedFolders[$jIndex].FolderPath)) {
                # Found first ancestor
                $ancestor = $script:AssignedFolders[$jIndex]
                $usedMailboxSize = $MailboxSize - $script:PublicFolderMailboxes[$assignedFolder.TargetMailbox][$script:Mailbox_UnusedSize]
                $usedRecoverableMailboxSize = $MailboxRecoverableItemSize - $script:PublicFolderMailboxes[$assignedFolder.TargetMailbox][$script:Mailbox_UnusedRecoverableItemSize]
                if ($usedMailboxSize -le $script:PublicFolderMailboxes[$ancestor.TargetMailbox][$script:Mailbox_UnusedSize] -and
                    $usedRecoverableMailboxSize -le $script:PublicFolderMailboxes[$ancestor.TargetMailbox][$script:Mailbox_UnusedRecoverableItemSize]) {
                    # If the current mailbox can fit into its ancestor mailbox, add the former's contents to ancestor
                    # and remove the mailbox assigned to it.Update the ancestor mailbox's size accordingly
                    $script:PublicFolderMailboxes[$assignedFolder.TargetMailbox][$script:Mailbox_UnusedSize] = $MailboxSize
                    $script:PublicFolderMailboxes[$ancestor.TargetMailbox][$script:Mailbox_UnusedSize] -= $usedMailboxSize
                    $script:PublicFolderMailboxes[$assignedFolder.TargetMailbox][$script:Mailbox_UnusedRecoverableItemSize] = $MailboxRecoverableItemSize
                    $script:PublicFolderMailboxes[$ancestor.TargetMailbox][$script:Mailbox_UnusedRecoverableItemSize] -= $usedRecoverableMailboxSize
                    $assignedFolder.TargetMailbox = $null
                }

                break
            }
        }
    }

    if ($script:AssignedFolders.Count -gt 1) {
        $script:AssignedFolders = $script:AssignedFolders | Where-Object { $null -ne $_.TargetMailbox }
    }
}

# Check if all folders have size and dumpster size less than mailbox size and dumpster size respectively
function AssertFolderSizeLessThanQuota() {
    $currentMaxFolderSize = ($script:PublicFolders | Measure-Object -Property FolderSize -Maximum).Maximum
    $currentMaxRecoverableItemSize = ($script:PublicFolders | Measure-Object -Property DeletedItemSize -Maximum).Maximum

    $shouldFail = $false
    if ($currentMaxFolderSize -gt $MailboxSize) {
        Write-Host "[$($(Get-Date).ToString())]" ($MapGenerator_LocalizedStrings.MammothFolder -f  $currentMaxFolderSize)
        $shouldFail = $true
    }

    if ($currentMaxRecoverableItemSize -gt $MailboxRecoverableItemSize) {
        Write-Host "[$($(Get-Date).ToString())]" ($MapGenerator_LocalizedStrings.MammothDumpsterFolder -f  $currentMaxRecoverableItemSize)
        $shouldFail = $true
    }

    if ($shouldFail) {
        Write-Host "[$($(Get-Date).ToString())]" $MapGenerator_LocalizedStrings.CannotLoadFolders
        exit
    }
}

# Check if Exchange version of all public folder servers are greater than required CU
function AssertMinVersion() {
    $servers = Get-ExchangeServer
    $serversWithPf = (Get-Mailbox -PublicFolder | Select-Object ServerName | Sort-Object -Unique ServerName).ServerName.ToLower()
    $failedServers = @()

    foreach ($server in $servers) {
        # Check only those Exchange servers which have public folder mailboxes
        if (!$serversWithPf.Contains($server.Name.ToLower())) {
            continue
        }

        $version = $server.AdminDisplayVersion
        $hasMinE15Version = (($version.Major -eq $script:Exchange15MajorVersion) -and
            ($version.Minor -eq $script:Exchange15MinorVersion) -and
            ($version.Build -ge $script:Exchange15CUBuild))
        $hasMinE16Version = (($version.Major -eq $script:Exchange16MajorVersion) -and
            ($version.Minor -eq $script:Exchange16MinorVersion) -and
            ($version.Build -ge $script:Exchange16CUBuild))

        if (!$hasMinE15Version -and !$hasMinE16Version -and ($version.Minor -le $script:Exchange16MinorVersion)) {
            $failedServers += $server.Fqdn
        }
    }

    if ($failedServers.Count -gt 0) {
        Write-Error ($MapGenerator_LocalizedStrings.VersionErrorMessage -f ($failedServers -join "`n`t"))
        exit
    }
}

function CheckMailboxCountLimit() {
    if ($script:NEXT_MAILBOX -gt $script:MAILBOX_LIMIT) {
        Write-Error ($MapGenerator_LocalizedStrings.MailboxLimitError -f ($script:MAILBOX_LIMIT))
        exit
    }
}

# Assert if minimum version of exchange supported
AssertMinVersion

# Parse the CSV file
Write-Host "[$($(Get-Date).ToString())]" $MapGenerator_LocalizedStrings.ProcessFolder
$script:PublicFolders = Import-Csv $ImportFile

# Check if there is at least one public folder in existence
if (!$script:PublicFolders) {
    Write-Host "[$($(Get-Date).ToString())]" $MapGenerator_LocalizedStrings.ProcessEmptyFile
    return
}

# Check if all folder sizes are less than the quota
AssertFolderSizeLessThanQuota

Write-Host "[$($(Get-Date).ToString())]" $MapGenerator_LocalizedStrings.LoadFolderHierarchy
LoadFolderHierarchy

# Contains the list of instantiated public folder mailboxes
# Key: mailbox name, Value: unused mailbox size
$script:PublicFolderMailboxes = @{}
$script:AssignedFolders = @()
$script:NEXT_MAILBOX = 1

# Since all public folders mailboxes need to serve hierarchy for this migration and we cannot have more than 100 mailboxes to serve hierarchy. We are setting limit to 100
$script:MAILBOX_LIMIT = 100

Write-Host "[$($(Get-Date).ToString())]" $MapGenerator_LocalizedStrings.AllocateFolders
$null = AllocateMailbox $script:ROOT $null

Write-Host "[$($(Get-Date).ToString())]" $MapGenerator_LocalizedStrings.AccommodateFolders
TryAccommodateSubFoldersWithParent

Write-Host "[$($(Get-Date).ToString())]" $MapGenerator_LocalizedStrings.ExportFolderMap
$script:NEXT_MAILBOX = 2
$previous = $script:AssignedFolders[0]
$previousOriginalMailboxName = $script:AssignedFolders[0].TargetMailbox
$numAssignedFolders = $script:AssignedFolders.Count

# Prepare the folder object that is to be finally exported
# During the process, rename the mailbox assigned to it.
# This is done to prevent any gap in generated mailbox name sequence at the end of the execution of TryAccommodateSubFoldersWithParent function
for ($index = 0 ; $index -lt $numAssignedFolders ; $index++) {
    $current = $script:AssignedFolders[$index]
    $currentMailboxName = $current.TargetMailbox
    CheckMailboxCountLimit
    if ($previousOriginalMailboxName -ne $currentMailboxName) {
        $current.TargetMailbox = "Mailbox" + ($script:NEXT_MAILBOX++)
    } else {
        $current.TargetMailbox = $previous.TargetMailbox
    }

    $previous = $current
    $previousOriginalMailboxName = $currentMailboxName
}

# Since we are migrating Dumpsters, we are assigning a different mailbox for NON_IPM_SUBTREE if not already present
# to ensure that primary mailbox does not get filled with deleted folders during migration
CheckMailboxCountLimit
if (!($script:AssignedFolders | Select-Object FolderPath | Where-Object { $($_).FolderPath.CompareTo("\NON_IPM_SUBTREE") -eq 0 })) {
    $script:AssignedFolders += New-Object PSObject -Property @{FolderPath = "\NON_IPM_SUBTREE"; TargetMailbox = ("Mailbox" + ($script:NEXT_MAILBOX++)) }
}

# Export the folder mapping to CSV file
$script:AssignedFolders | Export-Csv -Path $ExportFile -Force -NoTypeInformation -Encoding "Unicode"
