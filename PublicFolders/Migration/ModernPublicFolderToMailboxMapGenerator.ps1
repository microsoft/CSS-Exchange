 # .SYNOPSIS
# ModernPublicFolderToMailboxMapGenerator.ps1
#    Generates a CSV file that contains the mapping of 2013/2016 public folder branch to mailbox
#
# .DESCRIPTION
#
# Copyright (c) 2011 Microsoft Corporation. All rights reserved.
#
# THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE ENTIRE RISK
# OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER.
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

$script:Exchange15MajorVersion = 15;
$script:Exchange15MinorVersion = 0;
$script:Exchange15CUBuild = 1263;
$script:Exchange16MajorVersion = 15;
$script:Exchange16MinorVersion = 1;
$script:Exchange16CUBuild = 669;

################ END OF DEFAULTS #################

# Folder Node's member indices
# This is an optimization since creating and storing objects as PSObject types
# is an expensive operation in powershell
# CLASSNAME_MEMBERNAME
$script:FOLDERNODE_PATH = 0;
$script:FOLDERNODE_MAILBOX = 1;
$script:FOLDERNODE_TOTALITEMSIZE = 2;
$script:FOLDERNODE_AGGREGATETOTALITEMSIZE = 3;
$script:FOLDERNODE_TOTALRECOVERABLEITEMSIZE = 4;
$script:FOLDERNODE_AGGREGATETOTALRECOVERABLEITEMSIZE = 5;
$script:FOLDERNODE_PARENT = 6;
$script:FOLDERNODE_CHILDREN = 7;
$script:MAILBOX_NAME = 0;
$script:MAILBOX_UNUSEDSIZE = 1;
$script:MAILBOX_UNUSEDRECOVERABLEITEMSIZE = 2;
$script:MAILBOX_ISINHERITED = 3;

$script:ROOT = @("`\", $null, 0, 0, 0, 0, $null, @{});

#load hashtable of localized string
Import-LocalizedData -BindingVariable MapGenerator_LocalizedStrings -FileName ModernPublicFolderToMailboxMapGenerator.strings.psd1

# Function that constructs the entire tree based on the folderpath
# As and when it constructs it computes its aggregate folder size that included itself
function LoadFolderHierarchy() 
{
    foreach ($folder in $script:PublicFolders)
    {
        $folderSize = [long]$folder.FolderSize;
        $recoverableItemSize = [long]$folder.DeletedItemSize;
        
        # Start from root
        $parent = $script:ROOT;
	
	    #Stores the subpath of the folder currently getting processed
        $currFolderPath = "";
        foreach ($familyMember in $folder.FolderName.Split('\', [System.StringSplitOptions]::RemoveEmptyEntries))
        {        
            $currFolderPath = $currFolderPath + "\"+ $familyMember;
            # Try to locate the appropriate subfolder
            $child = $parent[$script:FOLDERNODE_CHILDREN].Item($familyMember);
            if ($child -eq $null)
            {
                if($folder.FolderName.Equals($currFolderPath))
                {
                    # Create this leaf node and add subfolder to parent's children
                    $child = @($folder.FolderName, $null, $folderSize, $folderSize, $recoverableItemSize, $recoverableItemSize, $parent, @{});
                    $parent[$script:FOLDERNODE_CHILDREN].Add($familyMember, $child);
                }
                else
                {
                    # We have found a folder which is not in the stats file, set the size of such folders to zero.
                    $child = @($currFolderPath, $null, 0, 0, 0, 0, $parent, @{});
                    $parent[$script:FOLDERNODE_CHILDREN].Add($familyMember, $child);
                }
            }

            # Add child's individual size to parent's aggregate size
            $parent[$script:FOLDERNODE_AGGREGATETOTALITEMSIZE] += $folderSize;
            $parent[$script:FOLDERNODE_AGGREGATETOTALRECOVERABLEITEMSIZE] += $recoverableItemSize;
            $parent = $child;
        }
    }
}

# Function that assigns content mailboxes to public folders
# $node: Root node to be assigned to a mailbox
# $mailboxName: If not $null, we will attempt to accomodate folder in this mailbox
function AllocateMailbox()
{
    param ($node, $mailboxName)

    if ($mailboxName -ne $null)
    {
        # Since a mailbox was supplied by the caller, we should first attempt to use it
        if ($node[$script:FOLDERNODE_AGGREGATETOTALITEMSIZE] -le $script:PublicFolderMailboxes[$mailboxName][$script:MAILBOX_UNUSEDSIZE] -and
            $node[$script:FOLDERNODE_AGGREGATETOTALRECOVERABLEITEMSIZE] -le $script:PublicFolderMailboxes[$mailboxName][$script:MAILBOX_UNUSEDRECOVERABLEITEMSIZE])
        {
            # Node's contents (including branch) can be completely fit into specified mailbox
            # Assign the folder to mailbox and update mailbox's remaining size
            $node[$script:FOLDERNODE_MAILBOX] = $mailboxName;
            $script:PublicFolderMailboxes[$mailboxName][$script:MAILBOX_UNUSEDSIZE] -= $node[$script:FOLDERNODE_AGGREGATETOTALITEMSIZE];
            $script:PublicFolderMailboxes[$mailboxName][$script:MAILBOX_UNUSEDRECOVERABLEITEMSIZE] -= $node[$script:FOLDERNODE_AGGREGATETOTALRECOVERABLEITEMSIZE];
            if ($script:PublicFolderMailboxes[$mailboxName][$script:MAILBOX_ISINHERITED] -eq $false)
            {
                # This mailbox was not parent's content mailbox, but was created by a sibling
                $script:AssignedFolders += New-Object PSObject -Property @{FolderPath = $node[$script:FOLDERNODE_PATH]; TargetMailbox = $node[$script:FOLDERNODE_MAILBOX]};
            }

            return $mailboxName;
        }
    }

    CheckMailboxCountLimit;
    $newMailboxName = "Mailbox" + ($script:NEXT_MAILBOX++);
    $script:PublicFolderMailboxes[$newMailboxName] = @($newMailboxName, $MailboxSize, $MailboxRecoverableItemSize, $false);

    $node[$script:FOLDERNODE_MAILBOX] = $newMailboxName;
    $script:AssignedFolders += New-Object PSObject -Property @{FolderPath = $node[$script:FOLDERNODE_PATH]; TargetMailbox = $node[$script:FOLDERNODE_MAILBOX]};
    if ($node[$script:FOLDERNODE_AGGREGATETOTALITEMSIZE] -le $script:PublicFolderMailboxes[$newMailboxName][$script:MAILBOX_UNUSEDSIZE] -and 
        $node[$script:FOLDERNODE_AGGREGATETOTALRECOVERABLEITEMSIZE] -le $script:PublicFolderMailboxes[$newMailboxName][$script:MAILBOX_UNUSEDRECOVERABLEITEMSIZE])
    {
        # Node's contents (including branch) can be completely fit into the newly created mailbox
        # Assign the folder to mailbox and update mailbox's remaining size
        $script:PublicFolderMailboxes[$newMailboxName][$script:MAILBOX_UNUSEDSIZE] -= $node[$script:FOLDERNODE_AGGREGATETOTALITEMSIZE];
        $script:PublicFolderMailboxes[$newMailboxName][$script:MAILBOX_UNUSEDRECOVERABLEITEMSIZE] -= $node[$script:FOLDERNODE_AGGREGATETOTALRECOVERABLEITEMSIZE];
        return $newMailboxName;
    }
    else
    {
        # Since node's contents (including branch) could not be fitted into the newly created mailbox,
        # put it's individual contents into the mailbox
        $script:PublicFolderMailboxes[$newMailboxName][$script:MAILBOX_UNUSEDSIZE] -= $node[$script:FOLDERNODE_TOTALITEMSIZE];
        $script:PublicFolderMailboxes[$newMailboxName][$script:MAILBOX_UNUSEDRECOVERABLEITEMSIZE] -= $node[$script:FOLDERNODE_TOTALRECOVERABLEITEMSIZE];
    }

    $subFolders = @(@($node[$script:FOLDERNODE_CHILDREN].GetEnumerator()) | Sort @{Expression={$_.Value[$script:FOLDERNODE_AGGREGATETOTALITEMSIZE]}; Ascending=$true});
    $script:PublicFolderMailboxes[$newMailboxName][$script:MAILBOX_ISINHERITED] = $true;
    foreach ($subFolder in $subFolders)
    {
        $newMailboxName = AllocateMailbox $subFolder.Value $newMailboxName;
    }

    return $null;
}

# Function to check if further optimization can be done on the output generated
function TryAccomodateSubFoldersWithParent()
{
    $numAssignedFolders = $script:AssignedFolders.Count;
    for ($index = $numAssignedFolders - 1 ; $index -ge 0 ; $index--)
    {
        $assignedFolder = $script:AssignedFolders[$index];

        # Locate folder's parent
        for ($jindex = $index - 1 ; $jindex -ge 0 ; $jindex--)
        {
            if ($assignedFolder.FolderPath.StartsWith($script:AssignedFolders[$jindex].FolderPath))
            {
                # Found first ancestor
                $ancestor = $script:AssignedFolders[$jindex];
                $usedMailboxSize = $MailboxSize - $script:PublicFolderMailboxes[$assignedFolder.TargetMailbox][$script:MAILBOX_UNUSEDSIZE];
                $usedRecoverableMailboxSize = $MailboxRecoverableItemSize - $script:PublicFolderMailboxes[$assignedFolder.TargetMailbox][$script:MAILBOX_UNUSEDRECOVERABLEITEMSIZE];
                if ($usedMailboxSize -le $script:PublicFolderMailboxes[$ancestor.TargetMailbox][$script:MAILBOX_UNUSEDSIZE] -and
                    $usedRecoverableMailboxSize -le $script:PublicFolderMailboxes[$ancestor.TargetMailbox][$script:MAILBOX_UNUSEDRECOVERABLEITEMSIZE])
                {
                    # If the current mailbox can fit into its ancestor mailbox, add the former's contents to ancestor
                    # and remove the mailbox assigned to it.Update the ancestor mailbox's size accordingly
                    $script:PublicFolderMailboxes[$assignedFolder.TargetMailbox][$script:MAILBOX_UNUSEDSIZE] = $MailboxSize;
                    $script:PublicFolderMailboxes[$ancestor.TargetMailbox][$script:MAILBOX_UNUSEDSIZE] -= $usedMailboxSize;
                    $script:PublicFolderMailboxes[$assignedFolder.TargetMailbox][$script:MAILBOX_UNUSEDRECOVERABLEITEMSIZE] = $MailboxRecoverableItemSize;
                    $script:PublicFolderMailboxes[$ancestor.TargetMailbox][$script:MAILBOX_UNUSEDRECOVERABLEITEMSIZE] -= $usedRecoverableMailboxSize;
                    $assignedFolder.TargetMailbox = $null;
                }

                break;
            }
        }
    }
    
    if ($script:AssignedFolders.Count -gt 1)
    {
        $script:AssignedFolders = $script:AssignedFolders | where {$_.TargetMailbox -ne $null};
    }
}

# Check if all folders have size and dumpster size less than mailbox size and dumpster size respectively
function AssertFolderSizeLessThanQuota()
{
     $foldersOverQuota = 0;
     $currMaxFolderSize = ($script:PublicFolders | Measure-Object -Property FolderSize -Maximum).Maximum;
     $currMaxRecoverableItemSize = ($script:PublicFolders | Measure-Object -Property DeletedItemSize -Maximum).Maximum;

     $shouldFail = $false;
     if($currMaxFolderSize -gt $MailboxSize)
     {
        Write-Host "[$($(Get-Date).ToString())]" ($MapGenerator_LocalizedStrings.MammothFolder -f  $currMaxFolderSize);
        $shouldFail = $true;
     }

     if($currMaxRecoverableItemSize -gt $MailboxRecoverableItemSize)
     {
        Write-Host "[$($(Get-Date).ToString())]" ($MapGenerator_LocalizedStrings.MammothDumpsterFolder -f  $currMaxRecoverableItemSize);
        $shouldFail = $true;
     }

     if($shouldFail)
     {
         Write-Host "[$($(Get-Date).ToString())]" $MapGenerator_LocalizedStrings.CannotLoadFolders;
         exit;
     }
}

# Check if Exchange version of all public folder servers are greater than required CU
function AssertMinVersion()
{
    $servers = Get-ExchangeServer;
    $serversWithPf = (Get-Mailbox -PublicFolder | select ServerName | Sort-Object -Unique ServerName).ServerName.ToLower()
    $failedServers = @();

    foreach ($server in $servers)
    {
        # Check only those Exchange servers which have public folder mailboxes
        if(!$serversWithPf.Contains($server.Name.ToLower()))
        {
            continue;
        }
        
        $version = $server.AdminDisplayVersion;
        $hasMinE15Version = (($version.Major -eq $script:Exchange15MajorVersion) -and
            ($version.Minor -eq $script:Exchange15MinorVersion) -and
            ($version.Build -ge $script:Exchange15CUBuild));
        $hasMinE16Version = (($version.Major -eq $script:Exchange16MajorVersion) -and
            ($version.Minor -eq $script:Exchange16MinorVersion) -and
            ($version.Build -ge $script:Exchange16CUBuild));

        if (!$hasMinE15Version -and !$hasMinE16Version -and ($version.Minor -le $script:Exchange16MinorVersion))
        {
            $failedServers += $server.Fqdn;
        }
    }

    if ($failedServers.Count -gt 0)
    {
        Write-Error ($MapGenerator_LocalizedStrings.VersionErrorMessage -f ($failedServers -join "`n`t"))
        exit;
    }
}

function CheckMailboxCountLimit(){
    if ($script:NEXT_MAILBOX -gt $script:MAILBOX_LIMIT) {
        Write-Error ($MapGenerator_LocalizedStrings.MailboxLimitError -f ($script:MAILBOX_LIMIT))
        exit;
    }
}

# Assert if minimum version of exchange supported 
AssertMinVersion

# Parse the CSV file
Write-Host "[$($(Get-Date).ToString())]" $MapGenerator_LocalizedStrings.ProcessFolder;
$script:PublicFolders = Import-CSV $ImportFile;

# Check if there is atleast one public folder in existence
if (!$script:PublicFolders)
{
    Write-Host "[$($(Get-Date).ToString())]" $MapGenerator_LocalizedStrings.ProcessEmptyFile;
    return;
}

# Check if all folder sizes are less than the quota
AssertFolderSizeLessThanQuota

Write-Host "[$($(Get-Date).ToString())]" $MapGenerator_LocalizedStrings.LoadFolderHierarchy;
LoadFolderHierarchy;

# Contains the list of instantiated public folder maiboxes
# Key: mailbox name, Value: unused mailbox size
$script:PublicFolderMailboxes = @{};
$script:AssignedFolders = @();
$script:NEXT_MAILBOX = 1;

# Since all public folders mailboxes need to serve hierarchy for this migration and we cannot have more than 100 mailboxes to serve hierarchy. We are setting limit to 100
$script:MAILBOX_LIMIT = 100;

Write-Host "[$($(Get-Date).ToString())]" $MapGenerator_LocalizedStrings.AllocateFolders;
$ignoreReturnValue = AllocateMailbox $script:ROOT $null;

Write-Host "[$($(Get-Date).ToString())]" $MapGenerator_LocalizedStrings.AccomodateFolders;
TryAccomodateSubFoldersWithParent;

Write-Host "[$($(Get-Date).ToString())]" $MapGenerator_LocalizedStrings.ExportFolderMap;
$script:NEXT_MAILBOX = 2;
$previous = $script:AssignedFolders[0];
$previousOriginalMailboxName = $script:AssignedFolders[0].TargetMailbox;
$numAssignedFolders = $script:AssignedFolders.Count;

# Prepare the folder object that is to be finally exported
# During the process, rename the mailbox assigned to it.  
# This is done to prevent any gap in generated mailbox name sequence at the end of the execution of TryAccomodateSubFoldersWithParent function
for ($index = 0 ; $index -lt $numAssignedFolders ; $index++)
{
    $current = $script:AssignedFolders[$index];
    $currentMailboxName = $current.TargetMailbox;
    CheckMailboxCountLimit;
    if ($previousOriginalMailboxName -ne $currentMailboxName)
    {
        $current.TargetMailbox = "Mailbox" + ($script:NEXT_MAILBOX++);
    }
    else
    {
        $current.TargetMailbox = $previous.TargetMailbox;
    }

    $previous = $current;
    $previousOriginalMailboxName = $currentMailboxName;
}

# Since we are migrating Dumpsters, we are assigning a different mailbox for NON_IPM_SUBTREE if not already present
# to ensure that primary mailbox does not get filled with deleted folders during migration
CheckMailboxCountLimit;
if(!($script:AssignedFolders| select FolderPath | where {$($_).FolderPath.CompareTo("\NON_IPM_SUBTREE") -eq 0}))
{
    $script:AssignedFolders += New-Object PSObject -Property @{FolderPath = "\NON_IPM_SUBTREE"; TargetMailbox = ("Mailbox" + ($script:NEXT_MAILBOX++))};    
}

# Export the folder mapping to CSV file
$script:AssignedFolders | Export-CSV -Path $ExportFile -Force -NoTypeInformation -Encoding "Unicode";
