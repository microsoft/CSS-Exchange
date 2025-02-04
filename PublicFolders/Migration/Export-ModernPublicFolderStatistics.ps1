# .SYNOPSIS
# Export-ModernPublicFolderStatistics.ps1
#    Generates a CSV file that contains the list of public folders and their individual sizes
#
# .DESCRIPTION
#
# Copyright (c) 2016 Microsoft Corporation. All rights reserved.
#
# THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE ENTIRE RISK
# OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER.

Param(
    # File to export to
    [Parameter(
        Mandatory=$true,
        HelpMessage = "Full path of the output file to be generated. If only filename is specified, then the output file will be generated in the current directory.")]
    [ValidateNotNull()]
    [string] $ExportFile
    )

#load hashtable of localized string
Import-LocalizedData -BindingVariable ModernPublicFolderStatistics_LocalizedStrings -FileName Export-ModernPublicFolderStatistics.strings.psd1

################ START OF DEFAULTS ################

$ErrorActionPreference = 'Stop'
$WarningPreference = 'SilentlyContinue';

$script:Exchange15MajorVersion = 15;
$script:Exchange15MinorVersion = 0;
$script:Exchange15CUBuild = 1263;
$script:Exchange16MajorVersion = 15;
$script:Exchange16MinorVersion = 1;
$script:Exchange16CUBuild = 669;

################ END OF DEFAULTS #################

# Function that determines if the given NON IPM folder should be included.
function ShouldIncludeNonIpmFolder()
{
    param($PublicFolderIdentity);

    # Append a "\" to the path. Since paths in the whitelist end with a "\",
    # this is required to ensure the root gets matched correctly.
    $folderPath = $PublicFolderIdentity.TrimEnd('\') + '\';

    foreach ($includedFolder in $script:IncludedNonIpmSubtree)
    {
        if ($folderPath.StartsWith($includedFolder))
        {
            return $true;
        }
    }

    return $false;
}

# Recurse through IPM_SUBTREE to get the folder path foreach Public Folder
function ReadIpmSubtree()
{
    $badFolders = @();
    $ipmSubtreeFolderList = Get-PublicFolder "\" -Recurse -ResultSize:Unlimited;

    foreach ($folder in $ipmSubtreeFolderList)
    {
        if (IsValidFolderName $folder.Name)
        {
            $nameAndDumpsterEntryId = New-Object PSObject -Property @{FolderIdentity = $folder.Identity.ToString(); DumpsterEntryId = $folder.DumpsterEntryId}
            $script:IdToNameAndDumpsterMap.Add($folder.EntryId, $nameAndDumpsterEntryId);
        }
        else
        {
            # Mark the folder as invalid but continue so that we can find all the bad ones.
            $badFolders += $folder;
        }
    }

    # Ensure there are no folders with invalid names.
    AssertAllFolderNamesValid $badFolders;

    # Root path will have a "\" at the end while other folders doesn't. Normalize by removing it.
    $ipmSubtreeRoot = $ipmSubtreeFolderList | Where-Object { $null -eq $_.ParentPath };
    $nameAndDumpsterEntryId = New-Object PSObject -Property @{FolderIdentity = ""; DumpsterEntryId = $ipmSubtreeRoot.DumpsterEntryId}
    $script:IdToNameAndDumpsterMap[$ipmSubtreeRoot.EntryId] = $nameAndDumpsterEntryId;

    return $ipmSubtreeFolderList.Count;
}

# Recurse through NON_IPM_SUBTREE to get the folder path foreach Public Folder
function ReadNonIpmSubtree()
{
    $badFolders = @();
    $nonIpmSubtreeFolderList = Get-PublicFolder "\NON_IPM_SUBTREE" -Recurse -ResultSize:Unlimited;

    foreach ($folder in $nonIpmSubtreeFolderList)
    {
        $folderIdentity = $folder.Identity.ToString();

        if (ShouldIncludeNonIpmFolder($folderIdentity))
        {
            if (IsValidFolderName $folder.Name)
            {
                $nameAndDumpsterEntryId = New-Object PSObject -Property @{FolderIdentity = $folder.Identity.ToString(); DumpsterEntryId = ""+$folder.DumpsterEntryId};
                $script:IdToNameAndDumpsterMap.Add($folder.EntryId, $nameAndDumpsterEntryId);

                $script:NonIpmSubtreeFolders.Add($folder.EntryId, $folderIdentity);
            }
            else
            {
                # Mark the folder as invalid but continue so that we can find all the bad ones.
                $badFolders += $folder;
            }
        }
    }

    # Ensure there are no folders with invalid names.
    AssertAllFolderNamesValid $badFolders;

    # Add the root folder to the list since this wouldn't otherwise be included.
    $nonIpmSubtreeRoot = $nonIpmSubtreeFolderList | Where-Object { $null -eq $_.ParentPath };
    $nameAndDumpsterEntryId = New-Object PSObject -Property @{FolderIdentity = $nonIpmSubtreeRoot.Identity.ToString(); DumpsterEntryId = $nonIpmSubtreeRoot.DumpsterEntryId};
    $script:IdToNameAndDumpsterMap.Add($nonIpmSubtreeRoot.EntryId, $nameAndDumpsterEntryId);
    $script:NonIpmSubtreeFolders.Add($nonIpmSubtreeRoot.EntryId, $nonIpmSubtreeRoot.Identity.ToString());

    return $nonIpmSubtreeFolderList.Count;
}

# Function that executes statistics
function GatherStatistics()
{
    $index = 0;
    $PFIDENTITY_INDEX = 2;

    #Prepare and call the Get-PublicFolderStatistics cmdlet
    $publicFolderStatistics = @(Get-PublicFolderStatistics -ResultSize:Unlimited);

    #Explcitly get statistics for NON_IPM_SUBTREE since this is not included by default.
    $publicFolderStatistics += @($script:NonIpmSubtreeFolders.Values | Get-PublicFolderStatistics -ResultSize:Unlimited);

    #Fill Folder Statistics
    while ($index -lt $publicFolderStatistics.Count)
    {
        $publicFolderEntryId = $($publicFolderStatistics[$index].EntryId);
        $dumpsterEntryId = $script:IdToNameAndDumpsterMap[$publicFolderEntryId].DumpsterEntryId;
        $publicFolderIdentity = $script:IdToNameAndDumpsterMap[$publicFolderEntryId].FolderIdentity;
        
        # We have a public folder in NON_IPM_SUBTREE\DUMPSTER_ROOT
        # Check if its a normal folder or dumpster folder
        if($publicFolderIdentity.StartsWith("\NON_IPM_SUBTREE\DUMPSTER_ROOT\"))
        {
            # Continue if dumpster is not set or
            # Folder is not present in NON IPM Subtree or
            # Folder's dumpster is not present in "\NON_IPM_SUBTREE\DUMPSTER_ROOT"
            if([String]::IsNullOrEmpty($dumpsterEntryId) -or (!$script:NonIpmSubtreeFolders.ContainsKey($dumpsterEntryId)) -or
               (!$script:NonIpmSubtreeFolders[$dumpsterEntryId].StartsWith("\NON_IPM_SUBTREE\DUMPSTER_ROOT\")))
            {
                $index++;
                continue;
            }
            
            if($script:FolderStatistics.ContainsKey($dumpsterEntryId))
            {
                # We already have processed its dumpster
                # Check which is the deepest folder, deepest one is the folder and shorter one is its dumpster
                # When processing dumpster we dont want to have a deleted folder and its dumpster size taken
                # into account twice. So we always take deleted folder into account instead of its dumpster.
                $dumpsterFolderIdentity = $script:FolderStatistics[$dumpsterEntryId][$PFIDENTITY_INDEX];
                $dumpsterDepth = ([Regex]::Matches($dumpsterFolderIdentity, "\\")).Count;
                $folderDepth = ([Regex]::Matches($publicFolderIdentity, "\\")).Count;
                if($folderDepth -gt $dumpsterDepth)
                {
                    $script:FolderStatistics.Remove($dumpsterEntryId);
                }
                else
                {
                    $index++;
                    continue;
                }
            }
        }
        $newFolder = @();
        $newFolder += $($publicFolderStatistics[$index].TotalItemSize.ToBytes());
        $newFolder += $($publicFolderStatistics[$index].TotalDeletedItemSize.ToBytes())
        $newFolder += $publicFolderIdentity;
        $newFolder += $dumpsterEntryId;
        $script:FolderStatistics[$publicFolderEntryId] = $newFolder;
        $index++;
    }
}

# Writes the current progress
function WriteProgress()
{
    param($statusFormat, $statusProcessed, $statusTotal)
    Write-Progress -Activity $ModernPublicFolderStatistics_LocalizedStrings.ProgressBarActivity `
        -Status ($statusFormat -f $statusProcessed,$statusTotal) `
        -PercentComplete (100*($statusProcessed/$statusTotal));
}

# Function that creates folder objects in right way for exporting
function CreateFolderObjects()
{
    $index = 1;
    $PFSIZE_INDEX = 0;
    $PFDELETEDSIZE_INDEX = 1;
    $PFIDENTITY_INDEX = 2;

    foreach ($publicFolderEntryId in $script:FolderStatistics.Keys)
    {
        $IsNonIpmSubtreeFolder = $script:NonIpmSubtreeFolders.ContainsKey($publicFolderEntryId);
        $publicFolderIdentity = "";

        if ($IsNonIpmSubtreeFolder)
        {
            $publicFolderIdentity = $script:FolderStatistics[$publicFolderEntryId][$PFIDENTITY_INDEX];
            $dumpsterSize = $script:FolderStatistics[$publicFolderEntryId][$PFDELETEDSIZE_INDEX];
            $folderSize = $script:FolderStatistics[$publicFolderEntryId][$PFSIZE_INDEX];
        }
        else
        {
            $publicFolderIdentity = "\IPM_SUBTREE" + $script:FolderStatistics[$publicFolderEntryId][$PFIDENTITY_INDEX];
            $dumpsterSize = $script:FolderStatistics[$publicFolderEntryId][$PFDELETEDSIZE_INDEX];
            $folderSize = $script:FolderStatistics[$publicFolderEntryId][$PFSIZE_INDEX];
        }

        if ($publicFolderIdentity -ne "")
        {
            WriteProgress $ModernPublicFolderStatistics_LocalizedStrings.ProcessedFolders $index $script:FolderStatistics.Keys.Count

            # Create a folder object to be exported to a CSV
            $newFolderObject = New-Object PSObject -Property @{FolderName = $publicFolderIdentity; FolderSize = $folderSize; DeletedItemSize = $dumpsterSize}
            [void]$script:ExportFolders.Add($newFolderObject);
            $index++;
        }
    }

    WriteProgress $ModernPublicFolderStatistics_LocalizedStrings.ProcessedFolders $script:FolderStatistics.Keys.Count $script:FolderStatistics.Keys.Count
}

# Check if Exchange version of all public folder servers are greater than required CU
function AssertMinVersion()
{
    $servers = Get-ExchangeServer;
    $serversWithPf = (Get-Mailbox -PublicFolder | select ServerName | Sort-Object -Unique ServerName).ServerName.ToLower()
    $failedServers = @();

    foreach ($server in $servers)
    {
         # Check only those Exchange servers which have public folders mailboxes
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

        # If version is less than minimum version of Exchange15 or Exchange16, or if the version belongs to Exchange19 onwards, then add the server to failed list.
        if (!$hasMinE15Version -and !$hasMinE16Version -and ($version.Minor -le $script:Exchange16MinorVersion))
        {
            $failedServers += $server.Fqdn;
        }
    }

    if ($failedServers.Count -gt 0)
    {
        Write-Error ($ModernPublicFolderStatistics_LocalizedStrings.VersionErrorMessage -f ($failedServers -join "`n`t"))
        exit;
    }
}

# Validate public folders are present.
function AssertPublicFoldersPresent()
{
    [void](Get-PublicFolder -ErrorAction Stop)
}

# Validate path to the ExportFile exists.
function AssertExportFileValid()
{
    param($ExportFile);

    # Check if the path leading upto the item is valid.
    $parent = Split-Path $ExportFile -Parent;
    $parentValid = ($parent -eq "") -or (Test-Path $parent -PathType Container);

    if ($parentValid)
    {
        # In case the item already exists, it should be a file.
        $isDirectory = Test-Path $ExportFile -PathType Container;

        if (!$isDirectory)
        {
            return;
        }
    }

    Write-Error ($ModernPublicFolderStatistics_LocalizedStrings.InvalidExportFile -f $ExportFile);
    exit;
}

# Validate public folder names does not have invalid characters in it.
function IsValidFolderName()
{
    param($Name);

    return !($Name.Contains('\') -or $Name.Contains('/'));
}

# Ensure there are no folders with invalid characters, or fail otherwise.
function AssertAllFolderNamesValid()
{
    param($BadFolders);

    if ($BadFolders.Count -gt 0)
    {
        $folderList = ($BadFolders | ForEach-Object { $_.ParentPath + ' -> ' + $_.Name }) -join "`n`t";
        Write-Error ($ModernPublicFolderStatistics_LocalizedStrings.InvalidFolderNames -f $folderList);
        exit;
    }
}


####################################################################################################
# Script starts here
####################################################################################################

# Assert pre-requisites.
AssertMinVersion
AssertPublicFoldersPresent
AssertExportFileValid $ExportFile

# Array of folder objects for exporting
$script:ExportFolders = $null;

# Hash table that contains the folder list (IPM_SUBTREE via Get-PublicFolderStatistics)
$script:FolderStatistics = @{};

# Hash table that contains the folder list (NON_IPM_SUBTREE via Get-PublicFolder)
$script:NonIpmSubtreeFolders = @{};

# Hash table EntryId to Name to map FolderPath
$script:IdToNameAndDumpsterMap = @{};

# Folders from NON_IPM_SUBTREE that are to be included while computing statistics
$script:IncludedNonIpmSubtree = @("\NON_IPM_SUBTREE\EFORMS REGISTRY", "\NON_IPM_SUBTREE\DUMPSTER_ROOT");


# Just making sure that all the paths in the whitelist have a trailing '\'.
# This will be of significance later on when the filtering happens.
$script:IncludedNonIpmSubtree = @($script:IncludedNonIpmSubtree | ForEach-Object { $_.TrimEnd('\') + '\' })

# Recurse through IPM_SUBTREE to get the folder path for each Public Folder
# Remarks:
# This is done so we can overcome a limitation of Get-PublicFolderStatistics
# where it fails to display Unicode chars in the FolderPath value, but
# Get-PublicFolder properly renders these characters
Write-Host "[$($(Get-Date).ToString())]" $ModernPublicFolderStatistics_LocalizedStrings.ProcessingIpmSubtree;
$folderCount = ReadIpmSubtree;
Write-Host "[$($(Get-Date).ToString())]" ($ModernPublicFolderStatistics_LocalizedStrings.ProcessingIpmSubtreeComplete -f $folderCount);

# Recurse through NON_IPM_SUBTREE to get the folder path for each Public Folder
Write-Host "[$($(Get-Date).ToString())]" $ModernPublicFolderStatistics_LocalizedStrings.ProcessingNonIpmSubtree;
$folderCount = ReadNonIpmSubtree;
Write-Host "[$($(Get-Date).ToString())]" ($ModernPublicFolderStatistics_LocalizedStrings.ProcessingNonIpmSubtreeComplete -f $folderCount);

# Gathering statistics
Write-Host "[$($(Get-Date).ToString())]" ($ModernPublicFolderStatistics_LocalizedStrings.RetrievingStatistics);
GatherStatistics;
Write-Host "[$($(Get-Date).ToString())]" ($ModernPublicFolderStatistics_LocalizedStrings.RetrievingStatisticsComplete -f $script:FolderStatistics.Count);

# Creating folder objects for exporting to a CSV
Write-Host "[$($(Get-Date).ToString())]" $ModernPublicFolderStatistics_LocalizedStrings.ExportToCSV;
$script:ExportFolders = New-Object System.Collections.ArrayList -ArgumentList ($script:FolderStatistics.Count);
CreateFolderObjects;

# Export the folders to CSV file
$script:ExportFolders | Sort-Object -Property FolderName | Select FolderSize, DeletedItemSize, FolderName | Export-CSV -Path $ExportFile -Force -NoTypeInformation -Encoding "Unicode";
