#################################################################################
#
# The sample scripts are not supported under any Microsoft standard support 
# program or service. The sample scripts are provided AS IS without warranty 
# of any kind. Microsoft further disclaims all implied warranties including, without 
# limitation, any implied warranties of merchantability or of fitness for a particular 
# purpose. The entire risk arising out of the use or performance of the sample scripts 
# and documentation remains with you. In no event shall Microsoft, its authors, or 
# anyone else involved in the creation, production, or delivery of the scripts be liable 
# for any damages whatsoever (including, without limitation, damages for loss of business 
# profits, business interruption, loss of business information, or other pecuniary loss) 
# arising out of the use of or inability to use the sample scripts or documentation, 
# even if Microsoft has been advised of the possibility of such damages.
#
#################################################################################
#
# .SYNOPSIS
#    The script verifies if the source environment is ready for migration of public folders to cloud. It does so by checking the limits of hierarchy, child, content items on public folders.
#    It verifies the public folder and dumpster mapping and also if the mail enabled public folders (MEPF) are in sync with the AD 
#    Then it presents a list of orphaned user permissions that should be removed before migration
#    The findings of the script are presented in a log file with an actionable message
#
# .DESCRIPTION
#    The script must be executed from an Exchange 2010*, 2013, 2016 or 2019 Management Shell window providing access to public folders in
#    the local Exchange deployment.
#    Copyright (c) 2018 Microsoft Corporation. All rights reserved.
#
# .PARAMETER verifyMEPF*
#    Optional parameter which specifies if MEPF needs to be cross verified with AD. By default it is true. The option works for Exchange Server 2013 and above
#
# .PARAMETER checkLimits
#    Optional parameter which specifies if Limits needs to be checked for public folder. By default it is true
#
# .PARAMETER verifyDumpsterMapping*
#    Optional parameter which specifies if public folder mapping with dumpsters needs to be verified. By default it is true. The option works for Exchange Server 2013 and above
#
# .PARAMETER checkPermissions
#    Optional parameter which specifies if orphan permissions need to be checked on public folders. By default it is true
#
# .PARAMETER  ProgressLogFile
#   File to log EntryIds of folders that were successfully updated. The content of this file may
#   become handy to save time if the previous execution of the script was aborted and you want to restart
#   from the point where the script stopped. To do this, simply get the contents of the file (get-content) and 
#   provide the data to the ExcludeFolderEntryIds parameter.
#
#   The default log name is SourceSideValidations.[yyyyMMdd_HHmm].log where the portion in square brackets
#   gets replaced with the current date and time at the moment of execution of the script.
#
# .PARAMETER ipmFolderFile
#    File to store the Ipm (end user visible) folders info. Its purpose is to scale the script and resume the iteration of ipm folders from where it left the last time.
#    The default value is "ipmFolderFile.csv"
#
# .PARAMETER DumpsterFolderFile
#    File to store the Dumpster folders info. Its purpose is to scale the script and resume the iteration of dumpster folders from where it left the last time.
#    The default value is "DumpsterFolderFile.csv"
#
# .PARAMETER IpmEformsFolderFile
#    File to store the Eforms folders info. Its purpose is to scale the script and resume the iteration of Eforms folders from where it left the last time.
#    The default value is "IpmEformsFolderFile.csv"
#
# .EXAMPLE
#    .\SourceSideValidations.ps1 -verifyMEPF $false -verifyDumpsterMapping $true -checkLimits $false -checkPermissions $false
#    
#    This example shows how to verify only dumpster mapping. Results will be stored in error_output.log.
#

param(
    [Parameter(Mandatory = $false)]
    [bool] $verifyMEPF = $true,

    [Parameter(Mandatory = $false)]
    [bool] $checkLimits = $true,

    [Parameter(Mandatory = $false)]
    [bool] $verifyDumpsterMapping = $true,

    [Parameter(Mandatory = $false)]
    [bool] $checkPermissions = $true,

    [Parameter(Mandatory = $false)]
    [bool] $startFresh = $true,
    
    [string]$ProgressLogFile = ".\SourceSideValidations.$((Get-Date).ToString('yyyyMMdd_HH')).log",
    [string]$ipmFolderFile = "ipmFolderFile.txt",
    [string]$DumpsterFolderFile = "DumpsterFolderFile.txt",
    [string]$IpmEformsFolderFile = "IpmEformsFolderFile.txt"
)

$start = (Get-Date)
$errorList = New-Object System.Collections.ArrayList
$ipmMEPFFile = "ipmMEPFFile.txt"
$ipmFoldersListFile = "ipmFoldersListFile.txt"
$nonipmFoldersListFile = "dumpsterFoldersListFile.txt"
$dumpsterFoldersList = @()
$ipmFolderMap = @{}
$dumpsterEntryIdToFolderMap = @{}
$ipmTraversed = @()
$nonIpmTraversed = @()
$eformsTraversed = @()
$legacy = $false
$errorsFound = $false
$global:missingCount = 0
$global:mismatchCount = 0
$global:dumpsterMismatchCount = 0
$global:corruptedPermission = $false

$root = Get-Publicfolder (Get-PublicFolder "\").ParentFolder
$ipmEformsFoldersList = [System.Collections.ArrayList](@(Get-PublicFolder -GetChildren "\NON_IPM_SUBTREE\EFORMS REGISTRY"  | Select-Object EntryId))

$localServerVersion = (Get-ExchangeServer $env:COMPUTERNAME -ErrorAction:Stop).AdminDisplayVersion;
if ( $localServerVersion.Major -eq 14 ) {
    $verifyDumpsterMapping = $false 
    $verifyMEPF = $false
    $legacy = $true
}

if ($startFresh) {
    if (Test-Path "$(Get-Location)\$($ipmFolderFile)") {
        Remove-Item $ipmFolderFile -Confirm:$false
        Remove-Item $ipmMEPFFile -Confirm:$false
    }
    if (Test-Path "$(Get-Location)\$($ipmFoldersListFile)") {
        Remove-Item $ipmFoldersListFile -Confirm:$false
    }
    if (Test-Path "$(Get-Location)\$($DumpsterFolderFile)") {
        Remove-Item $DumpsterFolderFile -Confirm:$false
    }
    if (Test-Path "$(Get-Location)\$($IpmEformsFolderFile)") {
        Remove-Item $IpmEformsFolderFile -Confirm:$false
    }
    if (Test-Path "$(Get-Location)\$($nonipmFoldersListFile)") {
        Remove-Item $nonipmFoldersListFile -Confirm:$false
    }
    if (Test-Path "$(Get-Location)\$($ProgressLogFile)") {
        Remove-Item $ProgressLogFile -Confirm:$false
    }
}

if (!(Test-Path "$(Get-Location)\$($ipmFolderFile)") -or ($null -eq (Get-Content $ipmFolderFile))) {
    Out-File $ipmFolderFile 
    Out-File $ipmMEPFFile 
}
else {
    $ipmTraversed = Get-Content $ipmFolderFile   
}
if (!(Test-Path "$(Get-Location)\$($ipmFoldersListFile)")) {
    $ipmFolderList = [System.Collections.ArrayList](@(Get-PublicFolder -GetChildren "\" |Select-Object EntryId))
}
else {
    $ipmFolderList = [System.Collections.ArrayList](Get-Content $ipmFoldersListFile)
}

if ($verifyDumpsterMapping -eq $true) {
    if (!(Test-Path "$(Get-Location)\$($DumpsterFolderFile)") -or ($null -eq (Get-Content $DumpsterFolderFile)) ) {
        Out-File $DumpsterFolderFile 
    }
    else {
        $nonIpmTraversed = Get-Content $DumpsterFolderFile
    }

    if (!(Test-Path "$(Get-Location)\$($IpmEformsFolderFile)") -or ($null -eq (Get-Content $IpmEformsFolderFile)) ) {
        Out-File $IpmEformsFolderFile 
    }
    else {
        $eformsTraversed = Get-Content $IpmEformsFolderFile
    }

    if (!(Test-Path "$(Get-Location)\$($nonipmFoldersListFile)")) {
        $dumpsterFoldersList = [System.Collections.ArrayList](@(Get-PublicFolder -GetChildren "\NON_IPM_SUBTREE\DUMPSTER_ROOT\DUMPSTER_EXTEND\RESERVED_1\RESERVED_1" | Where-Object DumpsterEntryId -NotLike $root.EntryId |Select-Object EntryId))
    }
    else {
        $dumpsterFoldersList = [System.Collections.ArrayList](Get-Content $nonipmFoldersListFile)
    }
}

function ipmFolderToDumpsterMapping ($ipmFolder) {
    $id = $ipmFolder.Identity
    if ($null -eq $ipmFolder.DumpsterEntryId) {
        $errorList.Add("ipm Folder $id does not have a dumpster entry id") > $null
        Continue;
    }
    $Dumpster = Get-PublicFolder $ipmFolder.DumpsterEntryId
    if ($Dumpster.ParentPath.Contains("\NON_IPM_SUBTREE\DUMPSTER_ROOT")) {
        if (!$dumpsterEntryIdToFolderMap.ContainsKey(($Dumpster.EntryId))) {
            $dumpsterEntryIdToFolderMap.Add($Dumpster.EntryId, $Dumpster)
        }
        
        if ($dumpster.DumpsterEntryId.CompareTo($ipmFolder.EntryId) -ne 0) {
            $errorList.Add("ipm Folder $id does not have a correct reverse mapping with dumpster" + $dumpster.Identity) > $null
            $global:dumpsterMismatchCount++
        }
    }
    else {
        $errorList.Add("ipm Folder $id has an invalid dumpster which is " + $ipmFolder.DumpsterEntryId) > $null
        $global:dumpsterMismatchCount++
    }
}

function checkOrphanMepfs($uniqueEntryIdsAd, $entryIdsPf) {
    $i = 0
    $j = 0
    while ($i -lt $uniqueEntryIdsAd.Count -and $j -lt $entryIdsPf.Count) {
        $result = $uniqueEntryIdsAd[$i].EntryId.CompareTo($entryIdsPf[$j].EntryId)
        if ($result -eq 0) {
            $AdGuid = $uniqueEntryIdsAd[$i].Guid.ToString()
            if ($AdGuid.CompareTo($entryIdsPf[$j].MailRecipientGuid) -ne 0) {
                $global:mismatchCount++               
                $errorList.Add("MEPF GUID Mismatch found for EntryId " + $entryIdsPf[$j].EntryId) > $null
            }
            $i++
            $j++
        }
        elseif ( $result -eq -1) {
            $global:missingCount++
            $errorList.Add("This EntryID is present in AD but not in Exchange, " + $uniqueEntryIdsAd[$i].EntryId) > $null
            $i++
        }
        else {
            $global:missingCount++
            $errorList.Add("This EntryID is present in Exchange but not in AD, " + $entryIdsPf[$j].EntryId) > $null
            $j++
        }
    }

    while ($i -lt $uniqueEntryIdsAd.Count) {
        $global:missingCount++
        $errorList.Add("Missing AD EntryId " + $uniqueEntryIdsAd[$i].EntryId) > $null
        $i++
    }

    while ( $j -lt $entryIdsPf.Count) {
        $global:missingCount++
        $errorList.Add("Missing Exchange EntryId for the following MEPFs " + $entryIdsPf[$j].EntryId) > $null
        $j++
    }   
}

function checkACL($ipmFolder) {
    $perms = Get-PublicFolderClientPermission $ipmFolder.EntryId
    foreach ($perm in $perms) {
        if ( ($perm.User.DisplayName -ne "Default") -and ($perm.User.DisplayName -ne "Anonymous") -and ($null -eq $perm.User.ADRecipient) -and ($perm.User.UserType -eq "Unknown") ) {
            $errorList.Add("this folder " + $ipmFolder.Identity + " permission needs to be removed for user " + $perm.User.DisplayName) > $null
			$global:corruptedPermission = $true
        }
        if ($legacy -and ($perm.User -like "NT User:S-*")) {
            $errorList.Add("this folder " + $ipmFolder.Identity + " permission needs to be removed for user " + $perm.User) > $null
			$global:corruptedPermission = $true
        }
    }
}

function limitChecker($ipmFolder, $children) {
    if ($children.Count -gt 10000) {
        $errorList.Add("Number of nested folders can not be more than 10K. Please check at " + $ipmFolder.parentPath) > $null        
    }
    if ($ipmFolder.folderPath.depth -gt 299) {
        $errorList.Add("Maximum depth for a public folder can not be more than 300. Please check at " + $ipmFolder.Identity) > $null        
    }
    $item = $ipmFolder | Get-PublicFolderStatistics | Select-Object Name, itemCount, folderPath
     
    $pfname = $item.folderPath -join '-'
    if ($item.itemCount -gt 1000000) {
        $errorList.Add("Number of items inside a folder can not be more than 1M. Please check at " + $pfname) > $null
    }
}


#verify eforms folders to dumpster mapping
if ($verifyDumpsterMapping -eq $true) {
    for ($i = 0; $i -lt $ipmEformsFoldersList.Count; $i++) {
        $ipmEformFolderEntryId = $ipmEformsFoldersList[$i]
        if ($eformsTraversed.Contains($ipmEformFolderEntryId)) {
            continue
        }
        $ipmEformFolder = Get-PublicFolder $ipmEformFolderEntryId.EntryId| Select-Object Identity, EntryId, DumpsterEntryId
        Write-Progress -Activity " eforms folders" -status "$ipmEformFolder" 
        if (!$ipmFolderMap.ContainsKey(($ipmEformFolder.EntryId))) {
            $ipmFolderMap.Add($ipmEformFolder.EntryId, $ipmEformFolder)
        }
        ipmFolderToDumpsterMapping $ipmEformFolder

        $children = Get-PublicFolder -GetChildren $ipmEformFolder.EntryId
        $children| % {$ipmEformsFoldersList.Add($_.entryid) > $null}
        Add-Content $IpmEformsFolderFile $ipmEformFolderEntryId 
    }
}

#Iterate over ipm folders and check the limit of child and depth. In the same loop verify folder to dumpster mapping and ACL's 
$processedCount = $ipmTraversed.Count
try {
    for ($i = 0; $i -lt $ipmFolderList.Count; $i++) {
        $ipmFolderEntryId = $ipmFolderList[$i].EntryId
        if ($null -eq $ipmFolderEntryId) {
            $ipmFolderEntryId = $ipmFolderList[$i]
        }
        
        if (!$legacy -and $ipmTraversed.Contains($ipmFolderEntryId)) {
            continue; 
        }
        
        $ipmFolder = Get-PublicFolder $ipmFolderEntryId | Select-Object Name, Identity, parentPath, folderPath, MailRecipientGuid, MailEnabled, EntryId, DumpsterEntryId
        Write-Progress -Activity " IPM folders processing " -status "$ipmFolder" 
        if ($ipmFolder.Name -eq 'IPM_SUBTREE') {
            Continue;
        }
        $children = Get-PublicFolder -GetChildren $ipmFolder.EntryId

        if ($checkLimits -eq $true) {
            limitChecker $ipmFolder $children
        }
        if ($verifyDumpsterMapping -eq $true -and !$ipmFolderMap.ContainsKey(($ipmFolder.EntryId))) {
            $ipmFolderMap.Add($ipmFolder.EntryId, $ipmFolder)
            ipmFolderToDumpsterMapping $ipmFolder
        }
        if ($checkPermissions -eq $true) {
            checkACL $ipmFolder
        }
        if (($null -ne $ipmFolder.MailRecipientGuid) -and ($ipmFolder.MailRecipientGuid.Guid.CompareTo('00000000-0000-0000-0000-000000000000') -ne 0)) {           
            $ipmFolder| Export-Csv  $ipmMEPFFile -Append -Force -NoTypeInformation -encoding "unicode"              
        }
                  
        $children| % {$ipmFolderList.Add($_.entryid) > $null}
        Add-Content $ipmFolderFile $ipmFolderEntryId
        $processedCount = $processedCount + 1
        Write-Progress -Activity " IPM folders processed " -status "$processedCount"
    }
}
finally {    
    if ($ipmFolderList.Count -gt 0) {
        $arr = $ipmFolderList.GetEnumerator()|ForEach-Object { if ($_.EntryId -eq $null) {
                "$($_)"
            }
            else {
                "$($_.EntryId)"
            }
        }
        $arr | Out-File $ipmFoldersListFile 
    }
}

#verify dumpster mapping to public folders
try {
    if ($verifyDumpsterMapping -eq $true) {
        Write-Host "Verifying if each dumpster points to the correct folder..."
        for ($i = 0; $i -lt $dumpsterFoldersList.Count; $i++) {
            $dumpsterFolderEntryId = $dumpsterFoldersList[$i].EntryId
            if ($null -eq $dumpsterFolderEntryId) {
                $dumpsterFolderEntryId = $dumpsterFoldersList[$i]
            }
            
            if ($nonIpmTraversed.Contains($dumpsterFolderEntryId)) {
                continue;
            }
            $dumpsterFolder = Get-PublicFolder $dumpsterFolderEntryId.EntryId| Select-Object Name, Identity, parentPath, folderPath, MailRecipientGuid, MailEnabled, EntryId, DumpsterEntryId, AdminFolderFlags
            if ($null -eq $dumpsterFolder) {
                $errorList.Add("EntryId $dumpsterFolderEntryId.EntryId does not have a corresponding dumpster folder") > $null
                Continue;
            }
            $id = $dumpsterFolder.Identity
            $children = Get-PublicFolder -GetChildren $dumpsterFolder.EntryId
            Write-Progress -Activity " dumpster folders" -status "$dumpsterFolder" 
            if ($null -eq $dumpsterFolder.DumpsterEntryId) {
                $errorList.Add("Folder $id does not have a dumpster entry id") > $null
                Continue;
            }
            #case when it encounters some deleted ipmFolders in dumpster tree
            if (($dumpsterFolder.AdminFolderFlags -ne "DumpsterFolder") -and ($dumpsterFolder.Name -ne 'IPM_SUBTREE')) {
                if (!$ipmFolderMap.ContainsKey(($dumpsterFolder.EntryId))) {
                    $ipmFolderMap.Add($dumpsterFolder.EntryId, $dumpsterFolder)
                    ipmFolderToDumpsterMapping $dumpsterFolder
                }
                if ($checkLimits -eq $true) {
                    limitChecker $dumpsterFolder $children
                }
                if ($checkPermissions -eq $true) {
                    checkACL $dumpsterFolder
                }
                if ($null -ne $dumpsterFolder.MailRecipientGuid) {           
                    $dumpsterFolder| Export-Csv $ipmMEPFFile -Append -Force -NoTypeInformation -encoding "unicode"      
                }
                
                Add-Content $ipmFolderFile $dumpsterFolder.EntryId
                Continue;
            }
            
            if ($ipmFolderMap.ContainsKey($dumpsterFolder.DumpsterEntryId)) {
                $folder = $ipmFolderMap[$dumpsterFolder.DumpsterEntryId]
                if ($folder.DumpsterEntryId.CompareTo($dumpsterFolder.EntryId) -ne 0) {
                    $errorList.Add("Dumpster folder $id does not have a correct reverse mapping with " + $folder.Identity) > $null
                    $global:dumpsterMismatchCount++
                }
            }
            elseif ($dumpsterEntryIdToFolderMap.ContainsKey($dumpsterFolder.DumpsterEntryId)) {
                $folder = $dumpsterEntryIdToFolderMap[$dumpsterFolder.DumpsterEntryId]
                if ($folder.DumpsterEntryId.CompareTo($dumpsterFolder.EntryId) -ne 0) {
                    $errorList.Add("Dumpster NON_IPM_SUBTREE folder $id does not have a correct reverse mapping with " + $folder.Identity) > $null
                    $global:dumpsterMismatchCount++
                }
            }
            elseif ($df.ParentPath.Length -eq "0" -or $df.ParentPath.Contains("NON_IPM_SUBTREE")) {
                continue;
            }
            else {
                $errorList.Add("Dumpster folder $id points to an invalid folder having dumpsterid " + $dumpsterFolder.DumpsterEntryId) > $null
                $global:dumpsterMismatchCount++
            }
            
            $children| % {$dumpsterFoldersList.Add($_.entryid) > $null}
            Add-content $DumpsterFolderFile $dumpsterFolderEntryId 
        }
        if ($global:dumpsterMismatchCount -ne 0) {
            $errorList.Add("$global:dumpsterMismatchCount folders have issue with dumpsters") > $null
        }
    }
    
}
finally {    
    if ($dumpsterFoldersList.Count -gt 0) {
        $arr = $dumpsterFoldersList.GetEnumerator()|ForEach-Object { if ($_.EntryId -eq $null) {
                "$($_)"
            }
            else {
                "$($_.EntryId)"
            }
        }
        $arr | Out-File $nonipmFoldersListFile 
    }
}

# Check if AD and PF are in sync for Mail Enabled Public Folders
if ($verifyMEPF -eq $true) {
    Write-Host "Verifying MEPF for AD and Exchange..."
    $entryIdsAd = @(Get-MailPublicFolder -ResultSize:Unlimited | Select-Object EntryId, Guid )
    $uniqueEntryIdsAd = @($entryIdsAd | Sort-Object -Unique EntryId)
    $listOfIpm = Import-Csv "$(Get-Location)\$($ipmMEPFFile)"
    $entryIdsPf = @($listOfIpm |  Select-Object EntryId, MailRecipientGuid | Sort-Object EntryId)
    $diff = $entryIdsPf.Count - $uniqueEntryIdsAd.Count
    $diff = if ( $diff -lt 0 ) { -$diff } Else { $diff }
    
    if ($entryIdsPf.Count -ne $uniqueEntryIdsAd.Count) {
        $errorList.Add("******************************** MEPF error starts ********************************") > $null
        $errorList.Add("There are $diff entries difference between AD and Exchange, fix them before starting migration.") > $null
    }
   
    checkOrphanMepfs $uniqueEntryIdsAd $entryIdsPf;
    if ($global:mismatchCount -ne 0 -or $global:missingCount -ne 0) {
        $errorList.Add("Encountered " + $global:mismatchCount + " miss matches and " + $global:missingCount + " missing between AD and Exchange") > $null
        $errorList.Add("******************************** MEPF error completed ********************************") > $null
    }
}

# Check the value of PublicFolderMailboxesLockedForNewConnections and PublicFoldersEnabled before migration
$initialValue = Get-OrganizationConfig |Select-Object PublicFolderMailboxesLockedForNewConnections, PublicFoldersEnabled
if ($initialValue.PublicFolderMailboxesLockedForNewConnections) {
    $errorList.Add("Value of PublicFolderMailboxesLockedForNewConnections is True. This should be false at the start of Migration. Use Set-OrganizationConfig command to set the value of PublicFolderMailboxesLockedForNewConnections to $False") > $null
}
if ($initialValue.PublicFoldersEnabled -eq 'Remote') {
    $errorList.Add("Value of PublicFoldersEnabled is not Local. This should be 'Local' at the start of Migration. Use Set-OrganizationConfig command to set the value of PublicFoldersEnabled to Local") > $null
}

if (($global:dumpsterMismatchCount -gt 0) -or (($global:mismatchCount -ne 0 -or $global:missingCount -ne 0) -and ($verifyMEPF -eq $true)) -or $global:corruptedPermission ) {
    $errorsFound = $true
}
if ($errorsFound){
	$errorList.Add("Please note down the below actionable steps: ") > $null
	if ($global:dumpsterMismatchCount -gt 0) {
		$errorList.Add("For dumpster issues:") > $null
		$errorList.Add("    a) If a folder has invalid dumpster and needs to be corrected then invoke the command : Update-PublicFolderMailbox  <contentmailboxname>  -FolderId  <folder identity> -CreateAssociatedDumpster -InvokeSynchronizer") > $null
		$errorList.Add("    b) If a folder has invalid content that needs to be skipped, then move the content to \NON_IPM_SUBTREE\HIERARCHY_SYNC_NOTIFICATIONS ") > $null
		$errorList.Add("    c) If there are many folders which do not have correct reverse mapping then it is advisable to try Dumpsterless Migration. Check this link for details https://techcommunity.microsoft.com/t5/Exchange-Team-Blog/Announcing-the-support-for-modern-public-folder-migrations/ba-p/608004") > $null
	}
	if ($global:mismatchCount -ne 0 -or $global:missingCount -ne 0) {
		$errorList.Add("To fix MEPF missing entryID:") > $null
		$errorList.Add("1) Disable the MEPF using cmdlet Disable-MailPublicFolder -Identity <folder identity> 2) Then enable it again using Enable-MailPublicFolder -Identity <folder identity>") > $null
		$errorList.Add("NOTE:Please save the Email addresses of MEPFs before disabling them") > $null
	}
	if ($global:corruptedPermission) {
		$errorList.Add("For permission issues:") > $null
		$errorList.Add("To remove the corrupted permissions on public folders, use the cmdlet: Remove-PublicFolderClientPermission <folder identity> -User <username> -Confirm:$false ") > $null
	}
}
else {
	$errorList.Add("Found no errors... ") > $null
}

$end = (Get-Date)
Write-Host 'Duration of execution of script : '  ($end-$start)
Write-Host "Please check the log file $ProgressLogFile for findings reported by the script"
$errorList |out-file -Append $ProgressLogFile
# SIG # Begin signature block
# MIIjlgYJKoZIhvcNAQcCoIIjhzCCI4MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDbGEBArWUQcM/o
# nuuSEyqkN8VGrBNqWuW6CWRtjq2QbKCCDYEwggX/MIID56ADAgECAhMzAAABUZ6N
# j0Bxow5BAAAAAAFRMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMTkwNTAyMjEzNzQ2WhcNMjAwNTAyMjEzNzQ2WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQCVWsaGaUcdNB7xVcNmdfZiVBhYFGcn8KMqxgNIvOZWNH9JYQLuhHhmJ5RWISy1
# oey3zTuxqLbkHAdmbeU8NFMo49Pv71MgIS9IG/EtqwOH7upan+lIq6NOcw5fO6Os
# +12R0Q28MzGn+3y7F2mKDnopVu0sEufy453gxz16M8bAw4+QXuv7+fR9WzRJ2CpU
# 62wQKYiFQMfew6Vh5fuPoXloN3k6+Qlz7zgcT4YRmxzx7jMVpP/uvK6sZcBxQ3Wg
# B/WkyXHgxaY19IAzLq2QiPiX2YryiR5EsYBq35BP7U15DlZtpSs2wIYTkkDBxhPJ
# IDJgowZu5GyhHdqrst3OjkSRAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUV4Iarkq57esagu6FUBb270Zijc8w
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDU0MTM1MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAWg+A
# rS4Anq7KrogslIQnoMHSXUPr/RqOIhJX+32ObuY3MFvdlRElbSsSJxrRy/OCCZdS
# se+f2AqQ+F/2aYwBDmUQbeMB8n0pYLZnOPifqe78RBH2fVZsvXxyfizbHubWWoUf
# NW/FJlZlLXwJmF3BoL8E2p09K3hagwz/otcKtQ1+Q4+DaOYXWleqJrJUsnHs9UiL
# crVF0leL/Q1V5bshob2OTlZq0qzSdrMDLWdhyrUOxnZ+ojZ7UdTY4VnCuogbZ9Zs
# 9syJbg7ZUS9SVgYkowRsWv5jV4lbqTD+tG4FzhOwcRQwdb6A8zp2Nnd+s7VdCuYF
# sGgI41ucD8oxVfcAMjF9YX5N2s4mltkqnUe3/htVrnxKKDAwSYliaux2L7gKw+bD
# 1kEZ/5ozLRnJ3jjDkomTrPctokY/KaZ1qub0NUnmOKH+3xUK/plWJK8BOQYuU7gK
# YH7Yy9WSKNlP7pKj6i417+3Na/frInjnBkKRCJ/eYTvBH+s5guezpfQWtU4bNo/j
# 8Qw2vpTQ9w7flhH78Rmwd319+YTmhv7TcxDbWlyteaj4RK2wk3pY1oSz2JPE5PNu
# Nmd9Gmf6oePZgy7Ii9JLLq8SnULV7b+IP0UXRY9q+GdRjM2AEX6msZvvPCIoG0aY
# HQu9wZsKEK2jqvWi8/xdeeeSI9FN6K1w4oVQM4Mwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVazCCFWcCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAVGejY9AcaMOQQAAAAABUTAN
# BglghkgBZQMEAgEFAKCBvjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgZuIPk/j6
# P5LnCqpFGiNfkgnxnGGQUD4fgCGPL7OuQUYwUgYKKwYBBAGCNwIBDDFEMEKgGoAY
# AFcAcgBpAHQAZQBMAG8AZwAuAHAAcwAxoSSAImh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9leGNoYW5nZSAwDQYJKoZIhvcNAQEBBQAEggEAa+AjfRBJeXH055Xay5sx
# HJ3OM0npXeFaGVA5EHJJIKm+/VxK4ZPGjLhg/deRJUSEEfYl+m/ziYDEQZQBpEs8
# q5+uRRvVkMgnnW1YfwgvRzMOXt1tlJ5fZB6WarlfzCPFAXJSZyRqiv2TMEZvpxla
# tPG75pEo9YIUocbnwcbctGmEhnbqxn6p2Cyaiae1pcRCg3FPC0l1mvxuKaw9qGio
# yFEO8eprizjIhTZqYgyL+f31Gpu0DtAn6kQ8ln4zDyYgDAMFU/SxeikAuxE6ykLW
# hbmogLvtQCpJXw4Cgc59eFFsaOjnsUhjKgEJAChQZYmOL+uXEKkW2jN5XsqsqzO3
# D6GCEuUwghLhBgorBgEEAYI3AwMBMYIS0TCCEs0GCSqGSIb3DQEHAqCCEr4wghK6
# AgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsqhkiG9w0BCRABBKCCAUAEggE8MIIB
# OAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCAlPkvLe1C6yWabXq0a
# mR7Ns6dRWokLc1+EsX+Wgwb0CAIGXV653nwbGBMyMDE5MTAwNDAyNTEyMy41MDZa
# MASAAgH0oIHQpIHNMIHKMQswCQYDVQQGEwJVUzELMAkGA1UECBMCV0ExEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsG
# A1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYD
# VQQLEx1UaGFsZXMgVFNTIEVTTjoyQUQ0LTRCOTItRkEwMTElMCMGA1UEAxMcTWlj
# cm9zb2Z0IFRpbWUtU3RhbXAgc2VydmljZaCCDjwwggTxMIID2aADAgECAhMzAAAA
# 169absCqPc62AAAAAADXMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFBDQSAyMDEwMB4XDTE4MDgyMzIwMjY1MFoXDTE5MTEyMzIwMjY1MFowgcox
# CzAJBgNVBAYTAlVTMQswCQYDVQQIEwJXQTEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQg
# SXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOjJBRDQtNEI5Mi1GQTAxMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBzZXJ2aWNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3YiIWuIJ
# DOGw3x23IWRijiLgEkhiEr78CtLSAJC+4SG7Rta9F/mG87dJSNx3Mugv6M8WSBzy
# 7Q1HS19vhOl7Ro/MR8OkNcSVkG8bbDL3S6LM3Oda5MDyCAXxsxTEAe4mIR/VNUDx
# hlUVhIjA92RnaZA5B+6vJzzIKs1Y03ZB1sp1WqnTTI7LfZYSlAVR7KbYAIzqDXXM
# F/18/QkcXrZc4uocy7hbmeO65xSI6jD3+xp5G83cL1F76IjHT+z1QE7VtTNJezct
# VcXKU51AayJamiJfTt6YIII6Dyy32Y/nsbpWYvCvxOWVRyd2CGeyzFL0IEzTy7On
# jeMib8FucrlgvQIDAQABo4IBGzCCARcwHQYDVR0OBBYEFN+4p1Un//dpvDNWYzZr
# TSmg6lU4MB8GA1UdIwQYMBaAFNVjOlyKMZDzQ3t8RhvFM2hahW1VMFYGA1UdHwRP
# ME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1
# Y3RzL01pY1RpbVN0YVBDQV8yMDEwLTA3LTAxLmNybDBaBggrBgEFBQcBAQROMEww
# SgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMv
# TWljVGltU3RhUENBXzIwMTAtMDctMDEuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0l
# BAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQELBQADggEBAEwLaFLE+QC1skxxsJza
# nnqDuAgo0Qe4tDiz3kHI7+yVkwPUH9DszjaXqalfL8MRJcjjGDTEYvDEBFXJA4tQ
# 6cKsyQIfFkiJo2gQIPYdBfWMDrkbRg1hd6+gRO9kDoifCrVkVBRdrz7MwikCtmaJ
# /YLtzhorwJpgcvuS5wvJKu+XO7ijOP2a9S62wopzxexmQQhpEcEM0ZS0KfNTfXgp
# jgSqQ3T43rKhxj2/DAJOdBwNZZnv80QJ+kQJBePg1ji/6zbuXy4edT48YED594FE
# +EP2odXUfcqDzdJXDZzz8fbwCeb9rJsNJ9Wo4MOBTrwqmwy4/KrNdpereMak+te5
# bTAwggZxMIIEWaADAgECAgphCYEqAAAAAAACMA0GCSqGSIb3DQEBCwUAMIGIMQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNy
# b3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0xMDA3MDEy
# MTM2NTVaFw0yNTA3MDEyMTQ2NTVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAy
# MDEwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqR0NvHcRijog7PwT
# l/X6f2mUa3RUENWlCgCChfvtfGhLLF/Fw+Vhwna3PmYrW/AVUycEMR9BGxqVHc4J
# E458YTBZsTBED/FgiIRUQwzXTbg4CLNC3ZOs1nMwVyaCo0UN0Or1R4HNvyRgMlhg
# RvJYR4YyhB50YWeRX4FUsc+TTJLBxKZd0WETbijGGvmGgLvfYfxGwScdJGcSchoh
# iq9LZIlQYrFd/XcfPfBXday9ikJNQFHRD5wGPmd/9WbAA5ZEfu/QS/1u5ZrKsajy
# eioKMfDaTgaRtogINeh4HLDpmc085y9Euqf03GS9pAHBIAmTeM38vMDJRF1eFpwB
# BU8iTQIDAQABo4IB5jCCAeIwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFNVj
# OlyKMZDzQ3t8RhvFM2hahW1VMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsG
# A1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJc
# YmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9z
# b2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIz
# LmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWlj
# cm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0
# MIGgBgNVHSABAf8EgZUwgZIwgY8GCSsGAQQBgjcuAzCBgTA9BggrBgEFBQcCARYx
# aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL1BLSS9kb2NzL0NQUy9kZWZhdWx0Lmh0
# bTBABggrBgEFBQcCAjA0HjIgHQBMAGUAZwBhAGwAXwBQAG8AbABpAGMAeQBfAFMA
# dABhAHQAZQBtAGUAbgB0AC4gHTANBgkqhkiG9w0BAQsFAAOCAgEAB+aIUQ3ixuCY
# P4FxAz2do6Ehb7Prpsz1Mb7PBeKp/vpXbRkws8LFZslq3/Xn8Hi9x6ieJeP5vO1r
# VFcIK1GCRBL7uVOMzPRgEop2zEBAQZvcXBf/XPleFzWYJFZLdO9CEMivv3/Gf/I3
# fVo/HPKZeUqRUgCvOA8X9S95gWXZqbVr5MfO9sp6AG9LMEQkIjzP7QOllo9ZKby2
# /QThcJ8ySif9Va8v/rbljjO7Yl+a21dA6fHOmWaQjP9qYn/dxUoLkSbiOewZSnFj
# nXshbcOco6I8+n99lmqQeKZt0uGc+R38ONiU9MalCpaGpL2eGq4EQoO4tYCbIjgg
# tSXlZOz39L9+Y1klD3ouOVd2onGqBooPiRa6YacRy5rYDkeagMXQzafQ732D8OE7
# cQnfXXSYIghh2rBQHm+98eEA3+cxB6STOvdlR3jo+KhIq/fecn5ha293qYHLpwms
# ObvsxsvYgrRyzR30uIUBHoD7G4kqVDmyW9rIDVWZeodzOwjmmC3qjeAzLhIp9cAv
# VCch98isTtoouLGp25ayp0Kiyc8ZQU3ghvkqmqMRZjDTu3QyS99je/WZii8bxyGv
# WbWu3EQ8l1Bx16HSxVXjad5XwdHeMMD9zOZN+w2/XU/pnR4ZOC+8z1gFLu8NoFA1
# 2u8JJxzVs341Hgi62jbb01+P3nSISRKhggLOMIICNwIBATCB+KGB0KSBzTCByjEL
# MAkGA1UEBhMCVVMxCzAJBgNVBAgTAldBMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046MkFENC00QjkyLUZBMDExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IHNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAM02duI00aclNqXrnE1W5fxdBxGtoIGD
# MIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEF
# BQACBQDhQJajMCIYDzIwMTkxMDAzMjM0NzQ3WhgPMjAxOTEwMDQyMzQ3NDdaMHcw
# PQYKKwYBBAGEWQoEATEvMC0wCgIFAOFAlqMCAQAwCgIBAAICGjsCAf8wBwIBAAIC
# EVkwCgIFAOFB6CMCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAK
# MAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQCuvbrokG7r
# aaLBIgbbFUfo0XidwqTjV8ovVwC4t0HNL6HnBLl921GZ5mR2iiWzUl3Z2s1sv2tl
# fZVGlV/Ro6KJh+XigvDGQOavBohgxJfNqU1Q17yG3N2DgJjM8qjrNrc+ufKeO3T6
# GiZzqwDiWP4htfRc5YhXovl2NyIVIUvJSDGCAw0wggMJAgEBMIGTMHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAA169absCqPc62AAAAAADXMA0GCWCG
# SAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZI
# hvcNAQkEMSIEIKOx2rMiOx0bSGASAwsc8wOAuXKH0pwgpXeTyklUQrciMIH6Bgsq
# hkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgpY5gDCcPQR793koodPsoQXLOyGrik4P1
# YsQRRs4k4zgwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAIT
# MwAAANevWm7Aqj3OtgAAAAAA1zAiBCAei3e45WeY+0Is0RCMulhjaRGwU5myqAM/
# LM39s3IaqDANBgkqhkiG9w0BAQsFAASCAQBSs77mluiDY/15mOTamsiuQvMi4I+O
# ymLS4QMhakTjNpYJGh94WOMgFq7iQDuy+sDPnI9qHhNHwPzVljeg5tRNBbRc5IpR
# OjJV5xw/Jgmu6qEmBLN7E7as74ZdX4oOXPR5dUFIyTvhBH+40rPJ1a56N5ZAU53Y
# flxLnEj1ZLItIBRwWajuMLT5bmBon1HN1vz2CjjJGdKRYm7/W9zL9QnOPLAjQ0MD
# VzfQ4ty4r9oOrmx5tu3pwi7G84Brw93oWsoGqqkxOfLVCBOFl4intX7sjbDYMxJn
# 5KN2MrYxTEhd0WQ0pQnIK8QXbC9nZ6OSnhUNbuwO5y+/eagTHkGToTd+
# SIG # End signature block
