#
# Get-MRMDetails.ps1
# Modified 2017/02/13
# Last Modifier:  Chris Pollitt
# Project Owner:  Rob Whaley
# Version: v2.0

# Syntax for running this script:
#
# .\Get-MRMDetails.ps1 -Mailbox <user>
#
# Example:
#
# .\Get-MRMDetails.ps1 -Mailbox rob@contoso.com
#
##############################################################################################
#
# This script is not officially supported by Microsoft, use it at your own risk.
# Microsoft has no liability, obligations, warranty, or responsibility regarding
# any result produced by use of this file.
#
##############################################################################################
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
# even if Microsoft has been advised of the possibility of such damages
##############################################################################################

Param (
	[Parameter(Mandatory=$true,HelpMessage='You must specify the name of a mailbox user')][string] $Mailbox
)

$ErrorActionPreference = 'SilentlyContinue'


function funcRetentionProperties
{
	# Export's All Retention Policies and Retention Policy Tags for the entire tenant
    Get-RetentionPolicy | Select-Object * | Export-Clixml "$Mailbox - MRM Retention Policies for entire Tenant.xml"
    [array]$Tags = Get-RetentionPolicyTag
      #Next line adds new property to each object in the array.
    $Tags = $Tags | add-member @{OctetRetentionIDAsSeenInMFCMAPI = ""} -PassThru
    foreach($t in $Tags) {
        #Convert each GUID to the Octet version that is seen in MFCMAPI's Properties
        $t.OctetRetentionIDAsSeenInMFCMAPI = [System.String]::Join("", ($t.RetentionId.ToByteArray() | ForEach-Object { $_.ToString(‘x2’) })).ToUpper()
    }
    $Tags | Select-Object * | Export-Clixml "$Mailbox - MRM Retention Policies for entire Tenant.xml"

	# Export the users mailbox information
	$MailboxProps | Select-Object * | Out-File "$Mailbox - Mailbox Information.txt"
	$MbxStatistics = get-mailboxstatistics $MailboxProps.exchangeguid.guid.tostring()
	#4 quotas of concern - total mailbox, recoverable mailbox, total archive, recoverable archive
	[string]$tempstate = $MailboxProps.ProhibitSendReceiveQuota.split("(")[1]
	[long]$MbxQuota = $tempstate.split("bytes")[0]
	$tempstate = $MailboxProps.RecoverableItemsQuota.split("(")[1]
	[long]$MbxRIQuota = $tempstate.split("bytes")[0]
	$tempstate = $MbxStatistics.TotalItemSize.value.ToString().split("(")[1]
	[long]$MbxTotalSize = $tempstate.split("bytes")[0]
	$tempstate = $MbxStatistics.TotalDeletedItemSize.value.ToString().split("(")[1]
	[long]$MbxDeletedSize = $tempstate.split("bytes")[0]
	[int]$PercentofPriumaryMBXQuota = $MbxTotalSize / $MbxQuota * 100
	[int]$PercentofPrimaryMBXRIQuota = $MbxDeletedSize / $MbxRIQuota * 100

	if(($MailboxProps.archivedatabase -ne $NULL) -and ($MailboxProps.archiveguid -ne "00000000-0000-0000-0000-000000000000")) {
#		$ArchiveMbxProps = get-mailbox $MailboxProps.exchangeguid.guid -archive
		$ArchiveMbxStats = get-mailboxstatistics $MailboxProps.exchangeguid.guid -archive

		[string]$tempstate = $MailboxProps.ArchiveQuota.split("(")[1]
		[long]$ArchiveMbxQuota = $tempstate.split("bytes")[0]
		#Archive Mailbox Recoverable Items quota does not appear to be visible to admins in PowerShell.  However, recoverable Items quota can be inferred from 3 properties
		#Those properties are the RecoverableItemsQuota of the primary mailbox, Litigation Hold and In-Place Hold.  https://technet.microsoft.com/en-us/library/mt668450.aspx
		[long]$ArchiveMbxRIQuota = $MbxRIQuota

		$tempstate = $ArchiveMbxStats.TotalItemSize.value.ToString().split("(")[1]
		[long]$ArchiveMbxTotalSize = $tempstate.split("bytes")[0]
		$tempstate = $ArchiveMbxStats.TotalDeletedItemSize.value.ToString().split("(")[1]
		[long]$ArchiveMbxDeletedSize = $tempstate.split("bytes")[0]
		[int]$PrimaryArchiveTotalFillPercentage =  $ArchiveMbxTotalSize / $ArchiveMbxQuota * 100
		[int]$PrimaryArchiveRIFillPercentage = $ArchiveMbxDeletedSize / $ArchiveMbxRIQuota * 100
	}
	# Get the Diagnostic Logs for user
	$logProps = Export-MailboxDiagnosticLogs $Mailbox -ExtendedProperties
	$xmlprops = [xml]($logProps.MailboxLog)
	$ELCRunLastData = $xmlprops.Properties.MailboxTable.Property | Where-Object {$_.Name -like "*elc*"}
	[datetime]$ELCLastSuccess = [datetime](($ELCRunLastData | ?{$_.name -eq "ELCLastSuccessTimestamp"}).value)


	# Get the Component Diagnostic Logs for user
	$error.Clear()
	$ELCLastRunFailure = (Export-MailboxDiagnosticLogs $Mailbox -ComponentName MRM).MailboxLog
	($error[0]).Exception | Out-File "$Mailbox - MRM Component Diagnostic Logs.txt" -Append
	if($ELCLastRunFailure -ne $NULL)
	{
      $ELCLastRunFailure | Out-File "$Mailbox - MRM Component Diagnostic Logs.txt"
      [datetime]$ELCLastFailure = [datetime]$ELCLastRunFailure.mailboxlog.split("Exception")[0]
	  if($ELCLastSuccess -gt $ELCLastFailure)
	  {
        "MRM has run successfully since the last failure.  This makes the Component Diagnostic Logs file much less interesting.
		----------------------------------------------------------------------------------------------------------------------
		" | Out-File "$Mailbox - Mailbox Diagnostic Logs.txt"
		$ELCRunLastData | Out-File "$Mailbox - Mailbox Diagnostic Logs.txt" -append
        "MRM has run successfully since the failure recorded in this file.  This failure is much less interesting.
		----------------------------------------------------------------------------------------------------------------------
		" | Out-File "$Mailbox - MRM Component Diagnostic Logs.txt"
        $ELCLastRunFailure | Out-File "$Mailbox - MRM Component Diagnostic Logs.txt" -append
	  }
      else
	  {
        "MRM has FAILED recently.  See the Component Diagnostic Logs file for details.
		-----------------------------------------------------------------------------
		" | Out-File "$Mailbox - Mailbox Diagnostic Logs.txt"
		$ELCRunLastData | Out-File "$Mailbox - Mailbox Diagnostic Logs.txt" -append
        "This log contains an interesting and very recent failure.
		---------------------------------------------------------
		" | Out-File "$Mailbox - MRM Component Diagnostic Logs.txt"
        $ELCLastRunFailure | Out-File "$Mailbox - MRM Component Diagnostic Logs.txt" -append
	  }
    }
	else {
	  "MRM has not encountered a failure.  Component Diagnostic Log is empty." | Out-File "$Mailbox - MRM Component Diagnostic Logs.txt"
      "MRM has never failed for this user.
      -----------------------------------
      " | Out-File "$Mailbox - Mailbox Diagnostic Logs.txt"
      $ELCRunLastData | Out-File "$Mailbox - Mailbox Diagnostic Logs.txt" -append

	}



	Search-AdminAuditLog -Cmdlets Start-ManagedFolderAssistant, Set-RetentionPolicy, Set-RetentionPolicyTag, Set-MailboxPlan, Set-Mailbox | Export-Csv "$Mailbox - MRM Component Audit Logs.csv" -NoTypeInformation
	# Get the Mailbox Folder Statistics
	$fldrStats = Get-MailboxFolderStatistics $MailboxProps.Identity -IncludeAnalysis -IncludeOldestAndNewestItems
	$fldrStats | Sort-Object FolderPath | Out-File "$Mailbox - Mailbox Folder Statistics.txt"
    $fldrStats | Select-Object FolderPath,ItemsInFolder,ItemsInFolderAndSubfolders,FolderAndSubFolderSize,NewestItemReceivedDate,OldestItemReceivedDate | Sort-Object FolderPath | Format-Table -AutoSize -Wrap | Out-File "$Mailbox - Mailbox Folder Statistics (Summary).txt"
	# Get the MRM 2.0 Policy and Tags Summary
	$MailboxRetentionPolicy = Get-RetentionPolicy $MailboxProps.RetentionPolicy
	$mrmPolicy = $MailboxRetentionPolicy | Select-Object -ExpandProperty Name
	$mrmMailboxTags = Get-RetentionPolicyTag -Mailbox $MailboxProps.Identity
	$msgRetentionProperties = "This Mailbox has the following Retention Hold settings assigned:"
	$msgRetentionProperties >> ($File)
	$msgRetentionProperties = "##################################################################################################################"
	$msgRetentionProperties >> ($File)
	$msgRetentionProperties = "Retention Hold is " + ($MailboxProps).RetentionHoldEnabled + " for the mailbox (True is Enabled, False is Disabled)"
	$msgRetentionProperties >> ($File)
	$msgRetentionProperties = "Retention Hold will start on " + ($MailboxProps).StartDateForRetentionHold + " (no value is Disabled)"
	$msgRetentionProperties >> ($File)
	$msgRetentionProperties = "Retention Hold will end on " + ($MailboxProps).EndDateForRetentionHold + " (no value is Disabled)"
	$msgRetentionProperties >> ($File)
	$msgRetentionProperties = ""
	$msgRetentionProperties >> ($File)
	$msgRetentionProperties = "This Mailbox has the following Retention Policy assigned:"
	$msgRetentionProperties >> ($File)
	$msgRetentionProperties = "##################################################################################################################"
	$msgRetentionProperties >> ($File)
	$msgRetentionProperties = $mrmPolicy
	$msgRetentionProperties >> ($File)
	$msgRetentionProperties = ""
	$msgRetentionProperties >> ($File)
	$msgRetentionProperties = "The Retention Policy " + $mrmPolicy + " has the following tags assigned to the mailbox " + $MailboxProps + ":"
	$msgRetentionProperties >> ($File)
	$msgRetentionProperties = "##################################################################################################################"
	$msgRetentionProperties >> ($File)
	$msgRetentionProperties = ($MailboxRetentionPolicy).RetentionPolicyTagLinks | Sort-Object
	$msgRetentionProperties >> ($File)
	$msgRetentionProperties = ""
	$msgRetentionProperties >> ($File)
	$msgRetentionProperties = "The Mailbox " + 	$MailboxProps.Identity + " says it has all of the following tags assigned to it (If different than above user added personal tags via OWA):"
	$msgRetentionProperties >> ($File)
	$msgRetentionProperties = "##########################################################################################################################################"
	$msgRetentionProperties >> ($File)
	$msgRetentionProperties = ($mrmMailboxTags).Name | Sort-Object
	$msgRetentionProperties >> ($File)
	$msgRetentionProperties = ""
	$msgRetentionProperties >> ($File)
	$msgRetentionProperties = "Here are the Details of the Retention Policy Tags for this Mailbox:"
	$msgRetentionProperties >> ($File)
	$msgRetentionProperties = "##################################################################################################################"
	$msgRetentionProperties >> ($File)
	foreach ($Tag in $MailboxRetentionPolicy.RetentionPolicyTagLinks)
	{
		Get-RetentionPolicyTag $Tag | Format-List Name,Description,Comment,AddressForJournaling,AgeLimitForRetention,LocalizedComment,LocalizedRetentionPolicyTagName,MessageClass,MessageFormatForJournaling,MustDisplayCommentEnabled,RetentionAction,RetentionEnabled,RetentionId,SystemTag,Type >> ($File)
	}
	$msgRetentionProperties = "##################################################################################################################"
	$msgRetentionProperties >> ($File)
	if($MbxTotalSize -le 10485760 ){  #If the Total Item size in the mailbox is less than or equal to 10MB MRM will not run. Both values converted to bytes.
		$msgRetentionProperties = "Primary Mailbox is less than 10MB.  MRM will not run until mailbox exceeds 10MB.  Current Mailbox sixe is " + $MbxTotalSize.ToString() + " bytes."
		$msgRetentionProperties >> ($File)
		$msgRetentionProperties = "##################################################################################################################"
		$msgRetentionProperties >> ($File)
	}
	else {
		$msgRetentionProperties = "Primary Mailbox exceeds 10MB.  Minimum mailbox size requirment for MRM has been met.  Current Mailbox sixe is " + $MbxTotalSize.ToString() + " bytes."
		$msgRetentionProperties >> ($File)
		$msgRetentionProperties = "##################################################################################################################"
		$msgRetentionProperties >> ($File)
	}
	if($PercentofPrimaryMBXRIQuota -gt 98){ #if Recoverable items in the primary mailbox is more than 98% full highlight it as a problem.
		$msgRetentionProperties = "Primary Mailbox is critically low on free quota for Recoverable Items. "
		$msgRetentionProperties >> ($File)
		$msgRetentionProperties = $MbxDeletedSize.ToString() + " bytes consumed in Recoverable Items."
		$msgRetentionProperties >> ($File)
		$msgRetentionProperties = $MbxRIQuota.ToString() + " bytes is the maximum. "
		$msgRetentionProperties >> ($File)
		$msgRetentionProperties = "##################################################################################################################"
		$msgRetentionProperties >> ($File)
	}
	else {
		$msgRetentionProperties = "Primary Mailbox Recoverable Items are not yet at quota."
		$msgRetentionProperties >> ($File)
		$msgRetentionProperties = $MbxTotalSize.ToString() + " bytes is the current Recoverable Items size in Primary Mailbox."
		$msgRetentionProperties >> ($File)
		$msgRetentionProperties = $MbxRIQuota.ToString() + " bytes is the maximum."
		$msgRetentionProperties >> ($File)
		$msgRetentionProperties = "##################################################################################################################"
		$msgRetentionProperties >> ($File)
	}
	if($PrimaryArchiveRIFillPercentage -gt 98){ #if Recoverable items in the primary archive mailbox is more than 98% full highlight it as a problem.
		$msgRetentionProperties = "Primary Archive Mailbox is critically low on free quota for Recoverable Items. "
		$msgRetentionProperties >> ($File)
		$msgRetentionProperties = $ArchiveMbxDeletedSize.ToString() + " bytes consumed in Recoverable Items."
		$msgRetentionProperties >> ($File)
		$msgRetentionProperties = $ArchiveMbxRIQuota.ToString() + " bytes is the maximum."
		$msgRetentionProperties >> ($File)
		$msgRetentionProperties = "##################################################################################################################"
		$msgRetentionProperties >> ($File)
	}
	else {
		$msgRetentionProperties = "Primary Archive Mailbox is not in imminent danger of filling Recoverable Items Quota."
		$msgRetentionProperties >> ($File)
		$msgRetentionProperties = $ArchiveMbxDeletedSize.ToString() + " bytes consumed in Recoverable Items."
		$msgRetentionProperties >> ($File)
		$msgRetentionProperties = $ArchiveMbxRIQuota.ToString() + " bytes is the maximum available."
		$msgRetentionProperties >> ($File)
		$msgRetentionProperties = "##################################################################################################################"
		$msgRetentionProperties >> ($File)
	}
	if($PrimaryArchiveTotalFillPercentage -gt 98){ #if Recoverable items in the primary archive mailbox is more than 98% full highlight it as a problem.
		$msgRetentionProperties = "Primary Archive Mailbox is critically low on free quota for Visible Items. "
		$msgRetentionProperties >> ($File)
		$msgRetentionProperties = $ArchiveMbxTotalSize.ToString() + " bytes consumed in Recoverable Items."
		$msgRetentionProperties >> ($File)
		$msgRetentionProperties = $ArchiveMbxQuota.ToString() + " bytes is the maximum."
		$msgRetentionProperties >> ($File)
		$msgRetentionProperties = "##################################################################################################################"
		$msgRetentionProperties >> ($File)
	}
	else {
		$msgRetentionProperties = "Primary Archive Mailbox is not in imminent danger of filling the mailbox quota."
		$msgRetentionProperties >> ($File)
		$msgRetentionProperties = $ArchiveMbxTotalSize.ToString() + " bytes consumed in Recoverable Items."
		$msgRetentionProperties >> ($File)
		$msgRetentionProperties = $ArchiveMbxQuota.ToString() + " bytes is the maximum."
		$msgRetentionProperties >> ($File)
		$msgRetentionProperties = "##################################################################################################################"
		$msgRetentionProperties >> ($File)
	}

	return
}

function funcManagedFolderProperties
{
	Get-ManagedFolderMailboxPolicy | Select-Object * | Export-Clixml "$Mailbox - MRM Managed Folder Mailbox Policies - All.xml"
	Get-ManagedFolder | Select-Object * | Export-Clixml "$Mailbox - MRM Managed Folders - All.xml"
	Get-ManagedContentSettings | Select-Object * | Export-Clixml "$Mailbox - MRM Managed Content Settings - All.xml"
	$MailboxManagedFolderPolicy = Get-ManagedFolderMailboxPolicy $MailboxProps.ManagedFolderMailboxPolicy
	$msgRetentionProperties = "This Mailbox has the following Retention Policy assigned:"
	$msgRetentionProperties >> ($File)
	$msgRetentionProperties = "##################################################################################################################"
	$msgRetentionProperties >> ($File)
	$msgRetentionProperties = $MailboxManagedFolderPolicy | Select-Object -ExpandProperty Name
	$msgRetentionProperties >> ($File)
	$msgRetentionProperties = ""
	$msgRetentionProperties >> ($File)
	$msgRetentionProperties = "Here are the Details of the Managed Folders for this Mailbox:"
	$msgRetentionProperties >> ($File)
	$msgRetentionProperties = "##################################################################################################################"
	$msgRetentionProperties >> ($File)
	foreach ($Folder in $MailboxManagedFolderPolicy.ManagedFolderLinks)
	{
		Get-ManagedFolder $Folder | Format-List Name,Description,Comment,FolderType,FolderName,StorageQuota,LocalizedComment,MustDisplayCommentEnabled,BaseFolderOnly,TemplateIds >> ($File)
	}
	$msgRetentionProperties = "Here are the Details of the Managed Content Settings for this Mailbox:"
	$msgRetentionProperties >> ($File)
	$msgRetentionProperties = "##################################################################################################################"
	$msgRetentionProperties >> ($File)
	foreach ($Folder in $MailboxManagedFolderPolicy.ManagedFolderLinks.FolderType)
	{
		Get-ManagedContentSettings -Identity $Folder | Format-List Name,Identity,Description,MessageClassDisplayName,MessageClass,RetentionEnabled,RetentionAction,AgeLimitForRetention,MoveToDestinationFolder,TriggerForRetention,MessageFormatForJournaling,JournalingEnabled,AddressForJournaling,LabelForJournaling,ManagedFolder,ManagedFolderName >> ($File)
	}
return
}

function funcConvertPrStartTime
{
# Example:
# ConvertPrStartTime 000000008AF3B39BE681D001
#
param($byteString)
$bytesReversed = ""
for ($x = $byteString.Length - 2; $x -gt 7; $x-=2) { $bytesReversed += $byteString.Substring($x, 2) }
[DateTime]::FromFileTimeUtc([Int64]::Parse($bytesReversed, "AllowHexSpecifier"))
}

function funcUltArchive
{
Param(
[string]$mbx
)
$m = get-mailbox $mbx
$mbxLocations = Get-MailboxLocation -User $m.Identity
write-host ""
write-host ""
write-host "There is a total of $($mbxLocations.Count-2) auxiliary archive mailboxes for [$strMailbox]."
write-host ""
write-host ""
write-host "Archive mailbox statistics:"
write-host ""
write-host "Mailbox Type`tMailbox GUID`t`t`t`t`t`t`tMailbox Size(MB)"
write-host "-------------------------------------------------------------------------------"
$totalArchiveSize = 0
foreach ($x in $mbxLocations)
{
	if ($x.MailboxLocationType -ne "Primary")
	{
		$stats = Get-MailboxStatistics -Identity ($x.MailboxGuid).Guid | Select-Object @{name="TotalItemSize"; expression={[math]::Round(($_.TotalItemSize.ToString().Split("(")[1].Split(" ")[0].Replace(",","")/1MB),2)}}
		write-host "$($x.MailboxLocationType)`t`t$($x.MailboxGUID)`t$($stats.TotalItemSize)"
		if ($stats)
		{
			$totalArchiveSize = $totalArchiveSize + $stats.TotalItemSize
		}
	}
}
write-host "-------------------------------------------------------------------------------"
write-host "Total archive size:`t`t`t`t$totalArchiveSize MB"
write-host ""
write-host ""
write-host ""
}

#===================================================================
# MAIN
#===================================================================

If ($SDE -eq $True)
{
	funcConvertPrStartTime
}

$MailboxProps = (Get-Mailbox $Mailbox)

if ($MailboxProps -ne $Null)
{
	Write-Host -ForegroundColor "Green" "Found Mailbox $Mailbox, please wait while information is being gathered..."
}

else
{
	Write-Host -ForegroundColor "Red" "The Mailbox $Mailbox cannot be found, please check spelling and try again!"
	exit
}

$File = "$Mailbox - MRM Summary.txt"

$Msg = "export complete, see file please send all files that start with $Mailbox - to your Microsoft Support Engineer"

if (($MailboxProps.RetentionPolicy -eq $Null) -and ($MailboxProps.ManagedFolderMailboxPolicy -eq $Null))
{
	Write-Host -ForegroundColor "Yellow" "The Mailbox does not have a Retention Policy or Managed Folder Policy applied!"
	exit
}

elseif ($MailboxProps.RetentionPolicy -ne $Null)
{
	New-Item $File -Type file -Force | Out-Null
	funcRetentionProperties
	write-host -ForegroundColor "Green" $Msg
}

else
{
	New-Item $File -Type file -Force | Out-Null
	funcManagedFolderProperties
	write-host -ForegroundColor "Green" $Msg
}

