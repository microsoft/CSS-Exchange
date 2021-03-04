# ValidateMailEnabledPublicFolders.ps1
#
# Note: If running on Exchange 2010, the ExFolders tool must be in the V14\bin folder
# in order to run one of the checks. ExFolders can be downloaded here:
# https://techcommunity.microsoft.com/gxcuf89792/attachments/gxcuf89792/Exchange/12412/2/ExFolders-SP1+.zip

Set-ADServerSettings -ViewEntireForest $true

Write-Host "Checking for mail-enabled System folders..."

$nonIpmSubtreeMailEnabled = @(Get-PublicFolder \non_ipm_subtree -Recurse -ResultSize Unlimited | Where-Object { $_.MailEnabled })

Write-Host "Found $($nonIpmSubtreeMailEnabled.Count) mail-enabled System folders."

Write-Host "Getting all public folders. This might take a while..."

$allIpmSubtree = @(Get-PublicFolder -Recurse -ResultSize Unlimited | Select-Object Identity, MailEnabled, EntryId)

Write-Host "Found $($allIpmSubtree.Count) public folders."

if ($allIpmSubtree.Count -lt 1) {
    return
}

$ipmSubtreeMailEnabled = @($allIpmSubtree | Where-Object { $_.MailEnabled })

Write-Host "$($ipmSubtreeMailEnabled.Count) of those are mail-enabled."

$mailDisabledWithProxyGuid = $null

if ($null -ne (Get-PublicFolder).DumpsterEntryId) {
    $mailDisabledWithProxyGuid = @($allIpmSubtree | Where-Object { -not $_.MailEnabled -and $null -ne $_.MailRecipientGuid -and [Guid]::Empty -ne $_.MailRecipientGuid } | ForEach-Object { $_.Identity.ToString() })
} else {
    $registryPath = "HKCU:\Software\Microsoft\Exchange\ExFolders"
    $valueName = "PublicFolderPropertiesSelected"
    $value = @("PR_PF_PROXY: 0x671D0102", "PR_PF_PROXY_REQUIRED: 0x671F000B", "DS:legacyExchangeDN")

    if (-not (Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
    }

    if (-not (Test-Path $registryPath)) {
        Write-Error "Could not create ExFolders registry key."
        return
    }

    New-ItemProperty -Path $registryPath -Name $valueName -Value $value -PropertyType MultiString -Force | Out-Null

    $result = (Get-ItemProperty -Path $registryPath -Name $valueName).PublicFolderPropertiesSelected

    if ($result[0] -ne $value[0] -or $result[1] -ne $value[1] -or $result[2] -ne $value[2]) {
        Write-Error "Could not set PublicFolderPropertiesSelected value for ExFolders in the registry."
        return
    }

    $msiInstallPath = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\ExchangeServer\v14\Setup" -Name "MsiInstallPath").MsiInstallPath
    $exFoldersExe = "$msiInstallPath\bin\ExFolders.exe"

    $pfDbToUse = Get-PublicFolderDatabase | Select-Object -First 1

    Write-Host "Generating ExFolders export."
    Write-Warning "NOTE: ExFolders will appear to be Not Responding during the export. That is normal."
    Write-Host "Waiting for export to finish..."

    $exFoldersExportFile = (Join-Path $PWD "ExFoldersMailEnabledPropertyExport.txt")

    & $exFoldersExe -connectto $pfDbToUse.Name -export -properties -f (Join-Path $PWD "ExFoldersMailEnabledPropertyExport.txt") | Out-Null

    if (-not (Test-Path $exFoldersExportFile)) {
        Write-Error "Failed to generate ExFolders export. Continuing with other tests. If"
        Write-Error "any mail-disabled folders have invalid proxy GUIDs, those will be missed."
    } else {
        $exportResults = Import-Csv .\ExFoldersMailEnabledPropertyExport.txt -Delimiter `t
        $mailDisabledWithProxyGuid = @($exportResults | Where-Object { $_."PR_PF_PROXY_REQUIRED: 0x671F000B" -ne "True" -and $_."PR_PF_PROXY: 0x671D0102" -ne "PropertyError: NotFound" -and $_."DS:legacyExchangeDN".length -lt 1 } | ForEach-Object { $_."Folder Path" })
    }
}

$mailEnabledFoldersWithNoADObject = @()

$mailPublicFoldersLinked = New-Object 'System.Collections.Generic.Dictionary[string, object]'

for ($i = 0; $i -lt $ipmSubtreeMailEnabled.Count; $i++) {
    Write-Progress -Activity "Checking for missing AD objects" -PercentComplete ($i * 100 / $ipmSubtreeMailEnabled.Count) -Status ("$i of $($ipmSubtreeMailEnabled.Count)")
    $result = $ipmSubtreeMailEnabled[$i] | Get-MailPublicFolder -ErrorAction SilentlyContinue
    if ($null -eq $result) {
        $mailEnabledFoldersWithNoADObject += $ipmSubtreeMailEnabled[$i]
    } else {
        $guidString = $result.Guid.ToString()
        if (-not $mailPublicFoldersLinked.ContainsKey($guidString)) {
            $mailPublicFoldersLinked.Add($guidString, $result) | Out-Null
        }
    }
}

Write-Host "$($mailEnabledFoldersWithNoADObject.Count) folders are mail-enabled with no AD object."

Write-Host "$($mailPublicFoldersLinked.Keys.Count) folders are mail-enabled and are properly linked to an existing AD object."

Write-Host "Getting all MailPublicFolder objects..."

$allMailPublicFolders = @(Get-MailPublicFolder -ResultSize Unlimited)

$orphanedMailPublicFolders = @()

for ($i = 0; $i -lt $allMailPublicFolders.Count; $i++) {
    Write-Progress -Activity "Checking for orphaned MailPublicFolders" -PercentComplete ($i * 100 / $allMailPublicFolders.Count) -Status ("$i of $($allMailPublicFolders.Count)")
    if (!($mailPublicFoldersLinked.ContainsKey($allMailPublicFolders[$i].Guid.ToString()))) {
        $orphanedMailPublicFolders += $allMailPublicFolders[$i]
    }
}

Write-Host "$($orphanedMailPublicFolders.Count) MailPublicFolders are orphaned."

Write-Host "Building EntryId HashSets..."

$byEntryId = New-Object 'System.Collections.Generic.Dictionary[string, object]'
$allIpmSubtree | ForEach-Object { $byEntryId.Add($_.EntryId.ToString(), $_) }

$byPartialEntryId = New-Object 'System.Collections.Generic.Dictionary[string, object]'
$allIpmSubtree | ForEach-Object { $byPartialEntryId.Add($_.EntryId.ToString().Substring(44), $_) }

$orphanedMPFsThatPointToAMailDisabledFolder = @()
$orphanedMPFsThatPointToAMailEnabledFolder = @()
$orphanedMPFsThatPointToNothing = @()
$emailAddressMergeCommands = @()

function GetCommandToMergeEmailAddresses($publicFolder, $orphanedMailPublicFolder) {
    $linkedMailPublicFolder = Get-PublicFolder $publicFolder.Identity | Get-MailPublicFolder
    $emailAddressesOnGoodObject = @($linkedMailPublicFolder.EmailAddresses | Where-Object { $_.ToString().StartsWith("smtp:", "OrdinalIgnoreCase") } | ForEach-Object { $_.ToString().Substring($_.ToString().IndexOf(':') + 1) })
    $emailAddressesOnBadObject = @($orphanedMailPublicFolder.EmailAddresses | Where-Object { $_.ToString().StartsWith("smtp:", "OrdinalIgnoreCase") } | ForEach-Object { $_.ToString().Substring($_.ToString().IndexOf(':') + 1) })
    $emailAddressesToAdd = $emailAddressesOnBadObject | Where-Object { -not $emailAddressesOnGoodObject.Contains($_) }
    $emailAddressesToAdd = $emailAddressesToAdd | ForEach-Object { "`"" + $_ + "`"" }
    if ($emailAddressesToAdd.Count -gt 0) {
        $emailAddressesToAddString = [string]::Join(",", $emailAddressesToAdd)
        $command = "Get-PublicFolder `"$($publicFolder.Identity)`" | Get-MailPublicFolder | Set-MailPublicFolder -EmailAddresses @{add=$emailAddressesToAddString}"
        return $command
    } else {
        return $null
    }
}

for ($i = 0; $i -lt $orphanedMailPublicFolders.Count; $i++) {
    Write-Progress -Activity "Checking for orphans that point to a valid folder" -PercentComplete ($i * 100 / $orphanedMailPublicFolders.Count) -Status ("$i of $($orphanedMailPublicFolders.Count)")
    $thisMPF = $orphanedMailPublicFolders[$i]
    $pf = $null
    if ($null -ne $thisMPF.ExternalEmailAddress -and $thisMPF.ExternalEmailAddress.ToString().StartsWith("expf")) {
        $partialEntryId = $thisMPF.ExternalEmailAddress.ToString().Substring(5).Replace("-", "")
        $partialEntryId += "0000"
        if ($byPartialEntryId.TryGetValue($partialEntryId, [ref]$pf)) {
            if ($pf.MailEnabled) {

                $command = GetCommandToMergeEmailAddresses $pf $thisMPF
                if ($null -ne $command) {
                    $emailAddressMergeCommands += $command
                }

                $orphanedMPFsThatPointToAMailEnabledFolder += $thisMPF
            } else {
                $orphanedMPFsThatPointToAMailDisabledFolder += $thisMPF
            }

            continue
        }
    }

    if ($null -ne $thisMPF.EntryId -and $byEntryId.TryGetValue($thisMPF.EntryId.ToString(), [ref]$pf)) {
        if ($pf.MailEnabled) {

            $command = GetCommandToMergeEmailAddresses $pf $thisMPF
            if ($null -ne $command) {
                $emailAddressMergeCommands += $command
            }

            $orphanedMPFsThatPointToAMailEnabledFolder += $thisMPF
        } else {
            $orphanedMPFsThatPointToAMailDisabledFolder += $thisMPF
        }
    } else {
        $orphanedMPFsThatPointToNothing += $thisMPF
    }
}

Write-Host $orphanedMailPublicFolders.Count "orphaned MailPublicFolder objects."
Write-Host $orphanedMPFsThatPointToAMailEnabledFolder.Count "of those orphans point to mail-enabled folders that point to some other object."
Write-Host $orphanedMPFsThatPointToAMailDisabledFolder.Count "of those orphans point to mail-disabled folders."

$foldersToMailDisableFile = Join-Path $PWD "FoldersToMailDisable.txt"
$foldersToMailDisable = @()
$nonIpmSubtreeMailEnabled | ForEach-Object { $foldersToMailDisable += $_.Identity.ToString() }
$mailEnabledFoldersWithNoADObject | ForEach-Object { $foldersToMailDisable += $_.Identity }

if ($foldersToMailDisable.Count -gt 0) {
    Set-Content -Path $foldersToMailDisableFile -Value $foldersToMailDisable

    Write-Host
    Write-Host "Results:"
    Write-Host
    Write-Host $foldersToMailDisable.Count "folders should be mail-disabled, either because the MailRecipientGuid"
    Write-Host "does not exist, or because they are system folders. These are listed in the file called:"
    Write-Host $foldersToMailDisableFile -ForegroundColor Green
    if ($null -ne $allIpmSubtree[0].DumpsterEntryId) {
        # This is modern public folders, which means we can just toggle the attribute
        Write-Host "After confirming the accuracy of the results, you can mail-disable them with the following command:"
        Write-Host "Get-Content `"$foldersToMailDisableFile`" | % { Set-PublicFolder `$_ -MailEnabled `$false }" -ForegroundColor Green
    } else {
        # This is 2010. We can just mail-disable.
        Write-Host "After confirming the accuracy of the results, you can mail-disable them with the following command:"
        Write-Host "Get-Content `"$foldersToMailDisableFile`" | % { Disable-MailPublicFolder `$_ }" -ForegroundColor Green
    }
} else {
    Write-Host
    Write-Host "No folders need to be mail-disabled."
}

$mailPublicFoldersToDeleteFile = Join-Path $PWD "MailPublicFolderOrphans.txt"
$mailPublicFoldersToDelete = @()
$orphanedMPFsThatPointToNothing | ForEach-Object { $mailPublicFoldersToDelete += $_.DistinguishedName.Replace("/", "\/") }

if ($orphanedMPFsThatPointToNothing.Count -gt 0) {
    Set-Content -Path $mailPublicFoldersToDeleteFile -Value $mailPublicFoldersToDelete

    Write-Host
    Write-Host $mailPublicFoldersToDelete.Count "MailPublicFolders are orphans and should be deleted. They exist in Active Directory"
    Write-Host "but are not linked to any public folder. These are listed in a file called:"
    Write-Host $mailPublicFoldersToDeleteFile -ForegroundColor Green
    Write-Host "After confirming the accuracy of the results, you can delete them with the following command:"
    Write-Host "Get-Content `"$mailPublicFoldersToDeleteFile`" | % { `$folder = ([ADSI](`"LDAP://`$_`")); `$parent = ([ADSI]`"`$(`$folder.Parent)`"); `$parent.Children.Remove(`$folder) }" -ForegroundColor Green
} else {
    Write-Host
    Write-Host "No orphaned MailPublicFolders were found."
}

$mailPublicFolderDuplicatesFile = Join-Path $PWD "MailPublicFolderDuplicates.txt"
$mailPublicFolderDuplicates = @()
$orphanedMPFsThatPointToAMailEnabledFolder | ForEach-Object { $mailPublicFolderDuplicates += $_.DistinguishedName }

if ($orphanedMPFsThatPointToAMailEnabledFolder.Count -gt 0) {
    Set-Content -Path $mailPublicFolderDuplicatesFile -Value $mailPublicFolderDuplicates

    Write-Host
    Write-Host $mailPublicFolderDuplicates.Count "MailPublicFolders are duplicates and should be deleted. They exist in Active Directory"
    Write-Host "and point to a valid folder, but that folder points to some other directory object."
    Write-Host "These are listed in a file called:"
    Write-Host $mailPublicFolderDuplicatesFile -ForegroundColor Green
    Write-Host "After confirming the accuracy of the results, you can delete them with the following command:"
    Write-Host "Get-Content `"$mailPublicFolderDuplicatesFile`" | % { `$folder = ([ADSI](`"LDAP://`$_`")); `$parent = ([ADSI]`"`$(`$folder.Parent)`"); `$parent.Children.Remove(`$folder) }" -ForegroundColor Green

    if ($emailAddressMergeCommands.Count -gt 0) {
        $emailAddressMergeScriptFile = Join-Path $PWD "AddAddressesFromDuplicates.ps1"
        Set-Content -Path $emailAddressMergeScriptFile -Value $emailAddressMergeCommands
        Write-Host "The duplicates we are deleting contain email addresses that might still be in use."
        Write-Host "To preserve these, we generated a script that will add these to the linked objects for those folders."
        Write-Host "After deleting the duplicate objects using the command above, run the script as follows to"
        Write-Host "populate these addresses:"
        Write-Host ".\$emailAddressMergeScriptFile" -ForegroundColor Green
    }
} else {
    Write-Host
    Write-Host "No duplicate MailPublicFolders were found."
}

$mailDisabledWithProxyGuidFile = Join-Path $PWD "MailDisabledWithProxyGuid.txt"

if ($mailDisabledWithProxyGuid.Count -gt 0) {
    Set-Content -Path $mailDisabledWithProxyGuidFile -Value $mailDisabledWithProxyGuid

    Write-Host
    Write-Host $mailDisabledWithProxyGuid.Count "public folders have proxy GUIDs even though the folders are mail-disabled."
    Write-Host "These folders should be mail-enabled. They can be mail-disabled again afterwards if desired."
    Write-Host "To mail-enable these folders, run:"
    Write-Host "Get-Content `"$mailDisabledWithProxyGuidFile`" | % { Enable-MailPublicFolder `$_ }" -ForegroundColor Green
} else {
    Write-Host
    Write-Host "No mail-disabled public folders with proxy GUIDs were found."
}

$mailPublicFoldersDisconnectedFile = Join-Path $PWD "MailPublicFoldersDisconnected.txt"
$mailPublicFoldersDisconnected = @()
$orphanedMPFsThatPointToAMailDisabledFolder | ForEach-Object { $mailPublicFoldersDisconnected += $_.DistinguishedName }

if ($orphanedMPFsThatPointToAMailDisabledFolder.Count -gt 0) {
    Set-Content -Path $mailPublicFoldersDisconnectedFile -Value $mailPublicFoldersDisconnected

    Write-Host
    Write-Host $mailPublicFoldersDisconnected.Count "MailPublicFolders are disconnected from their folders. This means they exist in"
    Write-Host "Active Directory and the folders are probably functioning as mail-enabled folders,"
    Write-Host "even while the properties of the public folders themselves say they are not mail-enabled."
    Write-Host "This can be complex to fix. Either the directory object should be deleted, or the public folder"
    Write-Host "should be mail-enabled, or both. These directory objects are listed in a file called:"
    Write-Host $mailPublicFoldersDisconnectedFile -ForegroundColor Green
} else {
    Write-Host
    Write-Host "No disconnected MailPublicFolders were found."
}

Write-Host
Write-Host "Done!"
