# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\..\..\Shared\Write-ErrorInformation.ps1

# Export out the data to files for data collection.
function Write-DataExport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$MailboxInformation,

        [Parameter(Mandatory = $true)]
        [string]$RootDirectory,

        [Parameter(Mandatory = $true)]
        [ref]$LocationExported,

        [object[]]$Messages,

        [string]$UniqueId
    )
    process {
        if ([string]::IsNullOrEmpty($UniqueId)) {
            $UniqueId = "$((Get-Date).ToString('yyMddhhmmss'))"
        }

        try {
            $directory = [System.IO.Path]::Combine($RootDirectory, ($MailboxInformation.MailboxInfo.PrimarySmtpAddress.ToString()))
            New-Item -Path $directory -ItemType Directory -Force -ErrorAction Stop | Out-Null
        } catch {
            Write-Host "Failed to create directory $directory."
            Write-HostErrorInformation
            Write-Host
            Write-Host "Setting to Root Directory instead"
            $directory = $RootDirectory
        }

        $exportNameFormat = [System.IO.Path]::Combine($directory, "$($MailboxInformation.MailboxGuid)-{0}-$UniqueId.{1}")

        try {
            $path = ($exportNameFormat -f "MailboxInformation", "xml")
            $MailboxInformation | Export-Clixml -Encoding utf8 -Path $path
            Write-Host "Successfully exported the Mailbox Information data to: $path"
            $LocationExported.Value.Add($path)
        } catch {
            Write-Host "Failed to export out the data for $($MailboxInformation.MailboxGuid) to xml"
            Write-HostErrorInformation
        }

        try {
            if ($null -ne $Messages -and
                $Messages.Count -gt 0) {
                $path = ($exportNameFormat -f "Messages", "csv")
                $Messages | Export-Csv -NoTypeInformation -Path $path
                Write-Host "Successfully exported the message data to: $path"
                $LocationExported.Value.Add($path)
            } else {
                Write-Host "Unable to export messages because there are none."
            }
        } catch {
            Write-Host "Failed to export out the message data for $($MailboxInformation.MailboxGuid) to csv"
            Write-HostErrorInformation
        }
    }
}
