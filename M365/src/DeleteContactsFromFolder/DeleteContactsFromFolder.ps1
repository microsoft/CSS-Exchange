# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.NOTES
	Name: DeleteContactsFromFolders.ps1
    Major Release History:
        04/27/2023  - Initial Public Release on CSS-Exchange
#>

$BuildVersion = ""

. $PSScriptRoot\..\..\..\Shared\LoggerFunctions.ps1
. $PSScriptRoot\..\..\..\Shared\Write-ErrorInformation.ps1
. $PSScriptRoot\..\..\..\Shared\AzureFunctions\Get-GraphAccessToken.ps1
. $PSScriptRoot\..\..\..\Shared\AzureFunctions\Invoke-GraphApiRequest.ps1
. $PSScriptRoot\..\..\..\Shared\OutputOverrides\Write-Host.ps1
. $PSScriptRoot\..\..\..\Shared\OutputOverrides\Write-Verbose.ps1
. $PSScriptRoot\..\..\..\Shared\OutputOverrides\Write-Warning.ps1
. $PSScriptRoot\..\..\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1

function Write-DebugLog($Message) {
    $Script:Logger = $Script:Logger | Write-LoggerInstance $Message
}

function Main {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('CustomRules\AvoidUsingReadHost', '', Justification = 'As discussed we need to use Read-Host in this script')]
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
    param()

    if (Test-ScriptVersion -AutoUpdate -Confirm:$false) {
        Write-Host ("Script was updated. Please re-run the command") -ForegroundColor Yellow
        return
    }

    Write-Host ("DeleteContactsFromFolders.ps1 script version $($BuildVersion)") -ForegroundColor Green

    $graphApiUrl = "https://graph.microsoft.com"
    $unableToDeleteAllContacts = $false
    $contacts = New-Object 'System.Collections.Generic.List[object]'

    $getAccessTokenParams = @{
        AzureADEndpoint = "https://login.live.com"
        ClientId        = "7e791a92-18c9-4811-b48e-a0200052991c"
        Scope           = "contacts.readwrite user.read mail.read"
    }
    $token = Get-GraphAccessToken @getAccessTokenParams

    # Graph API call to get the current logged in user
    $loggedInUserParams = @{
        Query       = "me"
        AccessToken = $token.AccessToken
        GraphApiUrl = $graphApiUrl
    }
    $loggedInUserResponse = Invoke-GraphApiRequest @loggedInUserParams

    if ($loggedInUserResponse.Successful -eq $false) {
        Write-Host "Unable to query the logged in user. Please try again." -ForegroundColor Red
        exit
    }
    Write-Host "Logged in user is: $($loggedInUserResponse.Content.UserPrincipalName)"

    try {
        # Get the list of contact folders
        $listContactFolders = @{
            Query       = "me/contactFolders"
            AccessToken = $token.AccessToken
            GraphApiUrl = $graphApiUrl
        }
        $listFoldersResponse = Invoke-GraphApiRequest @listContactFolders
        if ($listFoldersResponse.Successful -eq $false) {
            Write-Host "Unable to query the contact folders. Please try again." -ForegroundColor Red
            exit
        }

        $folders = $listFoldersResponse.Content.value

        if ($folders.Count -gt 0) {
            Write-Host "List of existing folders:"
            Write-Host "------------------------------------"
            foreach ($folder in $folders) {
                Write-Host $folder.displayName
            }
            Write-Host "------------------------------------"

            # Get the folder name to be deleted
            $folderToBeDeleted = Read-Host -Prompt "Enter the folder name to be deleted"

            if ($folders.displayName.ToLower().Contains($folderToBeDeleted.ToLower())) {
                $folderObj = $folders | Where-Object { $_.displayName -eq $folderToBeDeleted }
            }

            if ($null -ne $folderObj) {
                # Get the contacts in the folder
                $listContactsInFolder = @{
                    Query       = "me/contactFolders/$($folderObj.id)/contacts?`$top=100"
                    AccessToken = $token.AccessToken
                    GraphApiUrl = $graphApiUrl
                }
                $contactsResponse = Invoke-GraphApiRequest @listContactsInFolder
                if ($contactsResponse.Successful -eq $false) {
                    Write-Host "Unable to query the contacts. Please try again." -ForegroundColor Red
                    exit
                }
                $contacts.AddRange($contactsResponse.Content.value)

                # Get all the contacts in the folder and probably looping through the nextLink (pagination)
                if (-not([System.String]::IsNullOrEmpty($contactsResponse.Content.'@odata.nextLink'))) {
                    do {
                        $query = $contactsResponse.Content.'@odata.nextLink'.replace("https://graph.microsoft.com/v1.0/", "")
                        $listContactsInFolder.Query = $query
                        $contactsResponse = Invoke-GraphApiRequest @listContactsInFolder
                        $contacts.AddRange($contactsResponse.Content.value)
                    } until (-not($contactsResponse.Content.'@odata.nextLink'))
                }

                Write-Host "Number of contacts in the folder: '$($folderObj.displayName)' is: $($contacts.Count)"
                if ($PSCmdlet.ShouldProcess("", $folderObj.displayName, "About to delete the folder and its content. Are you sure?")) {
                    Write-Host "Deleting folder contents..." -ForegroundColor Cyan
                    # Loop through and delete the contacts
                    foreach ($contact in $contacts) {
                        Write-Host "Now processing: '$($contact.displayName)'" -ForegroundColor Cyan
                        Write-Host "Id:  $($contact.id)" -ForegroundColor Cyan
                        $deleteContactParams = @{
                            Query              = "me/contactFolders/$($folderObj.id)/contacts/$($contact.id)"
                            AccessToken        = $token.AccessToken
                            Method             = "DELETE"
                            ExpectedStatusCode = 204
                            GraphApiUrl        = $graphApiUrl
                        }
                        $deleteContactResponse = Invoke-GraphApiRequest @deleteContactParams
                        if ($deleteContactResponse.Successful -eq $false) {
                            Write-Host "Unable to delete the contact" -ForegroundColor Red
                            $unableToDeleteAllContacts = $true
                        } else {
                            Write-Host "Deleted contact successfully" -ForegroundColor Green
                        }
                    }

                    if ($unableToDeleteAllContacts -eq $false) {
                        Write-Host "Deleted folder content, now deleting the folder itself..." -ForegroundColor Cyan
                        # Remove the folder itself
                        $deleteContactFolderParams = @{
                            Query              = "me/contactFolders/$($folderObj.id)"
                            AccessToken        = $token.AccessToken
                            Method             = "DELETE"
                            ExpectedStatusCode = 204
                            GraphApiUrl        = $graphApiUrl
                        }
                        $deleteContactFolderResponse = Invoke-GraphApiRequest @deleteContactFolderParams
                        if ($deleteContactFolderResponse.Successful -eq $false) {
                            Write-Host "Unable to delete the folder: '$($folderObj.displayName)'" -ForegroundColor Red
                            Write-Host "Id: Id: $($folderObj.id)" -ForegroundColor Red
                            exit
                        }
                        Write-Host "Folder: '$($folderObj.displayName)' has been deleted" -ForegroundColor Green
                    } else {
                        Write-Host "Unable to delete all contacts in the folder. Please run the script again" -ForegroundColor Yellow
                    }
                }
            } else {
                Write-Host "A folder with the name '$folderToBeDeleted' wasn't found" -ForegroundColor Red
            }
        } else {
            Write-Host "No folders exists in this mailbox - nothing to do" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "An error occurred. Please contact support"
        Write-VerboseErrorInformation
    }
}

try {
    $loggerParams = @{
        LogName        = "DeleteContactsFromFolder"
        LogDirectory   = (Get-Location).Path
        AppendDateTime = $true
        ErrorAction    = "SilentlyContinue"
    }

    $Script:Logger = Get-NewLoggerInstance @loggerParams
    SetProperForegroundColor
    SetWriteHostAction ${Function:Write-DebugLog}
    SetWriteVerboseAction ${Function:Write-DebugLog}

    Main
} catch {
    Write-VerboseErrorInformation
} finally {
    Write-Host ""
    Write-Host ("Log file written to: $($Script:Logger.FullPath)")
    Write-Host ""
    Write-Host ("Do you have feedback regarding the script? Please email ExToolsFeedback@microsoft.com.") -ForegroundColor Green
    Write-Host ""

    RevertProperForegroundColor
}
