# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    This script audits mails and check if PidLidReminderFileParameter property is populated or not. If required admins can use this script to cleanup the property.
.DESCRIPTION
    There are two modes in which we can run the script Audit and Cleanup.

    Audit Mode: Script provides a csv to the admins with details of mails that have PidLidReminderFileParameter property populated.
    Cleanup Mode: Script performs Cleanup action on mails by either clearing the property or deleting the mail itself.

    Prerequisites to run the script for exchange onprem: You need to have full access permission on the UserMailboxes

    Prerequisites to run the script for exchange online: You either need a application that has full access permission. Provide the tenantId, ClientId and AppSecret in that case.
    Otherwise, you should have permissions to create application with full access permission. You should have AzureAD powershell module installed.
.PARAMETER DLLPath
    Use this parameter to provide path to Microsoft.Exchange.WebServices.dll
.PARAMETER EwsServerURL
    Use this parameter to provide Ews service url
.PARAMETER ClientID
    User this parameter to provide Client ID
.PARAMETER UserMailboxesFilePath
    Use this parameter to provide path to the file containing list of UserAddresses to audit
.PARAMETER StartTimeFilter
    Use this parameter to provide start time filter
.PARAMETER EndTimeFilter
    Use this parameter to provide end time filter
.PARAMETER MaxCSVLength
    Use this parameter to provide maximum accepted length of csv output
.PARAMETER CleanupAction
    Use this parameter to provide a cleanup action. ClearProperty or ClearEmail
.PARAMETER CleanupInfoFilePath
    Use this parameter to provide path to the csv file containing the details of emails to be cleaned up
.EXAMPLE
    PS C:\> .\ClearEmailProperty.ps1 -UserMailboxesFilePath <path to file containing user mailboxes> -DLLPath <path to Microsoft.Exchange.WebServices.dll>
    This will run the tool in audit mode on all the mailboxes provided in UserMailboxesFilePath and provide the user with a csv AuditResults_<current time>.csv in the same folder
.EXAMPLE
    PS C:\> .\ClearEmailProperty.ps1 -CleanupFilePath <path to cleanup csv> -CleanupAction ClearProperty -DLLPath <path to Microsoft.Exchange.WebServices.dll>
    This will go through all the entries in cleanup csv file and for each mail entry having Cleanup set to y it will clear PidLidReminderFileParameter property
.EXAMPLE
    PS C:\> .\ClearEmailProperty.ps1 -CleanupFilePath <path to cleanup csv> -CleanupAction ClearEmail -DLLPath <path to Microsoft.Exchange.WebServices.dll>
    This will go through all the entries in cleanup csv file and for each mail entry having cleanup set to y it will delete the email
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]

param(
    [Parameter(Mandatory=$true, ParameterSetName = 'Audit')]
    [Parameter(Mandatory=$true, ParameterSetName = 'Cleanup')]
    [ValidateScript({ Test-Path -Path $_ -PathType leaf })]
    [String]$DLLPath,

    [Parameter(Mandatory=$true, ParameterSetName = 'Audit')]
    [Parameter(Mandatory=$true, ParameterSetName = 'Cleanup')]
    [ValidateSet('Server', 'USGov', 'Comm')]
    [String]$Environment,

    [Parameter(Mandatory=$false, ParameterSetName = 'Audit')]
    [Parameter(Mandatory=$false, ParameterSetName = 'Cleanup')]
    [string]$EwsServerURL,

    [Parameter(Mandatory=$false, ParameterSetName = 'Audit')]
    [Parameter(Mandatory=$false, ParameterSetName = 'Cleanup')]
    [string]$ClientID,

    [Parameter(Mandatory=$true, ParameterSetName = 'Audit')]
    [ValidateScript({ Test-Path $_ })]
    [String]$UserMailboxesFilePath,

    [Parameter(Mandatory=$false, ParameterSetName = 'Audit')]
    [DateTime]$StartTimeFilter,

    [Parameter(Mandatory=$false, ParameterSetName = 'Audit')]
    [DateTime]$EndTimeFilter,

    [Parameter(Mandatory=$false, ParameterSetName = 'Audit')]
    [int]$MaxCSVLength = 1000,

    [Parameter(Mandatory=$true, ParameterSetName = 'Cleanup')]
    [ValidateSet('ClearProperty', 'ClearEmail')]
    [string]$CleanupAction,

    [Parameter(Mandatory=$true, ParameterSetName = 'Cleanup')]
    [ValidateScript({ Test-Path -Path $_ -PathType leaf })]
    [string]$CleanupInfoFilePath
)

begin {
    . $PSScriptRoot\WriteFunctions.ps1
    . $PSScriptRoot\..\..\..\Shared\OutputOverrides\Write-Host.ps1
    . $PSScriptRoot\..\..\..\Shared\OutputOverrides\Write-Progress.ps1
    . $PSScriptRoot\..\..\..\Shared\OutputOverrides\Write-Verbose.ps1
    . $PSScriptRoot\..\..\..\Shared\OutputOverrides\Write-Warning.ps1
    . $PSScriptRoot\..\..\..\Shared\LoggerFunctions.ps1
    . $PSScriptRoot\..\..\..\Shared\Show-Disclaimer.ps1
    . $PSScriptRoot\..\..\..\Shared\Get-ExchangeBuildVersionInformation.ps1

    $Script:Logger = Get-NewLoggerInstance -LogName "ClearEmailProperty-$((Get-Date).ToString("yyyyMMddhhmmss"))-Debug" `
        -AppendDateTimeToFileName $false `
        -ErrorAction SilentlyContinue

    SetWriteHostAction ${Function:Write-HostLog}
    SetWriteVerboseAction ${Function:Write-VerboseLog}
    SetWriteWarningAction ${Function:Write-HostLog}
    SetWriteProgressAction ${Function:Write-HostLog}

    $mode = $PsCmdlet.ParameterSetName

    function EWSAuth {
        param(
            [string]$Environment,
            $token
        )
        ## Create the Exchange Service object with credentials
        $Service = New-Object Microsoft.Exchange.WebServices.Data.ExchangeService

        if ($Environment -eq "Server") {
            $PSCredential = (Get-Credential)
            $Service.Credentials = New-Object Microsoft.Exchange.WebServices.Data.WebCredentials($PSCredential.UserName, [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PSCredential.Password)))
        } else {
            $Service.Credentials = New-Object Microsoft.Exchange.WebServices.Data.OAuthCredentials($token.access_token)
        }

        if ($Environment -eq "Server") {
            if ($null -ne $EwsServerURL -and $EwsServerURL -ne "") {
                $Service.Url = New-Object Uri($EwsServerURL)
                CheckOnpremCredentials -ewsService $Service
            } else {
                try {
                    $Service.AutodiscoverUrl($PSCredential.UserName)
                } catch {
                    Write-Error "Unable to make Autodiscover call to fetch EWS endpoint details. Please make sure you have enter valid credentials."
                    exit
                }
            }
        } elseif ($Environment -eq "Comm") {
            $Service.Url = New-Object Uri("https://outlook.office365.com/EWS/Exchange.asmx")
        } else {
            $Service.Url = New-Object Uri("https://outlook.office365.us/EWS/Exchange.asmx")
        }

        return $Service
    }

    function CheckOnpremCredentials {
        param (
            $ewsService
        )

        try {
            $null = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($ewsService, [Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::MsgFolderRoot)
        } catch {
            Write-Error "Invalid credentials. Please check your username and password and try again."
            exit
        }
    }

    function Get-MultiValueEmailString([array]$emailArray) {
        if ($emailArray.Length -gt 0) {

            $tempArray = @()
            foreach ($value in $emailArray) {
                $eachValue = $value.Address
                $tempArray += $eachValue
            }
            $valueList = $tempArray -join ","

            return $valueList
        } else {
            return $null
        }
    }

    function CreateCustomCSV {
        param (
            $mailbox,
            $data,
            [string]$CsvPath
        )

        $ItemType = $data.ItemClass

        if ($data.ItemClass.StartsWith("IPM.Note")) {
            $ItemType = "E-Mail"
        } elseif ($data.ItemClass.StartsWith("IPM.Appointment")) {
            $ItemType = "Calendar"
        } elseif ($data.ItemClass.StartsWith("IPM.Task")) {
            $ItemType = "Task"
        }

        $row = [PSCustomObject]@{
            "Mailbox"                     = $mailbox
            "Id"                          = $data.Id
            "ItemType"                    = $ItemType
            "Sender"                      = Get-MultiValueEmailString($data.From)
            "Recipient"                   = Get-MultiValueEmailString($data.ToRecipients)
            "Subject"                     = $data.Subject
            "DateReceived"                = $data.DateTimeReceived
            "PidLidReminderFileParameter" = $data.ExtendedProperties[0].Value
            "Cleanup"                     = "N"
        }

        $row | Export-Csv -Path $CsvPath -NoTypeInformation -Append -Force
    }

    # Define a function to get all the subfolders of a given folder
    function GetSubfolders {
        param (
            $folder,
            $foldersList
        )
        # Get the subfolders of the folder
        $folder.FindFolders([Microsoft.Exchange.WebServices.Data.FolderView]::new(1000)) | ForEach-Object {
            # Add the folder path to the list
            $null = $foldersList.Add($_)
            # Recursively get the subfolders of this folder
            GetSubfolders -folder $_ -foldersList $foldersList
        }
    }

    function FindItem {
        param (
            [Microsoft.Exchange.WebServices.Data.ExchangeService]$exchangeService,
            [string]$Id
        )
        $ps = New-Object Microsoft.Exchange.WebServices.Data.PropertySet(New-Object Microsoft.Exchange.WebServices.Data.ExtendedPropertyDefinition([Microsoft.Exchange.WebServices.Data.DefaultExtendedPropertySet]::Common, 0x0000851F, [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::String))
        return [Microsoft.Exchange.WebServices.Data.Item]::Bind($exchangeService, $Id, $ps);
    }

    function CreateOAUTHToken {
        param (
            [string]$TenantID,
            [string]$ClientID,
            [string]$AppSecret,
            [string]$Env

        )

        #Create correct environment variables
        switch ($Env) {
            'USGov' {
                $Scope = "https://outlook.office365.us/.default"
                $Url = "https://login.microsoftonline.us/$TenantID/oauth2/v2.0/token"
            }
            'Comm' {
                $Scope = "https://outlook.office365.com/.default"
                $Url = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
            }
            'Server' {
                return
            }
        }

        try {

            $body=@{
                scope         =$Scope
                client_id     =$ClientID
                client_secret =$AppSecret
                grant_type    ="client_credentials"
            }

            $PostSplat = @{
                ContentType = 'application/x-www-form-urlencoded'
                Method      = 'POST'

                # Create string by joining bodyList with '&'
                Body        = $Body
                Uri         = $Url
            }

            $Token=Invoke-RestMethod @PostSplat
        } catch {
            Write-Host "`nFailure creating EWS auth token, exiting Program. Please review the error message below and re-run the program:`n`n$_" -ForegroundColor Red
            exit
        }

        $script:tokenLastRefreshTime = (Get-Date)

        return $Token
    }

    function GetApplicationDetails {
        param (
            $clientId
        )

        try {
            Import-Module AzureAD
            Write-Host "`nPrompting user for authentication, please minimize this window if you do not see an authorization prompt as it may be in the background"
            Connect-AzureAD
        } catch {
            Write-Host "Unable to run Connect-AzureAD... Make sure you have AzureAD module installed"
            exit
        }

        $aadApplication = Get-AzureADApplication -Filter "AppId eq '$clientId'"

        #Assign App Password, make it valid for 7 days
        $appPassword = New-AzureADApplicationPasswordCredential -ObjectId $aadApplication.ObjectId -CustomKeyIdentifier "AppAccessKey" -EndDate (Get-Date).AddDays(7)

        Write-Host "`nWaiting 60 seconds for app credentials to register.."
        Start-Sleep -Seconds 60
        Write-Host "`nContinuing..."

        return @{
            "TenantID"  = (Get-AzureADTenantDetail).ObjectId
            "ClientID"  = $aadApplication.AppId
            "AppSecret" = $appPassword.Value
        }
    }

    function CreateApplication {
        try {
            Import-Module AzureAD
            Write-Host "`nPrompting user for authentication, please minimize this window if you do not see an authorization prompt as it may be in the background"
            Connect-AzureAD
        } catch {
            Write-Host "Unable to run Connect-AzureAD... Make sure you have AzureAD module installed"
            exit
        }

        $aadApplication = $null

        while (-Not $aadApplication) {
            #Prompt User for App Name
            [string]$appName = Read-Host "`nPlease enter desired application name"

            try {
                $aadApplication = New-AzureADApplication -DisplayName $appName
            } catch {
                Write-Host "`nThere was an error creating the application, please reference the error below and try again" -ForegroundColor Red
                $_

                exit
            }
        }

        #Add current user to owner of newly created application
        $currentUser = (Get-AzureADUser -ObjectId (Get-AzureADCurrentSessionInfo).Account.Id)
        Write-Host "`nAdding user $($currentUser.UserPrincipalName) as owner of $appName)"
        Add-AzureADApplicationOwner -ObjectId $aadApplication.ObjectId -RefObjectId $currentUser.ObjectId | Out-Null

        #Get Service Principal of MS Graph Resource API
        $ews_SP = Get-AzureADServicePrincipal -All $true | Where-Object { $_.DisplayName -eq "Office 365 Exchange Online" }

        #Initialize RequiredResourceAccess for Microsoft Graph Resource API
        $requiredAccess = New-Object Microsoft.Open.AzureAD.Model.RequiredResourceAccess
        $requiredAccess.ResourceAppId = $ews_SP.AppId
        $requiredAccess.ResourceAccess = New-Object System.Collections.Generic.List[Microsoft.Open.AzureAD.Model.ResourceAccess]

        #Set Application Permissions
        $ApplicationPermissions = @('full_access_as_app')

        #Add app permissions
        foreach ($permission in $ApplicationPermissions) {
            $reqPermission = $null
            #Get required app permission
            $reqPermission = $ews_SP.AppRoles | Where-Object { $_.Value -eq $permission }
            if ($reqPermission) {
                $resourceAccess = New-Object Microsoft.Open.AzureAD.Model.ResourceAccess
                $resourceAccess.Type = "Role"
                $resourceAccess.Id = $reqPermission.Id
                #Add required app permission
                $requiredAccess.ResourceAccess.Add($resourceAccess)
            } else {
                Write-Host "App permission $permission not found in the Graph Resource API" -ForegroundColor Red
            }
        }

        #Add required resource accesses
        $requiredResourcesAccess = New-Object System.Collections.Generic.List[Microsoft.Open.AzureAD.Model.RequiredResourceAccess]
        $requiredResourcesAccess.Add($requiredAccess)

        #Set permissions in newly created Azure AD App
        $appObjectId=$aadApplication.ObjectId
        Write-Host "`nSetting Azure AD Permissions"
        Set-AzureADApplication -ObjectId $appObjectId -RequiredResourceAccess $requiredResourcesAccess | Out-Null

        #Assign App Password, make it valid for 7 days
        $appPassword = New-AzureADApplicationPasswordCredential -ObjectId $appObjectId -CustomKeyIdentifier "AppAccessKey" -EndDate (Get-Date).AddDays(7)

        #Create Service Principal
        $appId=$aadApplication.AppId
        $servicePrincipal = New-AzureADServicePrincipal -AppId $appId -Tags @("WindowsAzureActiveDirectoryIntegratedApp")

        #Grant Admin Consent for App Permissions
        $requiredResourcesAccess=(Get-AzureADApplication -ObjectId $appObjectId).RequiredResourceAccess

        Write-Host "`nAssigning Necessary Azure AD Service Roles"
        foreach ($resourceAppAccess in $requiredResourcesAccess) {
            $resourceApp = Get-AzureADServicePrincipal -All $true | Where-Object { $_.AppId -eq $resourceAppAccess.ResourceAppId }

            foreach ($permission in $resourceAppAccess.ResourceAccess) {
                if ($permission.Type -eq "Role") {
                    New-AzureADServiceAppRoleAssignment -ObjectId $servicePrincipal.ObjectId -PrincipalId $servicePrincipal.ObjectId -ResourceId $resourceApp.ObjectId -Id $permission.Id | Out-Null
                }
            }
        }

        #Use newly created app to query graphAPI
        [string]$TenantID = (Get-AzureADTenantDetail).ObjectId
        [string]$ClientID = $aadApplication.AppId

        Write-Host "`nWaiting 60 seconds for app to register.."
        Start-Sleep -Seconds 60
        Write-Host "`nContinuing..."

        #Create file with application information for future use.
        $appInfo = @()
        $appInfo += [PSCustomObject]@{
            "Application Name:" = $aadApplication.DisplayName
            "Tenant ID:"        = $TenantID
            "Client (App) ID:"  = $ClientID
        }

        Write-Host "`nExporting information about newly created app '$($aadApplication.DisplayName)' to Application_Information.txt
        Use the application ClientID contained in this file for future run of the script"

        #Export newly created app credentials to file
        $appInfo | Format-List | Out-File -FilePath "Application_Information.txt" -Append

        return @{
            "TenantID"  = (Get-AzureADTenantDetail).ObjectId
            "ClientID"  = $aadApplication.AppId
            "AppSecret" = $appPassword.Value
        }
    }

    function CheckTokenExpiry {
        param (
            $applicationInfo,
            [ref]$ewsService,
            [ref]$token,
            [string]$Environment
        )

        if ($Environment -eq "Server") {
            return
        }

        # if token is going to expire in next 5 min then refresh it
        if ($null -eq $script:tokenLastRefreshTime -or $script:tokenLastRefreshTime.AddMinutes(55) -lt (Get-Date)) {
            $token = CreateOAUTHToken -TenantID $applicationInfo.TenantID -ClientID $applicationInfo.ClientID -AppSecret $applicationInfo.AppSecret -Env $Environment
            $ewsService = EWSAuth -Environment $Environment -token $token
        }
    }
} process {
    # Import "Microsoft Exchange Web Services Managed API 2.2"
    Import-Module -Name $DLLPath

    $failedMailboxes = New-Object 'System.Collections.Generic.List[string]'
    $invalidEntries = New-Object 'System.Collections.Generic.List[string]'

    #MailInfo
    $mailInfo = @{
        "Id"                          = [Microsoft.Exchange.WebServices.Data.ItemSchema]::Id
        "Sender"                      = [Microsoft.Exchange.WebServices.Data.EmailMessageSchema]::From
        "Recipient"                   = [Microsoft.Exchange.WebServices.Data.EmailMessageSchema]::ToRecipients
        "Subject"                     = [Microsoft.Exchange.WebServices.Data.EmailMessageSchema]::Subject
        "DateReceived"                = [Microsoft.Exchange.WebServices.Data.EmailMessageSchema]::DateTimeReceived
        "PidLidReminderFileParameter" = New-Object Microsoft.Exchange.WebServices.Data.ExtendedPropertyDefinition([Microsoft.Exchange.WebServices.Data.DefaultExtendedPropertySet]::Common, 0x0000851F, [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::String)
        "ItemClass"                   = [Microsoft.Exchange.WebServices.Data.ItemSchema]::ItemClass
    }

    if ($Environment -ne "Server") {
        if (-not $ClientID) {
            $application = CreateApplication
        } else {
            $application = GetApplicationDetails -clientId $ClientID
        }

        $applicationInfo = @{
            "TenantID"  = $application.Tenant.Id
            "ClientID"  = $application.ClientID
            "AppSecret" = $application.AppSecret
        }

        #Create OAUTH token
        $EWSToken = CreateOAUTHToken -TenantID $applicationInfo.TenantID -ClientID $applicationInfo.ClientID -AppSecret $applicationInfo.AppSecret -Env $Environment

        $ewsService = EWSAuth -Environment $Environment -Token $EWSToken
    } else {
        #Server
        $EWSToken = $null
        $ewsService = EWSAuth -Environment $Environment
    }

    if ($mode -eq "Audit") {
        $mailAddresses = (Get-Content $UserMailboxesFilePath).Split([Environment]::NewLine) | Where-Object { $_ -ne "" -and $_ -ne $null }

        if ($null -eq $mailAddresses -or $mailAddresses.Count -eq 0) {
            Write-Error "No mailbox provided in the file"
        }

        $csvFileName = ("AuditResults_{0}.csv" -F (Get-Date -Format "yyyyMMdd_HHmmss"))

        $itemView = New-Object Microsoft.Exchange.WebServices.Data.ItemView([int]::MaxValue)

        $searchFilterCollection = New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+SearchFilterCollection

        if ($StartTimeFilter -ne $null) {
            $searchFilterStartTime = New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+IsGreaterThan([Microsoft.Exchange.WebServices.Data.ItemSchema]::DateTimeCreated, $StartTimeFilter)
            $searchFilterCollection.Add($searchFilterStartTime)
        }

        if ($EndTimeFilter -ne $null) {
            $searchFilterEndTime = New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+IsLessThan([Microsoft.Exchange.WebServices.Data.ItemSchema]::DateTimeCreated, $EndTimeFilter)
            $searchFilterCollection.Add($searchFilterEndTime)
        }

        $searchFilterPidLidReminderFileParameterExists = New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+Exists($mailInfo["PidLidReminderFileParameter"])
        $searchFilterCollection.Add($searchFilterPidLidReminderFileParameterExists)

        $PropertySet = New-Object Microsoft.Exchange.WebServices.Data.PropertySet
        foreach ($key in $mailInfo.Keys) {
            $PropertySet.Add($mailInfo[$key])
        }

        $mailboxProcessed = 0
        $rowCount = 0

        foreach ($mailAddress in $mailAddresses) {
            Write-Host ("Processing {0} of {1} mailboxes" -F ($mailboxProcessed + 1), $mailAddresses.Count)
            if ($Environment -ne "Server") {
                $ewsService.ImpersonatedUserId = New-Object Microsoft.Exchange.WebServices.Data.ImpersonatedUserId([Microsoft.Exchange.WebServices.Data.ConnectingIdType]::SmtpAddress, $mailAddress)
            }

            $userMailbox = New-Object Microsoft.Exchange.WebServices.Data.Mailbox($mailAddress)

            if ($null -eq $userMailbox) {
                Write-Host ("Unable to get mailbox associated with mail address {0}" -F $mailAddress)
                $failedMailboxes.Add($mailAddress)
                $mailboxProcessed += 1
                continue
            }

            try {
                # Check for token expiry
                CheckTokenExpiry -Environment $Environment -token ([ref]$EWSToken) -ewsService ([ref]$ewsService) -applicationInfo $applicationInfo

                $rootFolderId = New-Object Microsoft.Exchange.WebServices.Data.FolderId([Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::MsgFolderRoot, $userMailbox)
                $rootFolder = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($ewsService, $rootFolderId)

                # Create a new ArrayList to hold the folder
                $foldersList = New-Object System.Collections.ArrayList

                GetSubfolders -folder $rootFolder -foldersList $foldersList
            } catch {
                Write-Host ("Unable to process mailbox {0}, either you don't have full access permission on the mailbox or the mailbox is inaccessible" -F $mailAddress)
                $failedMailboxes.Add($mailAddress)
                $mailboxProcessed += 1
                continue
            }

            $IdsProcessed = New-Object 'System.Collections.Generic.List[string]'

            foreach ($folder in $foldersList) {
                # Check for token expiry
                CheckTokenExpiry -Environment $Environment -token ([ref]$EWSToken) -ewsService ([ref]$ewsService) -applicationInfo $applicationInfo
                $results = $ewsService.FindItems($folder.Id, $searchFilterCollection, $itemView);
                if ($null -ne $results -and $null -ne $results.Items -and $results.Items.Count -gt 0) {
                    $items = $ewsService.LoadPropertiesForItems($results.Items, $PropertySet)
                } else {
                    continue
                }

                foreach ($item in $items) {
                    if ($item.Item.Id -notin $IdsProcessed) {
                        CreateCustomCSV -mailbox $mailAddress -data $item.Item -CsvPath $csvFileName
                        $rowCount ++
                        if ($rowCount -ge $MaxCSVLength) {
                            Write-Host ("The csv file has reached it's maximum limit of {0} rows... aborting... Please apply appropriate filters to reduce the result size" -F $MaxCSVLength)
                            Write-Host ("Please find the audit results in {0} created in the current folder." -f $csvFileName)
                            exit
                        }
                        $IdsProcessed.Add($item.Item.Id)
                    }
                }
            }

            $mailboxProcessed ++;
        }

        if ($rowCount -eq 0) {
            Write-Host "No vulnerable email found"
        } else {
            Write-Host ("Please find the audit results in {0} created in the current folder." -f $csvFileName)
        }
    } else {
        $params = @{
            Message   = "Display Warning about Store operation"
            Target    = "The script will perform store operation on mailboxes using EWS"
            Operation = ""
        }

        if ($CleanupAction -eq "ClearProperty") {
            $params.Operation = "Clear the PidLidReminderFileParameter property of mail items"
        }

        if ($CleanupAction -eq "ClearEmail") {
            $params.Operation = "Delete emails"
        }

        Show-Disclaimer @params

        $cleanupCSV = (Import-Csv $CleanupInfoFilePath)

        $entryCount = 0

        foreach ($entry in $cleanupCSV) {
            $entryCount ++
            if ($null -eq $entry.Id -or $entry.Id -eq "") {
                Write-Error ("No Id present for entry number: {0}, Line number: {1}" -f $entryCount, ($entryCount + 1))
                $invalidEntries.Add($entryCount)
                continue
            }

            if ($null -eq $entry.Mailbox -or $entry.Mailbox -eq "") {
                Write-Error ("No Mailbox address present for entry number: {0}, Line number: {1}" -f $entryCount, ($entryCount + 1))
                $invalidEntries.Add($entryCount)
                continue
            }

            if ($null -ne $entry.Cleanup -and $entry.Cleanup.ToLower() -eq "y") {
                if ($Environment -ne "Server") {
                    $ewsService.ImpersonatedUserId = New-Object Microsoft.Exchange.WebServices.Data.ImpersonatedUserId([Microsoft.Exchange.WebServices.Data.ConnectingIdType]::SmtpAddress, $entry.Mailbox)
                }
                # Check for token expiry
                CheckTokenExpiry -Environment $Environment -token ([ref]$EWSToken) -ewsService ([ref]$ewsService) -applicationInfo $applicationInfo
                $item = FindItem -exchangeService $ewsService -Id $entry.Id
                if ($null -ne $item) {
                    try {
                        if ($CleanupAction -eq "ClearEmail") {
                            $item.Delete([Microsoft.Exchange.WebServices.Data.DeleteMode]::HardDelete)
                        } else {
                            if (-not $item.RemoveExtendedProperty($mailInfo["PidLidReminderFileParameter"])) {
                                Write-Error ("Failed to clear property for entry number: {0}, Line number: {1}" -f $entryCount, ($entryCount + 1))
                                $invalidEntries.Add($entryCount)
                                continue
                            }

                            $item.Update([Microsoft.Exchange.WebServices.Data.ConflictResolutionMode]::AlwaysOverwrite);
                        }
                    } catch {
                        Write-Error ("Unable to perform cleanup action on entry number: {0}, Line number: {1}" -f $entryCount, ($entryCount + 1))
                        $invalidEntries.Add($entryCount)
                        continue
                    }
                } else {
                    Write-Error ("Unable to find email associated to entry number: {0}, Line number: {1}" -f $entryCount, ($entryCount + 1))
                    $invalidEntries.Add($entryCount)
                    continue
                }
            }
        }

        Write-Host "Completed cleanup operation!"
    }
} end {
    if ($mode -eq "Audit" -and $null -ne $failedMailboxes -and $failedMailboxes.Count -gt 0) {
        Write-Host ("Couldn't Audit mailboxes: {0}" -f [string]::Join(", ", $failedMailboxes))
    }

    if ($mode -eq "Cleanup" -and $null -ne $invalidEntries -and $invalidEntries.Count -gt 0) {
        Write-Host ("Couldn't Cleanup the entries: {0}" -f [string]::Join(", ", $invalidEntries))
    }
}
