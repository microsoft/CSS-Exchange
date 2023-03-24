# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Invoke-CatchActionError.ps1
. $PSScriptRoot\..\CertificateFunctions\Enable-TrustAnyCertificateCallback.ps1

function Send-EwsMailMessage {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $false)]
        [ValidatePattern("^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$")]
        [string]$From = $null,

        [Parameter(Mandatory = $true)]
        [ValidatePattern("^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$")]
        [string[]]$To,

        [Parameter(Mandatory = $false)]
        [ValidatePattern("^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$")]
        [string[]]$Cc = $null,

        [Parameter(Mandatory = $false)]
        [ValidatePattern("^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$")]
        [string[]]$Bcc = $null,

        [Parameter(Mandatory = $true)]
        [string]$Subject,

        [Parameter(Mandatory = $true)]
        [string]$Body,

        [Parameter(Mandatory = $false)]
        [switch]$BodyAsHtml,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Low", "Normal", "High")]
        [string]$Importance = "Normal",

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [string]$EwsManagedAPIAssemblyPath = "$($env:ExchangeInstallPath)bin\Microsoft.Exchange.WebServices.dll",

        [Parameter(Mandatory = $true)]
        [ValidatePattern("\/ews\/exchange.asmx$")]
        [string]$EwsServiceUrl,

        [Parameter(Mandatory = $false)]
        [switch]$IgnoreCertificateMismatch,

        [Parameter(Mandatory = $false)]
        [ScriptBlock]$CatchActionFunction
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        if (Test-Path $EwsManagedAPIAssemblyPath) {
            Write-Verbose ("EWS Managed API Assembly was found under: $($EwsManagedAPIAssemblyPath)")
            Add-Type -Path $EwsManagedAPIAssemblyPath
        } else {
            Write-Verbose ("EWS Managed API Assembly was not found under: $($EwsManagedAPIAssemblyPath)")
            Write-Verbose ("Please download it from: 'https://aka.ms/ews-managed-api-readme' and provide the correct path")
            return $false
        }
    } process {
        if ($IgnoreCertificateMismatch) {
            Write-Verbose ("IgnoreCertificateMismatch was used - policy will be set to: TrustAnyCertificate")
            Enable-TrustAnyCertificateCallback
        }

        try {
            $ewsService = New-Object "Microsoft.Exchange.WebServices.Data.ExchangeService" -ArgumentList Exchange2013_SP1
            $ewsService.Url = $EwsServiceUrl

            $ewsService.Credentials = New-Object "Microsoft.Exchange.WebServices.Data.WebCredentials"

            if ($null -ne $Credential) {
                Write-Verbose ("Credentials were provided - will try to use them")
                Write-Verbose ("Username: $($Credential.UserName)")
                $ewsService.UseDefaultCredentials = $false
                $ewsService.Credentials.Credentials.UserName = $Credential.UserName
                $ewsService.Credentials.Credentials.Password = $Credential.GetNetworkCredential().Password
            } else {
                Write-Verbose ("We will try to send the email from user: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)")
                $ewsService.UseDefaultCredentials = $true
            }

            $newMessage = New-Object "Microsoft.Exchange.WebServices.Data.EmailMessage" -ArgumentList $ewsService
            $newMessage.Subject = $Subject
            $newMessage.Importance = $Importance
            $newMessage.Body = $Body

            if (-not($BodyAsHtml)) {
                Write-Verbose ("Message will be send in plain text")
                $newMessage.Body.BodyType = "Text"
            }

            if ($null -ne $From) {
                Write-Verbose ("We will try to send the message by using the following 'From' address: $($From)")
                $newMessage.From = $From
            }

            foreach ($toRecipient in $To) {
                Write-Verbose ("Recipient: $($toRecipient) will be added to 'To' line")
                [void]$newMessage.ToRecipients.Add($toRecipient)
            }

            if ($null -ne $Cc) {
                foreach ($ccRecipient in $Cc) {
                    Write-Verbose ("Recipient: $($ccRecipient) will be added to 'Cc' line")
                    [void]$newMessage.CcRecipients.Add($ccRecipient)
                }
            }

            if ($null -ne $Bcc) {
                foreach ($bccRecipient in $Bcc) {
                    Write-Verbose ("Recipient: $($bccRecipient) will be added to 'Bcc' line")
                    [void]$newMessage.BccRecipients.Add($bccRecipient)
                }
            }
        } catch {
            Write-Verbose ("Something went wrong while preparing to send an email with the subject '$($newMessage.Subject)'")
            Invoke-CatchActionError $CatchActionFunction
            return $false
        }
    } end {
        try {
            $newMessage.SendAndSaveCopy()
        } catch {
            Write-Verbose ("Something went wrong while trying to send an email with the subject '$($newMessage.Subject)'")
            Invoke-CatchActionError $CatchActionFunction
            return $false
        }

        Write-Verbose ("An email with the subject '$($newMessage.Subject)' was sent and saved in the SendItems folder")
        return $true
    }
}
