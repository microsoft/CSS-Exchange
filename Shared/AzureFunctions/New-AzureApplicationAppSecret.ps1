. $PSScriptRoot\Invoke-GraphApiRequest.ps1

function New-AzureApplicationAppSecret {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        $AccessToken,
        $AzureApplicationName,
        $GraphApiUrl
    )

    <#
        This function creates an App secret for a given application and return it.
        The assigned App Password is valid for 7 days.
        https://learn.microsoft.com/graph/api/application-addpassword?view=graph-rest-1.0&tabs=http#request
    #>

    Write-Verbose "Calling $($MyInvocation.MyCommand)"

    $getAadApplicationParams = @{
        AccessToken          = $AccessToken
        AzureApplicationName = $AzureApplicationName
        GraphApiUrl          = $GraphApiUrl
    }
    $getAadApplicationResponse = Get-AzureApplication @getAadApplicationParams

    if ($null -eq $getAadApplicationResponse) {
        Write-Host "Something went wrong while querying the Azure application" -ForegroundColor Red
        exit
    } elseif ([System.String]::IsNullOrEmpty($getAadApplicationResponse.value.id)) {
        Write-Host "No Azure application found with the name: $AzureApplicationName. Please re-run the script with -CreateAzureApplication to create the application." -ForegroundColor Red
        exit
    }

    # Garbage collect expired secrets
    if ($getAadApplicationResponse.value.passwordCredentials.Count -gt 0) {
        Write-Host "The Azure application already has application secrets - checking for expired ones..."
        foreach ($password in $getAadApplicationResponse.value.passwordCredentials) {
            $endDateTime = [DateTime]::Parse($password.endDateTime).ToUniversalTime()
            if ($endDateTime -lt (Get-Date).ToUniversalTime()) {
                if ($PSCmdlet.ShouldProcess($password.keyId, "Delete expired client secret")) {
                    Write-Host "Secret with id: $($password.keyId) has expired since: $endDateTime - deleting it now..."
                    $deleteAadApplicationPasswordParams = @{
                        Query              = "applications/$($getAadApplicationResponse.value.id)/removePassword"
                        AccessToken        = $AccessToken
                        Body               = @{ "keyId" = $password.keyId } | ConvertTo-Json
                        Method             = "POST"
                        ExpectedStatusCode = 204
                        GraphApiUrl        = $GraphApiUrl
                    }
                    $deleteAadApplicationPasswordResponse = Invoke-GraphApiRequest @deleteAadApplicationPasswordParams

                    if ($deleteAadApplicationPasswordResponse.Successful -eq $false) {
                        Write-Host "Unable to delete secret with id: $($password.keyId) - please delete it manually" -ForegroundColor Yellow
                    }
                }
            }
        }
    }

    if ($PSCmdlet.ShouldProcess($AzureApplicationName, "Create client secret")) {
        # Specify secret expiration time which must be in ISO 8601 format and is always in UTC time
        $pwdEndDateTime = ([DateTime]::UtcNow).AddDays(7).ToString("o")
        # Graph API call to create a new application password
        $newAadApplicationPasswordParams = @{
            Query       = "applications/$($getAadApplicationResponse.value.id)/addPassword"
            AccessToken = $AccessToken
            Body        = @{
                "passwordCredential" = @{
                    "displayName" = "AppAccessKey"
                    "endDateTime" = $pwdEndDateTime
                }
            } | ConvertTo-Json
            Method      = "POST"
            GraphApiUrl = $GraphApiUrl
        }
        $newAadApplicationPasswordResponse = Invoke-GraphApiRequest @newAadApplicationPasswordParams

        if ($newAadApplicationPasswordResponse.Successful -eq $false) {
            Write-Host "Unable to create the Azure application password" -ForegroundColor Red
            exit
        }

        Write-Host "Secret created for Azure application: $AzureApplicationName - waiting 60 seconds for replication..."
        Start-Sleep -Seconds 60
        Write-Host "Continuing..."

        return $newAadApplicationPasswordResponse.Content.secretText
    }
}
