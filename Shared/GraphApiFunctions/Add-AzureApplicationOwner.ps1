# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\AzureFunctions\Invoke-GraphApiRequest.ps1

<#
    Adds a new owner to an existing Azure Application
    Get application information: https://learn.microsoft.com/graph/api/application-get
    Add owner: https://learn.microsoft.com/graph/api/application-post-owners
#>
function Add-AzureApplicationOwner {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateNotNullOrEmpty()]
        $AzAccountsObject,

        [ValidateNotNullOrEmpty()]
        $ApplicationId,

        [ValidateNotNullOrEmpty()]
        $NewOwnerUserId,

        [ValidateNotNullOrEmpty()]
        $GraphApiUrl
    )

    begin {
        Write-Verbose "Adding User with Id: $NewOwnerUserId as Owner of the Azure Application: $ApplicationId via Graph Api: $GraphApiUrl"

        $reason = $null

        $getAzureApplicationOwnerParams = @{
            AccessToken = $AzAccountsObject.AccessToken
            GraphApiUrl = $GraphApiUrl
        }
    } process {
        # Graph API call to query the existing owners of the Azure Application as we need to check if the user is already an owner
        if ($PSCmdlet.ShouldProcess("GET applications/$ApplicationId/owners", "Invoke-GraphApiRequest")) {
            $getAzureApplicationOwner = Invoke-GraphApiRequest @getAzureApplicationOwnerParams -Query "applications/$ApplicationId/owners"

            if ($getAzureApplicationOwner.Successful -eq $false) {
                Write-Verbose "Something went wrong while querying the existing Owners of this Azure Application"

                $reason = "UnableToQueryExistingOwners"
                break
            }
        }

        if ($getAzureApplicationOwner.Content.value.Length -eq 0 -or
            (-not($getAzureApplicationOwner.Content.Value.id.Contains($NewOwnerUserId)))) {

            Write-Verbose "User: $NewOwnerUserId is not yet an Owner of this Azure Application and must be added"

            # Graph API call to add the user as a new owner of the Azure Application
            $addNewOwnerToApplicationParams = $getAzureApplicationOwnerParams + @{
                Query              = "applications/$ApplicationId/owners/`$ref"
                Body               = @{ "@odata.id" = "$GraphApiUrl/v1.0/directoryObjects/$NewOwnerUserId" } | ConvertTo-Json
                Method             = "POST"
                ExpectedStatusCode = 204
            }
            if ($PSCmdlet.ShouldProcess("POST $NewOwnerUserId", "Invoke-GraphApiRequest")) {
                $addNewOwnerToApplicationResponse = Invoke-GraphApiRequest @addNewOwnerToApplicationParams

                if ($addNewOwnerToApplicationResponse.Successful -eq $false) {
                    Write-Verbose "Something went wrong while adding the User: $NewOwnerUserId as Owner to this Azure Application"

                    $reason = "AddFailed"
                    break
                }

                $reason = "Successful"
            }
        } else {
            Write-Verbose "User: $NewOwnerUserId is already an Owner of this Azure Application"

            $reason = "AlreadyAnOwner"
        }
    } end {
        return [PSCustomObject]@{
            IsOwner = ($reason -eq "Successful" -or $reason -eq "AlreadyAnOwner")
            Reason  = $reason
        }
    }
}
