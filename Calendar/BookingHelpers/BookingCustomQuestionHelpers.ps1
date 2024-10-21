# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-GraphBookingsCustomQuestions {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Identity
    )
    $MBcustomQuestions = Get-MgBookingBusinessCustomQuestion -BookingBusinessId $Identity
    $customQuestions = @()
    foreach ($customQuestion in $MBcustomQuestions) {
        $customQuestions += [PSCustomObject]@{
            Id                  = $customQuestion.Id
            DisplayName         = $customQuestion.DisplayName
            AnswerInputType     = $customQuestion.AnswerInputType
            Options             = $customQuestion.AnswerOptions | ConvertTo-Json -Depth 10
            CreatedDateTime     = $customQuestion.AdditionalProperties["createdDateTime"]
            LastUpdatedDateTime = $customQuestion.AdditionalProperties["lastUpdatedDateTime"]
        }
    }
    return $customQuestions
}
