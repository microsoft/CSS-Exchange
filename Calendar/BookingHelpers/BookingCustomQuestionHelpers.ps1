# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-GraphBookingsCustomQuestions {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Identity
    )
    $MBcustomQuestions = Get-MgBookingBusinessCustomQuestion -BookingBusinessId $Identity
    $CustomQuestions = @()
    foreach ($CustomQuestion in $MBcustomQuestions) {
        $CustomQuestions += [PSCustomObject]@{
            Id                  = $CustomQuestion.Id
            DisplayName         = $CustomQuestion.DisplayName
            AnswerInputType     = $CustomQuestion.AnswerInputType
            Options             = $CustomQuestion.AnswerOptions | ConvertTo-Json -Depth 10
            CreatedDateTime     = $CustomQuestion.AdditionalProperties["createdDateTime"]
            LastUpdatedDateTime = $CustomQuestion.AdditionalProperties["lastUpdatedDateTime"]
        }
    }
    return $CustomQuestions
}
