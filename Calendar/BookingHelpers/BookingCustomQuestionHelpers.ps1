
function Get-GraphBookingsCustomQuestions {
    param(
        [Parameter(Mandatory = $true)]
        [string]$identity
    )
    $MBcustomQuestions = Get-MgBookingBusinessCustomQuestion -BookingBusinessId $identity
    $customQuestions = @()
    foreach ($customQuestion in $MBcustomQuestions) {
        $customQuestions += [PSCustomObject]@{
            Id                  = $customQuestion.Id
            displayName         = $customQuestion.DisplayName
            AnswerInputType     = $customQuestion.AnswerInputType
            options             = $customQuestion.AnswerOptions | ConvertTo-Json -Depth 10
            createdDateTime     = $customQuestion.AdditionalProperties["createdDateTime"]
            lastUpdatedDateTime = $customQuestion.AdditionalProperties["lastUpdatedDateTime"]
        }
    }
    return $customQuestions
}
