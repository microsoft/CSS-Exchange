# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Get-IndexingErrorMessage {
    [CmdletBinding()]
    param(
        [object]$Message
    )
    begin {
        $condensedErrorMessage = [string]::Empty
    }
    process {

        if ($Message.MessageStatus -eq "Indexed") {
            return
        }

        if (([string]::IsNullOrWhiteSpace($Message.IndexingErrorMessage)) -or
            $Message.IndexingErrorMessage -eq "NULL") {

            if (-not ([string]::IsNullOrWhiteSpace($Message.ErrorTags))) {
                $condensedErrorMessage = $Message.ErrorTags
            } else {
                $condensedErrorMessage = "--Unknown--"
            }
        } elseif ($Message.IndexingErrorMessage -like "*Error parsing document exchange://localhost/Attachment*") {
            $errorCode = $Message.IndexingErrorMessage.Substring(0, $Message.IndexingErrorMessage.IndexOf("Error parsing")).Trim()
            $condensedErrorMessage = "Error parsing document: $errorCode"
        } else {
            $condensedErrorMessage = $Message.IndexingErrorMessage
        }
    }
    end {
        return $condensedErrorMessage
    }
}
