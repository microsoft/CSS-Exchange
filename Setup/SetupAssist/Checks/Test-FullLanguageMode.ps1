# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Test-FullLanguageMode {
    if ($ExecutionContext.SessionState.LanguageMode -ne "FullLanguage") {
        "PowerShell is not in FullLanguage mode. Exchange Setup requires FullLanguage mode. The SetupAssist script also requires it. Cannot continue." | Receive-Output -IsWarning
        return $false
    }

    return $true
}
