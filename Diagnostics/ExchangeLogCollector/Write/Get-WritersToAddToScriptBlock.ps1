# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Function Get-WritersToAddToScriptBlock {

    $writersString = "Function Write-InvokeCommandReturnHostWriter { " + (${Function:Write-InvokeCommandReturnHostWriter}).ToString() + " } `n`n Function Write-InvokeCommandReturnVerboseWriter { " + (${Function:Write-InvokeCommandReturnVerboseWriter}).ToString() + " } `n`n#"
    return $writersString
}
