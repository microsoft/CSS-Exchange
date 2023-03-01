# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function AvoidUsingReadHost {

    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.Language.ScriptBlockAst]$ScriptBlockAst
    )

    process {

        try {
            $functions = $ScriptBlockAst.FindAll(
                {
                    $args[0] -is [System.Management.Automation.Language.CommandAst]
                }, $true )
            foreach ( $function in $functions ) {

                if (($function.GetCommandName()) -eq "Read-Host") {
                    [PSCustomObject]@{
                        Message  = "Avoid using Read-Host. Use parameters to get information from the user. Use ShouldProcess to get Y/N confirmation on whether to proceed."
                        Extent   = $function.Extent
                        RuleName = $PSCmdlet.MyInvocation.InvocationName
                        Severity = "Warning"
                    }
                }
            }
        } catch {
            $PSCmdlet.ThrowTerminatingError( $_ )
        }
    }
}

function AvoidUsingClearHost {

    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.Language.ScriptBlockAst]$ScriptBlockAst
    )

    process {

        try {
            $functions = $ScriptBlockAst.FindAll(
                {
                    $args[0] -is [System.Management.Automation.Language.CommandAst]
                }, $true )
            foreach ( $function in $functions ) {

                if (($function.GetCommandName()) -eq "Clear-Host") {
                    [PSCustomObject]@{
                        Message  = "Avoid using Clear-Host. The screen should not be cleared when running the script."
                        Extent   = $function.Extent
                        RuleName = $PSCmdlet.MyInvocation.InvocationName
                        Severity = "Error"
                    }
                }
            }
        } catch {
            $PSCmdlet.ThrowTerminatingError( $_ )
        }
    }
}
