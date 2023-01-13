# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#

.SYNOPSIS
Parses the output of Search-AdminAuditLog to produce more readable results.

.DESCRIPTION
Takes the output of the Search-AdminAuditLog as an input and reconstructs the
results into a more easily read structure.

Results can be stored in a variable and sent to the script with -SearchResults
or taken directly off of a pipeline and converted.

Output should generally contain commands that can be copied and pasted into
an Exchange/Exchange Online Shell and run directly with little to no
Modification.

.PARAMETER SearchResults
Output of the Search-AdminAuditLog. Either stored in a variable or pipelined
into the script.

.PARAMETER ResolveCaller
Attempts to resolve the alias of the person who ran the command into the
primary SMTP address.

.OUTPUTS
Creates an output that contains the following information:

Caller         : Person who ran the command
Cmdlet         : Cmdlet that was run
FullCommand    : Reconstructed full command that was run
RunDate        : Date and Time command was run
ObjectModified : Object that was modified by the command

.EXAMPLE
$Search = Search-AdminAuditLog
$search | C:\Scripts\Get-SimpleAuditLogReport.ps1

Converts the results of Search-AdminAuditLog and sends the output to the screen

.EXAMPLE
Search-AdminAuditLog | C:\Scripts\Get-SimpleAuditLogReport.ps1 | Export-CSV -path C:\temp\AuditLog.csv

Converts the results of Search-AdminAuditLog and sends the output to a CSV file

.EXAMPLE
$MySearch = Search-AdminAuditLog -cmdlet set-mailbox
C:\Script\C:\Scripts\Get-SimpleAuditLogReport.ps1 -SearchResults $MySearch

Finds all instances of set-mailbox
Converts them by passing in the results to the switch SearchResults
Outputs to the screen

#>

param (
    [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    $SearchResults,
    [switch]$ResolveCaller
)

# Setup to process incoming results
begin {

    # Set the counter to 1
    $i = 1

    # If resolveCaller is called it can take much longer to run so notify the user of that
    if ($ResolveCaller) { Write-Warning "ResolveCaller specified; Script will take significantly longer to run as it attempts to resolve the primary SMTP address of each calling user.  Progress updates will be provided every 25 entries." }
}

# Process thru what ever is coming into the script
process {

    # Deal with each object in the input
    $SearchResults | ForEach-Object {

        # Get the alias of the User that ran the command
        $user = ($_.caller.split("/"))[-1]

        # If we used resolve caller then try to resolve the primary SMTP address of the calling user
        if ($ResolveCaller) {

            # attempt to resolve the recipient
            [string]$Recipient = (get-recipient $user -ErrorAction SilentlyContinue).PrimarySmtpAddress

            # if we get a result then put that in the output otherwise do nothing
            if (!([string]::IsNullOrEmpty($Recipient))) { $user = $Recipient }

            # Since this is going to take longer to run provide status every 25 entries
            if ($i % 25 -eq 0) { Write-Host "Processed 25 Results" }
            $i++
        }

        # Build the command that was run
        $switches = $_.CmdletParameters
        [string]$FullCommand = $_.CmdletName

        # Get all of the switches and add them in "human" form to the output
        foreach ($parameter in $switches) {

            # Format our values depending on what they are so that they are as close
            # a match as possible for what would have been entered
            switch -regex ($parameter.value) {

                # If we have a multi value array put in then we need to break it out and add quotes as needed
                '[;]' {

                    # Reset the formatted value string
                    $FormattedValue = $null

                    # Split it into an array
                    $valueArray = $switch.current.split(";")

                    # For each entry in the array add quotes if needed and add it to the formatted value string
                    $valueArray | ForEach-Object {
                        if ($_ -match "[ \t]") { $FormattedValue = $FormattedValue + "`"" + $_ + "`";" }
                        else { $FormattedValue = $FormattedValue + $_ + ";" }
                    }

                    # Clean up the trailing ;
                    $FormattedValue = $FormattedValue.TrimEnd(";")

                    # Add our switch + cleaned up value to the command string
                    $FullCommand = $FullCommand + " -" + $parameter.name + " " + $FormattedValue
                }

                # If we have a value with spaces add quotes
                '[ \t]' { $FullCommand = $FullCommand + " -" + $parameter.name + " `"" + $switch.current + "`"" }

                # If we have a true or false format them with :$ in front ( -allow:$true )
                '^True$|^False$' { $FullCommand = $FullCommand + " -" + $parameter.name + ":`$" + $switch.current }

                # Otherwise just put the switch and the value
                default { $FullCommand = $FullCommand + " -" + $parameter.name + " " + $switch.current }
            }
        }
    }

    # Pull out the Modified properties
    $ModifiedProperties = $_.ModifiedProperties

    # Make sure our holding variable are nulled out
    $Property = $null
    $OldValue = $null
    $NewValue = $null

    if ($ModifiedProperties.count -gt 0) {

        # Push each property set into a separate string
        $ModifiedProperties | ForEach-Object {
            [string]$Property = $Property + $_.name + ";"
            [string]$OldValue = $OldValue + $_.OldValue + ";"
            [string]$NewValue = $NewValue + $_.NewValue + ";"
        }

        # Trim off the last ;
        $Property = $Property.TrimEnd(";")
        $OldValue = $OldValue.TrimEnd(";")
        $NewValue = $NewValue.TrimEnd(";")
    } else {
        #since the are null nothing to do here
    }

    # Format our modified object
    if ([string]::IsNullOrEmpty($_.objectModified)) {
        $ObjModified = ""
    } else {
        $ObjModified = ($_.ObjectModified.split("/"))[-1]
        $ObjModified = ($ObjModified.split("\"))[-1]
    }

    # Get just the name of the cmdlet that was run
    [string]$cmdlet = $_.CmdletName

    # Reset the result object
    $Result = New-Object PSObject
    # Build the result object to return our values
    $Result | Add-Member -MemberType NoteProperty -Value $user -Name Caller
    $Result | Add-Member -MemberType NoteProperty -Value $cmdlet -Name Cmdlet
    $Result | Add-Member -MemberType NoteProperty -Value $FullCommand -Name FullCommand
    $Result | Add-Member -MemberType NoteProperty -Value $_.RunDate -Name RunDate
    $Result | Add-Member -MemberType NoteProperty -Value $ObjModified -Name ObjectModified
    $Result | Add-Member -MemberType NoteProperty -Value $Property -Name ModifiedProperties
    $Result | Add-Member -MemberType NoteProperty -Value $OldValue -Name OldValue
    $Result | Add-Member -MemberType NoteProperty -Value $NewValue -Name NewValue

    # Add the object to the array to be returned
    $Result
}
