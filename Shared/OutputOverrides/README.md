# Output Overrides

These collection of functions are used to override the default Built in Cmdlets to allow for consistent use when overrides are needed. The most common reason to use the overrides for this functions are to be able to call function that handles writing out the information to a log file. With the exception of `Write-Host` if you are not logging the information to a file, the use of these common overrides are not recommended.

## Write-Host

Within this repository, `Write-Host` is used over `Write-Output` because it writes the stream to the screen right away vs returning to the pipeline and you are able to color code the information. Because of these reasons, `Write-Host` is used over `Write-Output`.

By default, when the `ForegroundColor` is  `Yellow`, it is converted to be the color of the PowerShell session's default `WarningForegroundColor`. By default, when the `ForegroundColor` is `Red`, it is converted to be the color of the PowerShell session's default `ErrorForegroundColor`. This is done to accommodate for people who change the default color scheme of PowerShell.

### Helper Functions

Name | Description
-----|------------
SetProperForegroundColor | Used to set the ForegroundColor to `Gray` if it matches the `WarningForegroundColor` or `ErrorForegroundColor`. This is because some people use `Yellow` to be their default color to the screen. However, when we want to display something as `Yellow` to bring attention to the screen, it doesn't bring it attention any longer if everything else is also `Yellow`. This should be used prior to displaying anything to screen.
RevertProperForegroundColor | Sets the session to use the default `ForegroundColor` that was detected from `SetProperForegroundColor`. Recommended to always use this if `SetProperForegroundColor` is used in a `try` `finally` block.
SetWriteHostAction | Used to set an additional script block action to take after the default `Write-Host` is called. This is where you would set a script block to caller the logging action to take place.
SetWriteHostManipulateObjectAction | Used to set an additional script block action to take before `Write-Host` is called to manipulate the `Object`. This is to make the output similar. Example: Instead of having to write `[$env:COMPUTERNAME]` within every `Write-Host` string, you can use `SetWriteHostManipulateObjectAction` to change the string to include this prior to the object every time `Write-Host` is called. This makes it easier to use `Write-Host` everywhere vs creating a custom function to handle displaying this action for you.

### Special Example

Recommended use case for using `SetProperForegroundColor` and `RevertProperForegroundColor` together.

```
. $PSScriptRoot\..\Shared\OutputOverrides\Write-Host.ps1

...
try {
    # Make sure WarningForegroundColor and ErrorForegroundColor colors are different than default Write-Host color
    SetProperForegroundColor
    Main # contain possible Write-Host -ForegroundColor "Yellow/Red"
} finally {
    # Revert the color changes
    # Place in finally block to always have this execute
    RevertProperForegroundColor
}

```

## Write-Progress

`Write-Progress` is used to help display to screen that the script is working, even if we don't always want to display everything to the console with `Write-Host`. When debugging a script, it useful to know where you are at when things stop working or aren't working as expected. Instead of also doing a `Write-Verbose`, we can assist with logging information when `Write-Progress` is used if `SetWriteProgressAction` is used to set a script block action.

### Helper Functions

Name | Description
-----|------------
SetWriteProgressAction | Use to set a script block action to occur after the default `Write-Progress` action occurs. The override takes care of converting the passed parameters to a string prior to script block execution.
SetWriteRemoteProgressAction | Use to set a script block action to occur if `Write-Progress` is detected to have occurred within a remote script block action.


## Write-Verbose

`Write-Verbose` is used frequently within PowerShell to assist with providing back to the console where we are at with execution if `-Verbose` is used. In order to better assist with remote script debugging it can be beneficial to also write out all the information that `Write-Verbose` does as well. If an issue does occur, it is already written out to a log that can be provided to assist with debugging.

### Helper Functions

Name | Description
-----|------------
SetWriteVerboseAction | Used to set a script block to occur after the default `Write-Verbose` action has occurred. This is where you can have a custom action to log all of the `Write-Verbose` actions that occur within the script.
SetWriteRemoteVerboseAction | Use to set a custom script block action to occur after the default `Write-Verbose` action has occurred within the remote context. This is used to be able to still log information from a simple script block action on a remote computer. This is used because unless the `$VerbosePreference` is set to write to the stream, there is no other way to pull back information by default from the remote execution other than to place it on the pipeline to be returned.
SetWriteVerboseManipulateMessageAction | Used to set an additional script block action to take before `Write-Verbose` is called to manipulate the `Message`. This is to make the output similar.


## Write-Warning

`Write-Warning` is used to display a message to the console that might need additional attention. In order to better assist with remote script debugging it can be beneficial to also write out all the information that `Write-Warning` does as well. If an issue does occur, it is already written out to a log that can be provided to assist with debugging. By default, after the `Write-Warning` to the screen does occur, the message is changed to include `WARNING:` at the front to be similar to what is displayed on the screen.

### Helper Functions

Name | Description
-----|------------
SetWriteWarningAction | Used to set the script block action to occur after the default `Write-Warning` action occurs. This is where you can have a custom action to log all of the `Write-Warning` actions that occur within the script.
SetWriteRemoteWarningAction | Use to set a custom script block action to occur after the default `Write-Warning` action has occurred within the remote context. This is used to be able to still log information from a simple script block action on a remote computer.
SetWriteWarningManipulateMessageAction | Used to set an additional script block action to take before `Write-Warning` is called to manipulate the `Message`. This is to make the output similar.


## Examples

This is how you can use the helper functions of the output overrides that are within this section. All these follow similar logic for each override type.

SetWriteTYPEAction - Where TYPE is the the Built in Cmdlet type that you are using to have an additional action occur.

```
. $PSScriptRoot\..\Shared\OutputOverrides\Write-Host.ps1
. $PSScriptRoot\..\Shared\OutputOverrides\Write-Progress.ps1
. $PSScriptRoot\..\Shared\OutputOverrides\Write-Verbose.ps1
. $PSScriptRoot\..\Shared\OutputOverrides\Write-Warning.ps1

...


function Write-DebugLog ($message) {
    if (![string]::IsNullOrEmpty($message)) {
        $Script:DebugLogger = $Script:DebugLogger | Write-LoggerInstance $message
    }
}

function Write-HostLog ($message) {
    if (![string]::IsNullOrEmpty($message)) {
        $Script:HostLogger = $Script:HostLogger | Write-LoggerInstance $message
    }
    # all write-host should be logged in the debug log as well.
    Write-DebugLog $message
}

# Used from Shared\LoggerFunctions.ps1
$Script:DebugLogger = Get-NewLoggerInstance -LogName "LogName-Debug" -LogDirectory $OutputFilePath
$Script:HostLogger = Get-NewLoggerInstance -LogName "LogName-Results" -LogDirectory $OutputFilePath
SetWriteHostAction ${Function:Write-HostLog}
SetWriteProgressAction ${Function:Write-DebugLog}
SetWriteVerboseAction ${Function:Write-DebugLog}
SetWriteWarningAction ${Function:Write-HostLog} # Might also want the warning information in both log files

```


SetWriteTYPEManipulatePARAMAction - Where TYPE is the the Built in Cmdlet type that you are using to have an additional action occur and PARAM is the default parameter name.

**NOTE:** In this example, we are logging the information on the server that is doing the executing in the remote context, not where the script is being run from.

```

function RemoteScriptBlock {
# the only place this is imported throughout the whole script to make sure it is placed within this function.
. $PSScriptRoot\..\Shared\OutputOverrides\Write-Host.ps1
. $PSScriptRoot\..\Shared\OutputOverrides\Write-Verbose.ps1
. $PSScriptRoot\..\Shared\OutputOverrides\Write-Warning.ps1

function Write-DebugLog ($message) {
    if (![string]::IsNullOrEmpty($message)) {
        $Script:DebugLogger = $Script:DebugLogger | Write-LoggerInstance $message
    }
}

function Write-ManipulateAction ($Object) {
    return "[$((Get-Date).ToString()) - $ENV:COMPUTERNAME] - $object"
}

# Used from Shared\LoggerFunctions.ps1
$Script:DebugLogger = Get-NewLoggerInstance -LogName "LogName-Debug" -LogDirectory $OutputFilePath

# Set the logging action
SetWriteHostAction ${Function:Write-DebugLog}
SetWriteVerboseAction ${Function:Write-DebugLog}
SetWriteWarningAction ${Function:Write-DebugLog}

# Set the manipulate action. Note that Write-Host is an Object parameter vs a Message parameter
SetWriteHostManipulateObjectAction ${Function:Write-ManipulateAction}
SetWriteWarningManipulateMessageAction ${Function:Write-ManipulateAction}
SetWriteVerboseManipulateMessageAction ${Function:Write-ManipulateAction}

Write-Host "Starting Execution..."
...
# more actions
}

Invoke-Command -ComputerName $ServerList -ScriptBlock ${Function:RemoteScriptBlock}
```

SetWriteRemoteTYPEAction - Where TYPE is the the Built in Cmdlet type that you are using to have an additional action occur in the remote context. This is used for when you are doing a quick function against a server remotely and need to pull back the results.

**NOTE:** Use case example are coming once a common Shared function is created that can be use consistently.
