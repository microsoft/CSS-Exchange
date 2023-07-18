# How To Contribute

## Quick Start

* Brand new to Git and GitHub? Check out our [New User Guide](https://microsoft.github.io/CSS-Exchange/NewUserGuide/).
* If you are a Microsoft employee, link your GitHub account to your corp credentials and join the [Microsoft organization](https://github.com/microsoft).
* Have PowerShell 7 or later installed.
* Open the root of the repository with VSCode.
* Make the desired changes, using Shift-Alt-F to apply the repository formatting rules.
* From PS7, run `.build\CodeFormatter.ps1 -Save` and fix any PSScriptAnalyzer issues. To save time, you can add `-Branch main` to only format files that have changed in this PR.
* From PS7, run `.build\SpellCheck.ps1` and fix any spelling errors.
  * Most spelling issues can be fixed by using readable variable names and function names in camelCase or PascalCase. For example, `errorCode` or `ErrorCode` will pass, but in all-lowercase or all-uppercase they will not.
  * Only add words to the dictionary if absolutely necessary.
* From PS7, run `.build\Build.ps1`. Test the resulting script in `dist/`.
* Commit the changes on your own branch and open a Pull Request.

It is recommended to use Visual Studio Code when developing scripts for this project. Opening VSCode at
the root of this repo will ensure that VSCode uses the settings in the repro to enforce most of the
formatting rules.

Before committing, .build\CodeFormatter.ps1 should be run. When running CodeFormatter from PowerShell 7
or newer, the -Save argument can be used to save the required formatting changes automatically. CodeFormatter
will also apply PSScriptAnalyzer formatting rules, and will show any required changes in the form of a diff
output. It's a good idea to set the following setting to avoid erroneous ^M characters in the diff output:

`git config core.whitespace cr-at-eol`

## Style Guide

We generally follow the [PoshCode style guide](https://github.com/PoshCode/PowerShellPracticeAndStyle/blob/master/Style-Guide/Introduction.md). Most importantly:

[Code Layout and Formatting](https://github.com/PoshCode/PowerShellPracticeAndStyle/blob/master/Style-Guide/Code-Layout-and-Formatting.md)

[Function Structure](https://github.com/PoshCode/PowerShellPracticeAndStyle/blob/master/Style-Guide/Function-Structure.md)

Note that we don't enforce Verb-Noun naming for internal functions. We also break this rule for many script names.

## Features Of The Build System

This repo uses a unique and fairly simple build system to create a single release script from a multi-file
script project. You can check the output of this system by running the `.build\Build.ps1` script and
checking the `dist` folder. Note that Build.ps1 requires PowerShell 7 or newer.

This system provides two ways to combine files into a single .ps1.

### Including a script in another script

Dot-sourcing a script inside another script embeds the target script into the source script. For example,
placing the following line inside of Script1.ps1 causes Script2.ps1 to be embedded at that point in Script1.
Script2 is then excluded from release:

`. $PSScriptRoot\Script2.ps1`

We recommend dot-sourcing using a path starting with $PSScriptRoot to ensure the script can be run
from different working directories at development time.

Any number of scripts can be embedded, and those scripts can reside in the same folder, a subfolder, or
somewhere else in the repository, such as the Shared folder at the root. See the
`SourceSideValidation.ps1` script in this repo for an example of this.

Because dot-sourcing works normally at development time, the multi-file script can be run and debugged
without building at dev time.

### Including other file types in a script

Non-script files can be embedded in a script as well. This is accomplished with the following syntax:

`$someVarName = Get-Content $PSScriptRoot\SomeResource.txt -AsByteStream -Raw`

This command populates $someVarName with the binary content of the target file. You can then use that
data however you like, such as converting it to text or processing it some other way. See the `ExTRA.ps1`
script in this repo, which embeds a .txt and .html file in this way.

Again, things work normally at dev time and can be debugged without building. However, note that
-AsByteStream is only available in PowerShell Core, so PowerShell Core must be used at dev time for
this type of script. The PowerShell Core requirement goes away in the release version since the file
is then embedded in the script.

### Versioning

The version number of the script is date-based and is generated from the date of the last commit for
that script. You can access the version number at runtime by placing the following line somewhere in your script:

```powershell
$BuildVersion = ""
```

At build time, this variable will be populated with the version number of the script.

### AutoUpdate

Any script in this repo can add AutoUpdate capabilities by using the shared script and calling it as follows:

```powershell
. $PSScriptRoot\..\..\Shared\ScriptUpdateFunctions\Test-ScriptVersion.ps1

if (Test-ScriptVersion -AutoUpdate) {
    # Update was downloaded, so stop here.
    Write-Host "Script was updated. Please rerun the command."
    return
}
```

Note the path to the Shared folder may be different depending on where your script is located.

### Colorized Tables

Check out the shared script Out-Columns.ps1 for an example of how to use colorized tables. This script also
provides word-wrapping of table values. Search for it in the repo to see how different scripts use it.

### Other stuff

Check out the Shared folder.
