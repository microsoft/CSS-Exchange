# Exchange Server Support Scripts

[![Build Status](https://dev.azure.com/CSS-Exchange-Tools/CSS%20Exchange%20Scripts/_apis/build/status/microsoft.CSS-Exchange?branchName=release)](https://dev.azure.com/CSS-Exchange-Tools/CSS%20Exchange%20Scripts/_build/latest?definitionId=7&branchName=release)

## The Repository

This repository is the home of several scripts that are developed and maintained by Support Engineers
for Microsoft Exchange Server. The scripts are intended for identifying and resolving
a wide range of issues that impact on-premise or hybrid deployments and migrations.

For more information, see the documentation for individual scripts:

[https://microsoft.github.io/CSS-Exchange](https://microsoft.github.io/CSS-Exchange)

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.


## Quick Start

* Have PowerShell 7 or later installed.
* Open the root of the repository with VSCode.
* Make the desired changes, using Shift-Alt-F to apply the repository formatting rules.
* From PS7, run `.build\CodeFormatter.ps1 -Save` and fix any PSScriptAnalyzer issues.
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

## Building

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

`$someVarName = Get-Content $PSScriptRoot\someresource.txt -AsByteStream -Raw`

This command populates $someVarName with the binary content of the target file. You can then use that
data however you like, such as converting it to text or processing it some other way. See the `ExTRA.ps1`
script in this repo, which embeds a .txt and .html file in this way.

Again, things work normally at dev time and can be debugged without building. However, note that
-AsByteStream is only available in PowerShell Core, so PowerShell Core must be used at dev time for
this type of script. The PowerShell Core requirement goes away in the release version since the file
is then embedded in the script.
