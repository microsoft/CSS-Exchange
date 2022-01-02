# Reset-ScanEngineVersion

Download the latest release: [Reset-ScanEngineVersion.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Reset-ScanEngineVersion.ps1)

## Usage

Copy the script to an affected Exchange server and run it with no parameters. It can be run from EMS or plain PowerShell. The output should look like this:

![Screenshot](Reset-ScanEngineVersion-Screen1.png)

The script runs through the steps described in the blog post, and then it monitors the BITS download and reports the progress for convenience.
