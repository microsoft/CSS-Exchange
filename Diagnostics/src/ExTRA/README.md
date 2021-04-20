# ExTRA

The goal of this script is to replace the ExTRA UI that was included with older versions of Exchange.
The script can be run on any machine where a modern browser (Edge/Chrome/Firefox) is set as the default
browser. It does not need to be run on an Exchange server. It will _not_ work if Internet Explorer
is the default browser.

## Download

Get the latest release here:

https://github.com/microsoft/CSS-Exchange/releases/latest/download/ExTRA.ps1

## Usage

Generally, you will want to run this script on a user workstation and use it to generate the
EnabledTraces.config file. Then, that file can be copied to the Exchange server, and a logman command
can be used to start and stop the ExTRA trace.

The script can be run directly on a server if desired, but remember that IE cannot be the default
browser in that case.

To use, download the latest release. Then run the script with no parameters:

```
.\ExTRA.ps1
```

The default browser will launch with a tag selection interface. Once the desired tags are selected,
click Save and go back to the PowerShell window. You should see some output indicating that the
EnabledTraces.config file was saved in the folder. That EnabledTraces.config should be placed at
the root of C:\ on the server being traced.

The output also provides example logman syntax for creating, starting, and stopping the trace.
