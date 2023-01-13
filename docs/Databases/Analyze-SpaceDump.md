# Analyze-SpaceDump

Download the latest release: [Analyze-SpaceDump.ps1](https://github.com/microsoft/CSS-Exchange/releases/latest/download/Analyze-SpaceDump.ps1)

This script reports the space taken up by various tables based on a database space dump.

## Usage

The space dump must be obtained while the database is dismounted, or on a suspended copy
if the issue is happening there. To obtain the space dump, use the following syntax:

eseUtil /ms /v > C:\SpaceDump.txt

Then, feed that file to this script as follows:

.\Analyze-SpaceDump.ps1 -File C:\SpaceDump.txt

This script will only work with Exchange 2013 and later space dumps.
