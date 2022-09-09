# UnifiedContentCorrector
Exchange 2013 Exchange 2016 and Exchange 2019 fix Unified Content folder location for auto cleanup.


Exchange 2013, Exchange 2016, and Exchange 2019 if installed outside of the default directory (i.e. C:\Program Files) the UnifedContent Folder (Default file path: C:\Program Files\Microsoft\Exchange Server\V15\TransportRoles\data\Temp\UnifiedContent) is never updated or modifed to reflect an alternative installation location.


This causes a problem with the probe that checks that directory for files that need to be cleaned up resulting in excessive disk storage being used for temporary files that should be getting deleted, and would be if the Exchange server was installed in the default location.


This script corrects the Unified Content folder path so that the cleanup probe can check the directory for 
files that need to be cleaned up and removed. This only needs to be run on Exchange 2013, 2016, and 2019 servers
if both conditions are met.
 
    1.) Exchange 2013, 2016, 2019 installed outside of the default installation path (example C:\Program Files\Microsoft\Exchange Server\v15\)
    2.) You are actively utilizing the built in Antimalware agent.

If neither condition above applies to your scenario then this is a non-issue.

# How to use script switches

.\UnifiedContentCorrector.ps1 -GenerateReport

I've included a GenerateReport switch so that you can pull a report of all of the servers as well as their installation directory within a given Active Directory site this will output to a CSV. You really only want to modify servers that have their install path outside of the default "C:\Program Files". Go through the output and then add the names to the included ServerList.txt document with 3 examples of how you should structure the input.

Next after you have the ServerList.txt populated with the names of servers you want to modify you'll want to use the -ListOfServers switch. Example:

.\UnifiedContentCorrector.ps1 -ListOfServers

This will read the names from the ServerList.txt file and go through each server you specified and modify the Antimalware.xml file and correct the installation path so that Exchange can perform its automated cleanup function.

Once the script completes you will have to reboot the servers that have been modified in order for the changes to take effect.

# Requirements

Script is unsigned, so you will need to change the PowerShell execution policy to unrestricted temporarily. You can do that by running the following:

Set-ExecutionPolicy unrestricted

After you run the script I highly recommend changing the execution policy back to restricted.

Set-ExecutionPolicy restricted

The script needs to be executed as an Administrator. I do have it check to confirm that it's being executed with Administrative privileges, and if not it will terminate the script and notify you.

# Caveats

This will have to be run again after a CU upgrade as the Antimalware.xml file will be replaced during the upgrade procedure.

# Edge Role Instructions

The switches above were designed for Exchange servers joined to a domain. If you are utilizing the Edge role you will not be able to utilize the Generate Report switch, and its also likely that the ListOfServers switches will be broken as well since you will be using a local admin account to log into the Edge server.

Recommendations for Edge installations would be to run the script locally on the Edge server without any switches.
