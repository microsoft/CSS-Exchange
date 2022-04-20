# NUMA BIOS / All Processor Cores Visible Check

**Description:**

Check to see if the OS is able to see all the processor cores on the server. What normally happens is the OS is able to see 1 processor socket presented (aka half the number of cores)

This can become a major problem on a server if you do not see all the processor cores for a few reasons.

- Logic is built into the Exchange Code to handle user workload management is based of the how much CPU the user is using or the process itself. When we aren't able to see all the cores on the system, the process can consume a higher amount than what logic dictates. We base this logic off of the number of cores presented to the OS by `[System.Environment]::ProcessorCount`. Because the underlying hardware has full access to all the processor cores, the process can go above what Exchange calculated out to set the threshold to be at and then throttling can occur.

- Sometimes the underlying setting isn't able to keep up and doesn't distribute the load between both the processor sockets, thus causing an issue because the application just lost half of its resources. You can see this occur when you look at the performance counter "\Processor Information(0,_Total)\% Processor Time" and "\Processor Information(1,_Total)\% Processor Time" as each one sees their own socket. One will go up while the other goes down. This might only happen for a few seconds, but there are health checks on the server that can be triggered to cause additional issues that will spiral the server.

**Included in HTML Report?**

Yes

**Additional resources:**

[CUSTOMER ADVISORY c04650594](https://support.hpe.com/hpesc/public/docDisplay?docLocale=en_US&docId=emr_na-c04650594)

[Exchange performance:HP NUMA BIOS settings](https://ingogegenwarth.wordpress.com/2017/07/27/numa-settings/)

[Exchange 2016 users unable to edit Distribution Group membership using Outlook](https://docs.microsoft.com/archive/blogs/dannypexchange/exchange-2016-users-unable-to-edit-distribution-group-membership-when-outlook)

