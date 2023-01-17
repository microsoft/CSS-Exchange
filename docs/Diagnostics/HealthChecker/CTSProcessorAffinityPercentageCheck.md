# CTS Processor Affinity Percentage Check

**Description:**

We check if the `CtsProcessorAffinityPercentage` DWORD value under `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\V15\Search\SystemParameters` exists and is set to any other value than `0`. This setting can be used to limit CPU utilization of a process.

This can cause an impact to the server's search performance. This should never be used as a long term solution!

**Included in HTML Report?**

Yes

