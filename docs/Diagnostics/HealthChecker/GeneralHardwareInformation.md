# General Hardware Information

**Description:**

We show some general information about the Processor/Hardware of the Exchange server against which the script was executed.

**Hardware Type:**

- VMWare
- AmazonEC2
- HyperV
- Physical
- Unknown

We additionally show the following information, if `HardwareType` is `Physical` or `AmazonEC2`:
- Manufacturer
- Model
- Processor

**Number of Processors:**

- We show an note if `ServerType` is `VMWare` [1]
- We show an error if we have more than `2 Processors` installed

**Number of Physical/Logical Cores:**

- We show a warning if we have more than `24 Physical Cores` and running `Exchange 2013/2016` [2]
- We show a warning if we have more than `48 Physical Cores` and running `Exchange 2019` [2]

**Hyper-Threading:**

[We show if Hyper-Threading is enabled or not.](HyperThreadingCheck.md)

**NUMA BIOS Check:**

We check to see if we can properly see all cores on the server. [3], [4]

**Max Processor Speed:**

We return the `MaxMegacyclesPerCore`. This is the max speed that we can get out of the cores. We also check if the processor is throttled which may be a result of a misconfigured Power Plan.

**Physical Memory:**

We validate if the amount of installed memory meets our specifications. [5]

**Included in HTML Report?**

Yes

**Additional resources:**

[1 - Does CoresPerSocket Affect Performance?](https://blogs.vmware.com/vsphere/2013/10/does-CoresPerSocket-affect-performance.html)

[2 - Commodity servers](https://docs.microsoft.com/exchange/plan-and-deploy/deployment-ref/preferred-architecture-2019?view=exchserver-2019#commodity-servers)

[3 - CUSTOMER ADVISORY c04650594](https://support.hpe.com/hpesc/public/docDisplay?docLocale=en_US&docId=emr_na-c04650594)

[4 - Exchange performance:HP NUMA BIOS settings](https://ingogegenwarth.wordpress.com/2017/07/27/numa-settings/)

[5 - Exchange 2013 Sizing](https://docs.microsoft.com/exchange/exchange-2013-sizing-and-configuration-recommendations-exchange-2013-help#exchange-2013-sizing)

[5 - Hardware requirements for Exchange 2016](https://docs.microsoft.com/exchange/plan-and-deploy/system-requirements?view=exchserver-2016#hardware-requirements-for-exchange-2016)

[5 - Hardware requirements for Exchange 2019](https://docs.microsoft.com/exchange/plan-and-deploy/system-requirements?view=exchserver-2019#hardware-requirements-for-exchange-2019)

