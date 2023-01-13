# Pagefile Size Check

**Description:**

We check if the Pagefile is configured as recommended and that there is only 1 PageFile configured (multiple PageFiles can cause performance issues on Exchange server).

#### Exchange 2019

- Set the paging file minimum and maximum value to the same size: 25% of installed memory

#### Exchange 2013/2016

Set the paging file minimum and maximum value to the same size:

- Less than 32 GB of RAM installed: Physical RAM plus 10MB, up to a maximum value of 32GB (32,778MB)

- 32 GB of RAM or more installed: 32GB

#### How to set the pagefile to a static value?

You can set the pagefile to a static size via `wmic` whereas `InitialSize` and `MaximumSize` is the size in megabytes calculated based on the Exchange Server version and memory installed in the server:

```
wmic ComputerSystem set AutomaticManagedPagefile=False
wmic PageFileSet set InitialSize=1024,MaximumSize=1024
```

**Included in HTML Report?**

Yes

**Additional resources:**

[PageFile requirements for Exchange 2019](https://docs.microsoft.com/exchange/plan-and-deploy/system-requirements?view=exchserver-2019#hardware-requirements-for-exchange-2019)

[PageFile requirements for Exchange 2016](https://docs.microsoft.com/exchange/plan-and-deploy/system-requirements?view=exchserver-2016#hardware-requirements-for-exchange-2016)

[PageFile requirements for Exchange 2013](https://docs.microsoft.com/exchange/exchange-2013-system-requirements-exchange-2013-help#hardware)

