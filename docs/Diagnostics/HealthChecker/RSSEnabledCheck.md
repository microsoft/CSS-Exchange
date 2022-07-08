# RSS Enabled Check

**Description:**

We check on `Windows 2012 R2` or newer whether RSS (if it's supported from the NIC) is enabled or not. This is collected by the `Get-NetAdapterRss` cmdlet. We show a warning if it's supported on NIC-side but disabled.

The Get-NetAdapterRss cmdlet gets receive side scaling (RSS) properties of the network adapters that support RSS. RSS is a scalability technology that distributes the receive network traffic among multiple processors by hashing the header of the incoming packet and using an indirection table. Without RSS in Windows Server® 2012 and later, network traffic is received on the first processor which can quickly reach full utilization limiting receive network throughput. Various properties can be configured to optimize the performance of RSS.

**Included in HTML Report?**

Yes

**Additional resources:**

[Introduction to Receive Side Scaling](https://docs.microsoft.com/windows-hardware/drivers/network/introduction-to-receive-side-scaling)

