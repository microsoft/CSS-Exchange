$VirtualizationWarning = @"
Virtual Machine detected.  Certain settings about the host hardware cannot be detected from the virtual machine.  Verify on the VM Host that: 

    - There is no more than a 1:1 Physical Core to Virtual CPU ratio (no oversubscribing)
    - If Hyper-Threading is enabled do NOT count Hyper-Threaded cores as physical cores
    - Do not oversubscribe memory or use dynamic memory allocation
    
Although Exchange technically supports up to a 2:1 physical core to vCPU ratio, a 1:1 ratio is strongly recommended for performance reasons.  Certain third party Hyper-Visors such as VMWare have their own guidance.  

VMWare recommends a 1:1 ratio.  Their guidance can be found at https://www.vmware.com/files/pdf/Exchange_2013_on_VMware_Best_Practices_Guide.pdf.  
Related specifically to VMWare, if you notice you are experiencing packet loss on your VMXNET3 adapter, you may want to review the following article from VMWare:  http://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=2039495. 

For further details, please review the virtualization recommendations on Microsoft Docs at the following locations: 
Exchange 2013: https://docs.microsoft.com/en-us/exchange/exchange-2013-virtualization-exchange-2013-help#requirements-for-hardware-virtualization.  
Exchange 2016/2019: https://docs.microsoft.com/en-us/exchange/plan-and-deploy/virtualization?view=exchserver-2019. 

"@

#this is to set the verbose information to a different color 
if($PSBoundParameters["Verbose"]){
    #Write verose output in cyan since we already use yellow for warnings 
    $Script:VerboseEnabled = $true
    $VerboseForeground = $Host.PrivateData.VerboseForegroundColor 
    $Host.PrivateData.VerboseForegroundColor = "Cyan"
}