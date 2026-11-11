# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

<#
.SYNOPSIS
    Returns the known modules and company names that are expected to be loaded into Exchange processes.
.DESCRIPTION
    Single source of the module allow list used to detect unexpected (3rd party) modules in Exchange processes.
    Used by Test-ExchAVExclusions.ps1 and Troubleshoot-ModernSearch.ps1.
    ModuleNames are the IL file names. Callers should treat the NGen native image (*.ni.dll) of an allowed module as allowed.
.OUTPUTS
    PSCustomObject with the following string[] properties:
        ModuleNames       - Modules shipped with Exchange or Windows that have no or a non-Microsoft company name
        CompanyNames      - Microsoft company names, including localized ones
        FipFsCompanyNames - Company names allowed only for modules under FIP-FS\Bin
        AmsiKnownModuleNames - Windows Defender modules loaded by the AMSI provider.
                               Test-ExchAVExclusions.ps1 treats them as AMSI provider modules when amsi.dll is loaded in the process.
                               Troubleshoot-ModernSearch.ps1 always checks them and accepts only the registered provider DLL as AMSI.
#>
function Get-ExchangeProcessModuleAllowList {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    # cSpell:disable
    $moduleNames = @(
        # No company name
        # Bin\Search\Ceres\HostController\Data\Repository\Journal\
        "Microsoft.Exchange.TransportFlow.50.dll",
        "Microsoft.ClientResourceView.FlowService.dll",
        "Microsoft.Exchange.TransportFlowMdm.50.dll",
        "Microsoft.Exchange.Search.Writer.50.dll",
        "Microsoft.Exchange.TransportFlowMdm.105.dll",
        "Microsoft.Exchange.TransportFlow.105.dll",
        "Microsoft.Exchange.Search.Writer.109.dll",
        "Microsoft.Exchange.WatermarkCtsFlow.100.dll",

        "FUSE.Paxos.Network.dll",
        "FUSE.Weld.Base.Portable.dll",
        "ParallelExtensionsExtras.dll",
        "Google.ProtocolBuffers.dll",
        "Bond.Precompiler.dll",
        "Microsoft.Applications.Telemetry.dll",
        "Microsoft.Applications.Telemetry.Server.dll",
        "Microsoft.RightsManagementServices.Core.dll",
        "Microsoft.Search.ObjectStore.Client.dll",
        "System.IdentityModel.Tokens.Jwt.dll",
        "Owin.dll",
        "DiskLockerApi.dll",
        "ExDbFailureItemApi.dll",
        "ManagedBlingSigned.dll",
        "Microsoft.DSSMNativeSSELib.dll",
        "Microsoft.Exchange.BigFunnelFlow.28.dll",
        "BigFunnel.NeuralTree.dll",
        "DocParserWrapper.dll",
        "MimeKit.dll",

        #.NET Foundation
        "Microsoft.AspNet.SignalR.Core.dll",
        "Microsoft.AspNet.SignalR.SystemWeb.dll",

        #Microsoft Research Limited
        "Infer.Compiler.dll",
        "Infer.Runtime.dll",

        #The Legion of the Bouncy Castle
        "BouncyCastle.Crypto.dll",

        #Google Inc.
        "Google.Protobuf.dll",

        #Newtonsoft
        "Newtonsoft.Json.dll",
        "Newtonsoft.Json.Bson.dll",

        #Marc Gravell
        "protobuf-net.dll",
        "protobuf-net.Core.dll",

        #Matthew Manela
        "DiffPlex.dll",

        #The Apache Software Foundation
        "log4net.dll",

        #http://system.data.sqlite.org/
        "System.Data.SQLite.dll",

        #Robert Simpson, et al.
        "SQLite.Interop.dll",

        #Microsoft.Cloud.InstrumentationFramework.*
        "Microsoft.Cloud.InstrumentationFramework.Events.dll",
        "Microsoft.Cloud.InstrumentationFramework.Health.dll",
        "Microsoft.Cloud.InstrumentationFramework.Metrics.dll",

        #Windows
        "prxyqry.DLL",
        "icu.dll",
        # ICU component libraries shipped next to icu.dll, still present in Windows Server 2025
        "icuuc.dll",
        "icuin.dll",
        "TextShaping.dll",

        #Windows Fraunhofer IIS MPEG Audio Layer-3 ACM codec - MPEG Audio Layer-3 Codec for MSACM
        "l3codecp.acm"
    )

    $companyNames = @(
        "Microsoft Corporation",
        "Microsoft Corporation.",
        "Microsoft",
        "Microsoft Corp.",
        "Microsoft CoreXT",
        #"Microsoft Research Limited" #Only 2 modules

        "Корпорация Майкрософт",
        "Корпорація Майкрософт",
        "Корпорація Майкрософт (Microsoft Corporation)",
        "Microsoft  корпорациясы",
        "Корпорация Майкрософт."
    )

    $fipFsCompanyNames = @(
        "Oracle Corporation",
        "Oracle Corp."
    )

    # Windows Defender modules loaded by the registered AMSI provider DLL, expected in w3wp and other processes that scan content via AMSI.
    # MPCLIENT.DLL isn't registered and the registered path can point to another platform version than the loaded one.
    $amsiKnownModuleNames = @(
        "MPCLIENT.DLL",
        "MpOav.dll"
    )
    # cSpell:enable

    return [PSCustomObject]@{
        ModuleNames          = [string[]]$moduleNames
        CompanyNames         = [string[]]$companyNames
        FipFsCompanyNames    = [string[]]$fipFsCompanyNames
        AmsiKnownModuleNames = [string[]]$amsiKnownModuleNames
    }
}
