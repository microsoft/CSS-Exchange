# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

$healthCheckerCustomClass = @"
using System;
using System.Collections;
    namespace HealthChecker
    {
        //HTML & display classes
        public class HtmlServerValues
        {
            public System.Array OverviewValues;
            public System.Array ActionItems;   //use HtmlServerActionItemRow
            public System.Array ServerDetails;    // use HtmlServerInformationRow
        }

        public class HtmlServerActionItemRow
        {
            public string Setting;
            public string DetailValue;
            public string RecommendedDetails;
            public string MoreInformation;
            public string Class;
        }

        public class HtmlServerInformationRow
        {
            public string Name;
            public string DetailValue;
            public object TableValue;
            public string Class;
        }

        public class DisplayResultsLineInfo
        {
            public string DisplayValue;
            public string Name;
            public string TestingName; // Used for pestering testing
            public string CustomName; // Used for security vulnerability
            public int TabNumber;
            public object TestingValue; //Used for pester testing down the road.
            public object CustomValue; // Used for security vulnerability
            public object OutColumns; //used for colorized format table option.
            public string WriteType;

            public string Line
            {
                get
                {
                    if (String.IsNullOrEmpty(this.Name))
                    {
                        return this.DisplayValue;
                    }

                    return String.Concat(this.Name, ": ", this.DisplayValue);
                }
            }
        }

        public class DisplayResultsGroupingKey
        {
            public string Name;
            public int DefaultTabNumber;
            public bool DisplayGroupName;
            public int DisplayOrder;
        }

        public class AnalyzedInformation
        {
            public object HealthCheckerExchangeServer;
            public Hashtable HtmlServerValues = new Hashtable();
            public Hashtable DisplayResults = new Hashtable();
        }
    }
"@

try {
    #Enums and custom data types
    if (-not($ScriptUpdateOnly)) {
        Add-Type -TypeDefinition $healthCheckerCustomClass -ErrorAction Stop
    }
} catch {
    Write-Warning "There was an error trying to add custom classes to the current PowerShell session. You need to close this session and open a new one to have the script properly work."
    exit
}
