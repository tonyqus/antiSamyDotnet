using System;
using System.Collections.Generic;
using System.Text;
using OWASP = org.owasp.validator.html;


namespace AntiXSSTest
{
    class PolicyLoader
    {
        private PolicyLoader()
        { 
        
        }

        public const string configurationFolder = @"configuration\";

        public static OWASP.Policy Load(string policyCode)
        {
            policyCode=policyCode.ToLower();
            if (policyCode == "actv")
            {
                return OWASP.Policy.getInstance(configurationFolder + "antisamy-high.xml");
            }
            else if (policyCode == "actv-medium")
            {
                return OWASP.Policy.getInstance(configurationFolder + "antisamy-medium.xml");
            }
            else if (policyCode == "actv-low")
            {
                return OWASP.Policy.getInstance(configurationFolder + "antisamy-low.xml");
            }
            else if (policyCode == "ebay")
            {
                return OWASP.Policy.getInstance(configurationFolder + "antisamy-ebay.xml");
            }
            else if (policyCode == "bad1")
            {
                return OWASP.Policy.getInstance(configurationFolder + "antisamy-bad1.xml");
            }
            else if (policyCode == "bad2")
            {
                return OWASP.Policy.getInstance(configurationFolder + "antisamy-bad2.xml");
            }
            else
            {
                return null;
            }
        }
    }
}
