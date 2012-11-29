using System;
using System.Collections.Generic;
using System.Text;
using OWASP = org.owasp.validator.html;
using NUnit.Framework;

namespace AntiXSSTest
{
    public class TestHelper
    {
        internal static void RunExpression(string text, OWASP.Policy policy, int expectedErrorNumber, string[] expectedErrors)
        {
            OWASP.AntiSamy as1 = new OWASP.AntiSamy();
            OWASP.CleanResults cr = as1.scan(text, policy);

            if (expectedErrors == null)
            {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < cr.getNumberOfErrors(); i++)
                {
                    sb.AppendLine(cr.getErrorMessages()[i].ToString());
                }
                if (sb.Length > 0)
                    Assert.Fail(sb.ToString());
                Assert.AreEqual(0, cr.getNumberOfErrors());
            }
            else
            {
                Assert.AreEqual(expectedErrors.Length, cr.getNumberOfErrors());
                for (int i = 0; i < cr.getNumberOfErrors(); i++)
                {
                    Assert.AreEqual(expectedErrors[i], cr.getErrorMessages()[i].ToString());
                }
            }

            Assert.AreEqual(expectedErrorNumber, cr.getNumberOfErrors());

        }
    }
}
