using System;
using System.Collections.Generic;
using System.Text;
using NUnit.Framework;
using OWASP = org.owasp.validator.html;

namespace AntiXSSTest
{
    [TestFixture]
    public class TestPolicy
    {
        [Test]
        public void TestValidateSetting()
        {
            try
            {
                OWASP.Policy policy = PolicyLoader.Load("bad1");
                Assert.IsFalse(policy.IsValid);
            }
            catch (NullReferenceException)
            {

            }
            catch (Exception)
            {
                Assert.Fail("incorrect exception");
            }
            OWASP.Policy policy2 = PolicyLoader.Load("bad2");
            Assert.IsFalse(policy2.IsValid);

            OWASP.Policy policy3 = PolicyLoader.Load("ebay");
            Assert.IsTrue(policy3.IsValid);
        }
    }
}
